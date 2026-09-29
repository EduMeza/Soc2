"""Geolocalización de IPs públicas vía ip-api.com (sin clave) con caché local.

Las IPs privadas se ignoran (no se consultan). Si no hay internet o la API
falla, se devuelve un diccionario vacío y el reporte simplemente omite el
país/bandera de esas IPs.
"""
from __future__ import annotations

import json
import urllib.request

from modules.config import DATA_DIR, PRIVATE_IP_PATTERN

CACHE_FILE = DATA_DIR / "geoip_cache.json"
_BATCH = 100
_TIMEOUT = 8

_cache: dict[str, tuple[str, str]] = {}


def _load_cache() -> None:
    global _cache
    if _cache:
        return
    try:
        if CACHE_FILE.exists():
            data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            _cache = {key: (str(cc), str(name)) for key, (cc, name) in data.items()}
    except Exception:
        _cache = {}


def _save_cache() -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(
            json.dumps(_cache, ensure_ascii=False, indent=1), encoding="utf-8"
        )
    except Exception:
        pass


def flag_from_country(cc: str) -> str:
    """Convierte un código ISO-3166 en su emoji de bandera ('PY' -> '🇵🇾')."""
    cc = (cc or "").strip().upper()
    if len(cc) != 2 or not cc.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in cc)


def _is_private(ip: str) -> bool:
    return bool(PRIVATE_IP_PATTERN.search(ip.replace(" ", "")))


def resolve_ips(ips: list[str]) -> dict[str, dict[str, str]]:
    """Resuelve país/bandera de IPs públicas.

    Devuelve {ip: {"cc": codigo, "pais": nombre}}. Las IPs privadas o las que
    no se puedan resolver no aparecen en el resultado. Consulta solo las
    direcciones que no están en la caché.
    """
    _load_cache()
    unique = list(dict.fromkeys(ip for ip in (ips or []) if ip))
    todo = [ip for ip in unique if not _is_private(ip) and ip not in _cache]

    for start in range(0, len(todo), _BATCH):
        batch = todo[start:start + _BATCH]
        payload = json.dumps([{"query": ip} for ip in batch], separators=(",", ":")).encode()
        req = urllib.request.Request(
            "http://ip-api.com/batch?fields=status,countryCode,country,query",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                results = json.loads(resp.read().decode("utf-8"))
        except Exception:
            continue
        for item in results:
            if item.get("status") == "success" and item.get("query"):
                _cache[item["query"]] = (
                    str(item.get("countryCode", "") or ""),
                    str(item.get("country", "") or ""),
                )

    _save_cache()
    return {
        ip: {"cc": _cache[ip][0], "pais": _cache[ip][1]}
        for ip in unique
        if ip in _cache and _cache[ip][1]
    }