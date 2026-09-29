"""Threat Intelligence: enriquecimiento de CVEs (NVD) e IPs (proveedores).

Proveedores por IP (requieren clave por VARIABLE DE ENTORNO):
- AbuseIPDB (ABUSEIPDB_API_KEY), GreyNoise (GREYNOISE_API_KEY),
  VirusTotal (VIRUSTOTAL_API_KEY), OTX AlienVault (OTX_API_KEY),
  ThreatFox (THREATFOX_API_KEY) y Shodan (SHODAN_API_KEY).
CVEs: NVD API v2 (funciona sin clave; opcional NVD_API_KEY para mayor límite).

Las claves NUNCA se guardan en el proyecto ni en data/. Si existe un archivo
de legado data/intel_keys.json, sus valores se migran a memoria y se recomienda
borrarlo; se añade al .gitignore.

Los resultados se cachean en data/threatintel_cache.json (sin expiración;
borra el archivo para forzar reconsulta). Los fallos por proveedor se marcan
con None y nunca rompen el flujo.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

import requests

from modules.config import DATA_DIR, PRIVATE_IP_PATTERN

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger(__name__)

KEYS_FILE = DATA_DIR / "intel_keys.json"   # legacy (solo lectura-migración)
CACHE_FILE = DATA_DIR / "threatintel_cache.json"

session = requests.Session()
session.headers["User-Agent"] = "SOC-24x7-Dashboard/1.0"

_cache: dict[str, dict] = {"cves": {}, "ips": {}, "updated": ""}

IP_PROVIDER_LABELS: dict[str, str] = {
    "abuseipdb": "AbuseIPDB",
    "greynoise": "GreyNoise",
    "virustotal": "VirusTotal",
    "threatfox": "ThreatFox",
    "otx": "OTX AlienVault",
    "shodan": "Shodan",
}

# Mapeo proveedor -> variable de entorno
PROVIDER_ENV_VARS: dict[str, str] = {
    "abuseipdb": "ABUSEIPDB_API_KEY",
    "virustotal": "VIRUSTOTAL_API_KEY",
    "greynoise": "GREYNOISE_API_KEY",
    "threatfox": "THREATFOX_API_KEY",
    "otx": "OTX_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "nvd": "NVD_API_KEY",
}


def load_keys() -> dict[str, str]:
    """Carga las claves de API desde variables de entorno.

    Prioridad: variable de entorno del SO. Si existe el archivo legacy
    data/intel_keys.json, sus valores se usan como respaldo *una vez* y se
    recomienda eliminarlo (está ignorado por git).
    """
    keys: dict[str, str] = {}
    for provider, env_var in PROVIDER_ENV_VARS.items():
        value = os.getenv(env_var, "").strip()
        if value:
            keys[provider] = value

    # Compatibilidad con el archivo legacy (solo lectura, avisa para migrar)
    try:
        if KEYS_FILE.exists():
            raw = json.loads(KEYS_FILE.read_text(encoding="utf-8"))
            legacy = {str(k).strip(): str(v or "").strip() for k, v in raw.items()}
            for k, v in legacy.items():
                if v and k not in keys:
                    keys[k] = v
            if legacy:
                logger.warning(
                    "Se encontraron claves de API en %s (archivo legacy). "
                    "Migra los valores a variables de entorno y elimina el archivo.",
                    KEYS_FILE.name,
                )
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("No se pudo leer %s: %s", KEYS_FILE, type(exc).__name__)
    return keys


def configured_providers(keys: dict[str, str]) -> list[str]:
    """Proveedores de IP con clave configurada + 'nvd' si se definió."""
    result = []
    keys = {k: (v or "").strip() for k, v in keys.items()}
    if keys.get("nvd"):
        result.append("nvd (NVD)")
    for provider, label in IP_PROVIDER_LABELS.items():
        if keys.get(provider):
            result.append(label)
    return result


def _load_cache() -> None:
    global _cache
    try:
        if CACHE_FILE.exists():
            _cache = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
            _cache.setdefault("cves", {})
            _cache.setdefault("ips", {})
    except Exception:
        _cache = {"cves": {}, "ips": {}, "updated": ""}


def _save_cache() -> None:
    global _cache
    _cache["updated"] = datetime.now().isoformat(timespec="seconds")
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(
            json.dumps(_cache, ensure_ascii=False, indent=1), encoding="utf-8"
        )
    except Exception:
        pass


def _api_call(method: str, url: str, headers: dict | None = None,
              params: dict | None = None, json_body: dict | None = None,
              timeout: int = 12):
    """Ejecuta una llamada HTTP y devuelve el JSON; None ante cualquier fallo."""
    try:
        resp = session.request(method, url, headers=headers or {},
                               params=params, json=json_body, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CVEs (NVD)
# ---------------------------------------------------------------------------
def _nvd_cve(cve_id: str, key: str) -> dict | None:
    headers = {"apiKey": key} if key else {}
    data = _api_call(
        "GET", "https://services.nvd.nist.gov/rest/json/cves/2.0",
        headers=headers, params={"cveId": cve_id},
    )
    if not data or not data.get("vulnerabilities"):
        return None
    vuln = data["vulnerabilities"][0].get("cve", {})
    desc = ""
    for item in vuln.get("descriptions", []) or []:
        if item.get("lang") == "en":
            desc = item.get("value", "")
            break
    metrics = vuln.get("metrics", {}) or {}
    score = severity = None
    for key_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key_name) or []
        if entries:
            data_obj = entries[0].get("cvssData", {})
            score = data_obj.get("baseScore")
            severity = data_obj.get("baseSeverity")
            break
    return {
        "title": cve_id,
        "description": desc,
        "score": score,
        "severity": severity,
        "published": (vuln.get("published", "") or "")[:10],
        "references": len(vuln.get("references", []) or []),
        "source": "NVD",
    }


# ---------------------------------------------------------------------------
# IPs (proveedores con clave)
# ---------------------------------------------------------------------------
def _abuseipdb(ip: str, key: str) -> dict | None:
    headers = {"Key": key}
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    data = _api_call("GET", "https://api.abuseipdb.com/api/v2/check",
                     headers=headers, params=params)
    if not data:
        return None
    d = data.get("data", {})
    return {
        "fuente": "AbuseIPDB",
        "abuseConfidenceScore": d.get("abuseConfidenceScore"),
        "totalReports": d.get("totalReports"),
        "lastReportedAt": (d.get("lastReportedAt") or "")[:10],
        "usageType": d.get("usageType"),
        "isp": d.get("isp"),
        "isWhitelisted": d.get("isWhitelisted"),
        "domains": [x.get("domain") for x in (d.get("domains") or []) if x.get("domain")],
        "categoria": "whitelisted" if d.get("isWhitelisted") else "reported",
    }


def _virustotal(ip: str, key: str) -> dict | None:
    headers = {"x-apikey": key}
    data = _api_call("GET", f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                     headers=headers)
    if not data:
        return None
    a = data.get("data", {}).get("attributes", {})
    stats = a.get("last_analysis_stats", {}) or {}
    return {
        "fuente": "VirusTotal",
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "reputation": a.get("reputation"),
        "as_owner": a.get("as_owner"),
        "country": a.get("country"),
        "last_analysis_date": (a.get("last_analysis_date") or 0),
        "categoria": "mal",  # placeholders conservadores
    }


def _greynoise(ip: str, key: str) -> dict | None:
    headers = {"key": key}
    data = _api_call("GET", f"https://api.greynoise.io/v3/community/{ip}",
                     headers=headers)
    if not data:
        return None
    return {
        "fuente": "GreyNoise",
        "classification": data.get("classification"),
        "noise": bool(data.get("noise")),
        "riot": bool(data.get("riot")),
        "name": data.get("name"),
        "categoria": str(data.get("classification") or "unknown"),
    }


def _threatfox(ip: str, key: str) -> dict | None:
    headers = {"Auth-Key": key}
    body = {"query": "search_ioc", "search_term": ip}
    data = _api_call("POST", "https://threatfox-api.abuse.ch/api/v1/",
                     headers=headers, json_body=body)
    if not data or data.get("query_status") != "ok":
        return None
    rows = data.get("data") or []
    if not rows:
        return None
    row = rows[0]
    return {
        "fuente": "ThreatFox",
        "threat_type": row.get("threat_type"),
        "malware": row.get("malware_printable"),
        "first_seen": (row.get("first_seen") or "")[:10],
        "last_seen": (row.get("last_seen") or "")[:10],
        "categoria": "mal",
    }


def _otx(ip: str, key: str) -> dict | None:
    headers = {"X-OTX-API-KEY": key}
    data = _api_call("GET",
                     f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                     headers=headers)
    if not data:
        return None
    pulses = data.get("pulse_info", {}).get("pulses", []) or []
    return {
        "fuente": "OTX AlienVault",
        "country_code": data.get("country_code"),
        "asn": data.get("asn"),
        "reputation": data.get("reputation"),
        "pulses": len(pulses),
        "tags": [t for p in pulses for t in (p.get("tags") or [])],
        "categoria": "mal" if pulses else "clean",
    }


def _shodan(ip: str, key: str) -> dict | None:
    data = _api_call("GET", f"https://api.shodan.io/shodan/host/{ip}",
                     params={"key": key})
    if not data:
        return None
    return {
        "fuente": "Shodan",
        "os": data.get("os"),
        "ports": data.get("ports") or [],
        "tags": data.get("tags") or [],
        "country_name": data.get("country_name"),
        "hostnames": data.get("hostnames") or [],
        "vulns": list((data.get("vulns") or dict()).keys()),
        "isp": data.get("isp"),
        "categoria": "mal" if data.get("vulns") else "info",
    }


_IP_FUNCS = {
    "abuseipdb": _abuseipdb,
    "virustotal": _virustotal,
    "greynoise": _greynoise,
    "threatfox": _threatfox,
    "otx": _otx,
    "shodan": _shodan,
}


def _is_private(ip: str) -> bool:
    return bool(PRIVATE_IP_PATTERN.search(ip.replace(" ", "")))


# ---------------------------------------------------------------------------
# API pública (cache-aware)
# ---------------------------------------------------------------------------
def enrich_cves(cve_ids: list[str], keys: dict[str, str]) -> dict[str, dict]:
    """Consulta NVD por cada CVE y devuelve {cve: {datos}}. Usa caché."""
    _load_cache()
    nvd_key = (keys or {}).get("nvd", "")
    out: dict[str, dict] = {}
    for cve in list(dict.fromkeys(cve_ids or [])):
        cached = _cache["cves"].get(cve)
        if cached:
            out[cve] = cached
            continue
        result = _nvd_cve(cve, nvd_key)
        if result:
            out[cve] = result
            _cache["cves"][cve] = result
    _save_cache()
    return out


def enrich_ips(ips: list[str], keys: dict[str, str]) -> dict[str, dict]:
    """Consulta los proveedores con clave por cada IP pública.

    Devuelve {ip: {proveedor: {datos}}}. Las IPs privadas se omiten y los
    proveedores sin clave no se consultan.
    """
    keys = {k: (v or "").strip() for k, v in (keys or {}).items()}
    providers = [name for name in _IP_FUNCS if keys.get(name)]
    _load_cache()

    unique = [ip for ip in list(dict.fromkeys(ips or [])) if ip and not _is_private(ip)]
    out: dict[str, dict] = {}
    for ip in unique:
        entry: dict[str, dict] = {}
        for provider in providers:
            cached = (_cache["ips"].get(ip) or {}).get(provider)
            if cached:
                entry[provider] = cached
                continue
            func = _IP_FUNCS[provider]
            result = func(ip, keys[provider])
            if result:
                entry[provider] = result
                _cache["ips"].setdefault(ip, {})[provider] = result
        if entry:
            out[ip] = entry
    _save_cache()
    return out


def provider_label(provider: str) -> str:
    return IP_PROVIDER_LABELS.get(provider, provider)