"""Parser CSV robusto migrado del motor SOC original."""
from __future__ import annotations

import csv
import io
import re
import unicodedata
from pathlib import Path
from typing import BinaryIO, TextIO, Union

import pandas as pd
import numpy as np

# Límites de seguridad
DEFAULT_MAX_CSV_MB = 50
DEFAULT_MAX_ROWS = 200_000
MAX_COLUMNS = 80

CANONICAL_FIELDS = (
    "severity",
    "agent",
    "timestamp",
    "rule",
    "description",
    "src_ip",
    "dst_ip",
    "cve",
    "process",
    "status",
    "user",
)

SEVERITY_MAP = {
    "critical": "Critical", "critico": "Critical", "critica": "Critical", "emergency": "Critical", "nivelcritico": "Critical",
    "4": "Critical", "5": "Critical",
    "high": "High", "alta": "High", "alto": "High", "elevated": "High", "3": "High",
    "medium": "Medium", "media": "Medium", "moderate": "Medium", "warning": "Medium", "2": "Medium",
    "low": "Low", "baja": "Low", "bajo": "Low", "info": "Low", "informational": "Low", "informative": "Low", "notification": "Low", "1": "Low",
}

SEVERITY_LEVEL_RANGES = [
    (15, 15, "Critical"),
    (12, 14, "High"),
    (4, 5, "Critical"),
    (3, 3, "High"),
    (2, 2, "Medium"),
    (1, 1, "Low"),
]

COLUMN_ALIASES = {
    "severity": {"rulelevel", "severity", "severidad", "prioridad", "priority", "level", "nivel", "criticality", "criticidad", "gravedad", "risk", "riesgo", "sevrity"},
    "agent": {"agent", "agente", "hostname", "host", "computername", "computer", "equipo", "workstation", "machine", "maquina", "wazuhagent", "agentname", "agentid", "host_name", "computer_name"},
    "timestamp": {"timestamp", "time", "fecha", "datetime", "date", "hora", "event_time", "created", "created_at", "time_created", "when"},
    "rule": {"rule", "rule_id", "rule_name", "regla", "signature", "signature_id", "azure", "detections", "eventcode", "event_id", "id"},
    "description": {"description", "descripcion", "message", "mensaje", "details", "detalle", "summary", "resumen", "log", "event", "text", "full_log", "alert", "event_title", "log_notes", "data"},
    "src_ip": {"src_ip", "source_ip", "srcip", "sourceip", "ip_origen", "source", "src", "origen", "sourceaddress", "srcaddress", "srcaddr", "direccion_ip_origen", "sip"},
    "dst_ip": {"dst_ip", "dest_ip", "destination_ip", "dstip", "destip", "ip_destino", "destino", "destination", "dst", "dest", "destinationaddress", "dstaddress", "dip"},
    "cve": {"cve", "cve_id", "vulnerability", "vuln_id"},
    "process": {"process", "proceso", "process_name", "processname", "module", "executable", "program", "image", "file"},
    "user": {"user", "usuario", "username", "principal", "account", "cuenta", "actor", "actoruser", "targetusername", "user.name"},
    "status": {"status", "estado", "action", "accion", "result", "outcome", "success", "eventaction", "event_type"},
}


def _check_size(content: bytes, max_mb: int) -> None:
    if len(content) > max_mb * 1024 * 1024:
        raise ValueError(
            f"El CSV excede el límite de {max_mb} MB ({len(content) / 1024 / 1024:.1f} MB recibidos)."
        )


def _norm(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def _fold(value: str) -> str:
    text = unicodedata.normalize("NFKD", value)
    return "".join(c for c in text if not unicodedata.combining(c))


def _normalize_severity(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "Unknown"
    low = _fold(str(value).strip().casefold())
    if low.startswith("cri"):
        return "Critical"
    if low.startswith("hig") or low.startswith("alt") or low.startswith("ele"):
        return "High"
    if low.startswith("med") or low.startswith("mod") or low.startswith("war"):
        return "Medium"
    if low.startswith("low") or low.startswith("baj") or low.startswith("inf"):
        return "Low"
    low_folded = _fold(str(value)).casefold()
    if low_folded in SEVERITY_MAP:
        return SEVERITY_MAP[low_folded]
    match = re.search(r"\d{1,3}", low)
    if match:
        level = int(match.group())
        for lo, hi, canonical in SEVERITY_LEVEL_RANGES:
            if lo <= level <= hi:
                return canonical
    return "Unknown"


def normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


def detect_columns(columns: list[str]) -> dict[str, str]:
    normalized = {normalize(c): c for c in columns}
    detected = {}
    for canonical, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            norm_alias = normalize(alias)
            if norm_alias in normalized:
                detected[canonical] = normalized[norm_alias]
                break
    return detected


def normalize_dataframe(df: pd.DataFrame, detected: dict[str, str]) -> pd.DataFrame:
    out = df.copy()
    norm_cols = {normalize(c): c for c in out.columns}
    if "rulelevel" in norm_cols:
        out["rule_level"] = out[norm_cols["rulelevel"]]
    if "ruleid" in norm_cols:
        out["rule_id"] = out[norm_cols["ruleid"]]

    rename_map: dict[str, str] = {}
    for canonical in CANONICAL_FIELDS:
        src = detected.get(canonical)
        if not src:
            continue
        if src != canonical:
            rename_map[src] = canonical
            if canonical in out.columns:
                out = out.drop(columns=[canonical])

    if rename_map:
        out = out.rename(columns=rename_map)

    for canonical in CANONICAL_FIELDS:
        if canonical not in out.columns:
            out[canonical] = ""

    out["severity"] = np.vectorize(_normalize_severity)(out["severity"].values)
    out["agent"] = out["agent"].apply(lambda v: str(v).strip() if v is not None else "")
    out["timestamp"] = out["timestamp"].apply(lambda v: str(v).strip() if v is not None else "")
    if "user" in out.columns:
        out["user"] = out["user"].apply(lambda v: str(v).strip() if v is not None else "")
    return out


def load_csv(
    content: bytes,
    max_mb: int = DEFAULT_MAX_CSV_MB,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> tuple[pd.DataFrame, dict[str, str]]:
    _check_size(content, max_mb)

    try:
        # Try utf-8-sig first (handles BOM)
        df = pd.read_csv(io.BytesIO(content), encoding="utf-8-sig")
    except UnicodeDecodeError:
        try:
            df = pd.read_csv(io.BytesIO(content), encoding="latin-1")
        except Exception:
            raise ValueError("No se pudo decodificar el CSV. Use UTF-8 o Latin-1.")

    if len(df.columns) > MAX_COLUMNS:
        raise ValueError(f"El CSV tiene demasiadas columnas ({len(df.columns)} > {MAX_COLUMNS}).")
    if len(df) > max_rows:
        raise ValueError(f"El CSV excede el límite de {max_rows:,} filas ({len(df):,} recibidas).")

    detected = detect_columns(df.columns.tolist())
    df = normalize_dataframe(df, detected)
    return df, detect_columns(df.columns.tolist())