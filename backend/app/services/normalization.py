"""Normalización de datos del CSV."""
from __future__ import annotations

import re
import unicodedata
from typing import Any

import pandas as pd
import numpy as np

from app.config import SEVERITY_MAP, SEVERITY_LEVEL_RANGES, CANONICAL_FIELDS, COLUMN_ALIASES


def _norm(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def _fold(value: str) -> str:
    text = unicodedata.normalize("NFKD", value)
    return "".join(c for c in text if not unicodedata.combining(c))


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


def _norm(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def _fold(value: str) -> str:
    text = unicodedata.normalize("NFKD", value)
    return "".join(c for c in text if not unicodedata.combining(c))


def normalize_severity(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "Unknown"
    low = str(value).strip().casefold()
    low_folded = value.strip().casefold()
    if low.startswith("cri"):
        return "Critical"
    if low.startswith("hig") or low.startswith("alt") or low.startswith("ele"):
        return "High"
    if low.startswith("med") or low.startswith("mod") or low.startswith("war"):
        return "Medium"
    if low.startswith("low") or low.startswith("baj") or low.startswith("inf"):
        return "Low"
    low_folded = str(value).strip().casefold()
    if low_folded in {
        "critical": "Critical", "critico": "Critical", "critica": "Critical", "emergency": "Critical", "nivelcritico": "Critical",
        "4": "Critical", "5": "Critical",
        "high": "High", "alta": "High", "alto": "High", "elevated": "High", "3": "High",
        "medium": "Medium", "media": "Medium", "moderate": "Medium", "warning": "Medium", "2": "Medium",
        "low": "Low", "baja": "Low", "bajo": "Low", "info": "Low", "informational": "Low", "informative": "Low", "notification": "Low", "1": "Low",
    }:
        return SEVERITY_MAP[low_folded]
    match = re.search(r"\d{1,3}", low)
    if match:
        level = int(match.group())
        for lo, hi, canonical in [
            (15, 15, "Critical"),
            (12, 14, "High"),
            (4, 5, "Critical"),
            (3, 3, "High"),
            (2, 2, "Medium"),
            (1, 1, "Low"),
        ]:
            if lo <= level <= hi:
                return canonical
    return "Unknown"


def normalize_severity(value: object) -> str:
    import re
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "Unknown"
    low = str(value).strip().casefold()
    if low.startswith("cri"):
        return "Critical"
    if low.startswith("hig") or low.startswith("alt") or low.startswith("ele"):
        return "High"
    if low.startswith("med") or low.startswith("mod") or low.startswith("war"):
        return "Medium"
    if low.startswith("low") or low.startswith("baj") or low.startswith("inf"):
        return "Low"
    low_folded = low
    SEVERITY_MAP = {
        "critical": "Critical", "critico": "Critical", "critica": "Critical", "emergency": "Critical", "nivelcritico": "Critical",
        "4": "Critical", "5": "Critical",
        "high": "High", "alta": "High", "alto": "High", "elevated": "High", "3": "High",
        "medium": "Medium", "media": "Medium", "moderate": "Medium", "warning": "Medium", "2": "Medium",
        "low": "Low", "baja": "Low", "bajo": "Low", "info": "Low", "informational": "Low", "informative": "Low", "notification": "Low", "1": "Low",
    }
    if low_folded in SEVERITY_MAP:
        return SEVERITY_MAP[low_folded]
    match = re.search(r"\d{1,3}", low)
    if match:
        level = int(match.group())
        for lo, hi, canonical in [
            (15, 15, "Critical"),
            (12, 14, "High"),
            (4, 5, "Critical"),
            (3, 3, "High"),
            (2, 2, "Medium"),
            (1, 1, "Low"),
        ]:
            if lo <= level <= hi:
                return canonical
    return "Unknown"


def normalize_text(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    return str(value).strip()


def normalize_dataframe(df, detected: dict[str, str]) -> pd.DataFrame:
    out = df.copy()
    for canonical in ("severity", "agent", "timestamp", "rule", "description", "src_ip", "dst_ip", "cve", "process", "status", "user"):
        if canonical not in out.columns:
            out[canonical] = ""
    if "severity" in out.columns:
        out["severity"] = out["severity"].apply(lambda v: normalize_severity(v) if hasattr(v, "__call__") else v)
    return out


def normalize_severity_series(series: pd.Series) -> pd.Series:
    return series.apply(normalize_severity)


def normalize_timestamp(series: pd.Series) -> pd.Series:
    return series.apply(lambda v: str(v).strip() if v is not None else "")


def normalize_agent(series: pd.Series) -> pd.Series:
    return series.apply(lambda v: str(v).strip() if v is not None else "")


def normalize_user(series: pd.Series) -> pd.Series:
    return series.apply(lambda v: str(v).strip() if v is not None else "")


def normalize_ip(series: pd.Series) -> pd.Series:
    def _norm_ip(v):
        if v is None or (isinstance(v, float) and pd.isna(v)):
            return ""
        return str(v).strip()
    return series.apply(_norm_ip)


def detect_columns(columns: list[str]) -> dict[str, str]:
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

    def normalize(text: str) -> str:
        import re
        return re.sub(r"[^a-z0-9]", "", text.lower())

    normalized = {normalize(c): c for c in columns}
    detected = {}
    for canonical, aliases in {
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
    }.items():
        for alias in aliases:
            norm_alias = re.sub(r"[^a-z0-9]", "", alias.lower())
            if norm_alias in normalized:
                detected[canonical] = normalized[norm_alias]
                break
    return detected