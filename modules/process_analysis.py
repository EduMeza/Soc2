"""Detección multicanal de procesos sospechosos.

Combina:
1. Regex extendido sobre texto libre (description, rule, cve, process, status)
   más columnas adicionales de proceso/comando presentes en el CSV
   (data.win.eventdata.image, commandLine, parentImage, data.win.system.message,
   full_log, ...).
2. rule.id de Wazuh mapeados a procesos sospechosos (p. ej. 92058 sdbinst.exe).
3. rule.level >= 12 como señal COMBIENAda: solo marca si la fila además tiene
   contenido de proceso (evita marcar todo un lote alto/crítico).
4. Heurísticas simples (opcionales, solo aplican si existen las columnas):
   rutas inusuales, integridad baja ejecutada como SYSTEM y procesos con
   parent sospechoso (svchost.exe lanzando cmd/powershell).

Devuelve por fila: bandera booleana + fragmento legible; y la lista de
fragmentos únicos (para el reporte y la tabla de hallazgos).
"""
from __future__ import annotations

import re

import pandas as pd

from modules.column_detector import normalize as _norm_col
from modules.config import (
    EXTRA_PROCESS_FIELDS,
    SUSPICIOUS_CHILD_PATTERN,
    SUSPICIOUS_PARENT_PATTERN,
    SUSPICIOUS_PROCESS_REGISTRY,
    SUSPICIOUS_PATH_PATTERN,
    SUSPICIOUS_RULE_IDS,
    SUSPICIOUS_RULE_LEVEL_BOOST,
)

TEXT_FIELDS = ("description", "rule", "cve", "process", "status")

_INTEGRITY_ALIASES = {
    "datawineventdataintegritylevel",
    "wineventdataintegritylevel",
    "integritylevel",
    "processintegritylevel",
}

_SUBJECT_ALIASES = {
    "datawineventdatasubjectusername",
    "wineventdatasubjectusername",
    "subjectusername",
    "datawinsystemsubjectusername",
    "winsystemsubjectusername",
    "subjectusersid",
}

_PARENT_ALIASES = {
    "datawineventdataparentprocessname",
    "wineventdataparentprocessname",
    "parentprocessname",
    "datawineventdataparentimage",
    "wineventdataparentimage",
    "parentimage",
}

_CHILD_ALIASES = {
    "datawineventdataprocessname",
    "wineventdataprocessname",
    "processname",
    "datawineventdataimage",
    "wineventdataimage",
    "eventdataimage",
    "process",
}

_compiled_registry: list[tuple[re.Pattern, str]] | None = None


def _registry() -> list[tuple[re.Pattern, str]]:
    global _compiled_registry
    if _compiled_registry is None:
        _compiled_registry = [
            (re.compile(pattern, re.IGNORECASE), label)
            for pattern, label in SUSPICIOUS_PROCESS_REGISTRY
        ]
    return _compiled_registry


def _as_int(value: object) -> int | None:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return None
    match = re.search(r"\d+", str(value))
    return int(match.group()) if match else None


def _clean(value: object) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return ""
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


def _process_text(row: pd.Series, extra_cols: list[str]) -> str:
    """Une el texto de la fila: columnas canónicas + columnas extra de proceso."""
    parts = []
    for field in TEXT_FIELDS:
        value = _clean(row.get(field))
        if value:
            parts.append(value)
    for column in extra_cols:
        value = _clean(row.get(column))
        if value:
            parts.append(value)
    return " ".join(parts)


def _has_process_content(row: pd.Series, extra_cols: list[str]) -> bool:
    """True si la fila trae contenido de proceso/comando en alguna columna."""
    for field in ("process", *extra_cols):
        if _clean(row.get(field)):
            return True
    return False


def _column_names(df: pd.DataFrame) -> dict[str, str]:
    return {_norm_col(c): c for c in df.columns}


def _value(row: pd.Series, column: str | None) -> str:
    if not column:
        return ""
    return _clean(row.get(column))


def _column_for(names: dict[str, str], aliases: set[str]) -> str | None:
    for alias in aliases:
        if alias in names:
            return names[alias]
    return None


def _low_integrity_as_system(row: pd.Series, names: dict[str, str]) -> bool:
    integrity = _value(row, _column_for(names, _INTEGRITY_ALIASES)).casefold()
    subject = _value(row, _column_for(names, _SUBJECT_ALIASES)).casefold()
    if not integrity or not subject:
        return False
    low = ("low" in integrity or "sin definir" in integrity
           or (integrity.isdigit() and int(integrity) <= 1))
    system = subject == "system" or "system" in subject and "nt authority" in subject
    return low and system


def _suspicious_parent(row: pd.Series, names: dict[str, str]) -> bool:
    parent = _value(row, _column_for(names, _PARENT_ALIASES))
    child = _value(row, _column_for(names, _CHILD_ALIASES))
    if not parent or not child:
        return False
    return bool(SUSPICIOUS_PARENT_PATTERN.search(parent)
                and SUSPICIOUS_CHILD_PATTERN.search(child))


def detect_suspicious_processes(
    df: pd.DataFrame,
) -> tuple[pd.Series, pd.Series, list[str]]:
    """Analiza el DataFrame y devuelve (flag_por_fila, fragmento_por_fila,
    fragmentos_inicos). Añade además las columnas 'proc_sospechoso' y
    'hallazgo_proceso' al DataFrame de entrada (para los hallazgos relevantes).
    """
    names = _column_names(df)
    extra_cols = [
        c for c in df.columns
        if _norm_col(c) in EXTRA_PROCESS_FIELDS
        and _norm_col(c) not in {_norm_col(f) for f in TEXT_FIELDS}
    ]
    rule_id_col = _column_for(names, {"ruleid"})
    rule_level_col = _column_for(names, {"rulelevel"})

    flags: list[bool] = []
    fragments: list[str] = []
    unique: list[str] = []
    seen: set[str] = set()

    texts = df.apply(lambda row: _process_text(row, extra_cols), axis=1)

    for i in range(len(df)):
        row = df.iloc[i]
        text = texts.iloc[i]
        signals: list[str] = []

        if text:
            for pattern, label in _registry():
                if pattern.search(text):
                    signals.append(label)
                    break

            if SUSPICIOUS_PATH_PATTERN.search(text):
                signals.append("proceso en ruta inusual (AppData/Temp)")

        rule_id = _as_int(row.get(rule_id_col)) if rule_id_col else None
        if rule_id in SUSPICIOUS_RULE_IDS:
            signals.append(SUSPICIOUS_RULE_IDS[rule_id])

        rule_level = _as_int(row.get(rule_level_col)) if rule_level_col else None
        if (rule_level is not None
                and rule_level >= SUSPICIOUS_RULE_LEVEL_BOOST
                and _has_process_content(row, extra_cols)):
            signals.append(f"rule.level {rule_level} + actividad de proceso")

        if _low_integrity_as_system(row, names):
            signals.append("integridad baja como SYSTEM")
        if _suspicious_parent(row, names):
            signals.append("svchost.exe/winlogon lanzando shell")

        flag = bool(signals)
        flags.append(flag)
        fragment = signals[0] if signals else ""
        fragments.append(fragment)

        if flag and fragment and fragment not in seen:
            seen.add(fragment)
            unique.append(fragment)

    flag_series = pd.Series(flags, index=df.index)
    fragment_series = pd.Series(fragments, index=df.index)
    df["proc_sospechoso"] = flag_series
    df["hallazgo_proceso"] = fragment_series

    return flag_series, fragment_series, unique