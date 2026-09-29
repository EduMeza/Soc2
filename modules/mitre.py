"""Clasificación de hallazgos según MITRE ATT&CK.

Asigna cada evento a las tácticas relevantes combinando:
- patrones de texto (descripción/rule/cve/proceso) por táctica, y
- reglas de Wazuh (columna `rule_id`) mapeadas a cada táctica en `config.py`.

Devuelve un resumen por táctica (conteo, ejemplo, técnicas y rule.id activos)
y un DataFrame con columnas booleanas 'mitre_*'.
"""
from __future__ import annotations

import re

import pandas as pd

from modules.analysis import _combine_text, TEXT_FIELDS
from modules.config import MITRE_TECHNIQUES


def _rule_int(value: object) -> int | None:
    """Convierte un valor de rule.id a entero ('92058.0' o '92058' -> 92058)."""
    if value is None:
        return None
    if isinstance(value, float) and pd.isna(value):
        return None
    try:
        return int(float(str(value).strip()))
    except (ValueError, TypeError):
        return None


def _rule_matches(df: pd.DataFrame, rule_ids: list[int]) -> pd.Series:
    """Serie booleana: filas cuyo rule.id está en `rule_ids` de la táctica."""
    if not rule_ids or "rule_id" not in df.columns:
        return pd.Series(False, index=df.index)
    wanted = {int(r) for r in rule_ids}
    values = df["rule_id"].map(_rule_int)
    return values.isin(wanted).fillna(False).astype(bool)


def _matched_rule_ids(df: pd.DataFrame, rule_ids: list[int]) -> list[int]:
    """Rule ids de Wazuh que realmente aparecen en el lote para la táctica."""
    if not rule_ids or "rule_id" not in df.columns:
        return []
    wanted = {int(r) for r in rule_ids}
    values = df["rule_id"].map(_rule_int)
    counts = values.value_counts(dropna=False).to_dict()
    return sorted(rid for rid in wanted if counts.get(rid, 0))


def _flag_matrix(df: pd.DataFrame) -> dict[str, pd.Series]:
    """Devuelve, por técnica MITRE, una Serie booleana de eventos que la cumplen
    (patrón de texto o rule.id de Wazuh)."""
    flags: dict[str, pd.Series] = {}
    text = df.apply(_combine_text, axis=1)
    for technique, meta in MITRE_TECHNIQUES.items():
        combined = pd.Series(False, index=df.index)
        for pattern in meta["patterns"]:
            combined |= text.str.contains(pattern.pattern, regex=True, na=False)
        combined |= _rule_matches(df, meta.get("rule_ids", []))
        flags[technique] = combined
    return flags


def classify(df: pd.DataFrame) -> tuple[dict[str, dict], pd.DataFrame]:
    """Clasifica los eventos y devuelve (resumen_por_tecnica, df con columnas MITRE).

    El DataFrame devuelto incluye una columna booleana por técnica (prefijo
    'mitre_') que puede reutilizarse para filtros o gráficos.
    """
    flags = _flag_matrix(df)
    enriched = df.copy()
    summary: dict[str, dict] = {}

    for technique, meta in MITRE_TECHNIQUES.items():
        mask = flags[technique]
        col = f"mitre_{_slug(technique)}"
        enriched[col] = mask

        count = int(mask.sum())
        example = ""
        if count:
            samples = enriched.loc[mask, TEXT_FIELDS].head(1)
            values = []
            for raw in samples.iloc[0].values:
                txt = str(raw).strip() if pd.notna(raw) else ""
                if txt and txt.lower() != "nan":
                    values.append(txt)
            example = " | ".join(values)[:180]

        summary[technique] = {
            "tactic_id": meta["tactic_id"],
            "count": count,
            "example": example,
            "description": meta["description"],
            "rule_ids": _matched_rule_ids(df, meta.get("rule_ids", [])),
            "techniques": meta.get("techniques", []),
        }

    return summary, enriched


def _slug(name: str) -> str:
    """Convierte un nombre de técnica en sufijo seguro para nombre de columna."""
    return re.sub(r"[^a-z0-9]+", "_", name.casefold()).strip("_")