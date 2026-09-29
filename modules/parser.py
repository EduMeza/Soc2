"""Lectura y normalización del CSV cargado por el usuario."""
from __future__ import annotations

import io
import re
import unicodedata
from pathlib import Path

import pandas as pd
import numpy as np

from modules.column_detector import detect_columns, normalize
from modules.config import COLUMN_ALIASES, SEVERITY_LEVEL_RANGES, SEVERITY_MAP

# Límites de seguridad para el upload de CSV (configurables por entorno)
DEFAULT_MAX_CSV_MB = 50          # tamaño máximo del archivo
DEFAULT_MAX_ROWS = 200_000       # filas máximas que se cargan en memoria
MAX_COLUMNS = 80                 # columnas máximas aceptadas

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


def _check_size(content: object, max_mb: int) -> None:
    """Valida que el contenido no exceda el límite de tamaño."""
    if isinstance(content, Path):
        size = content.stat().st_size
    elif isinstance(content, str) and Path(content).exists():
        size = Path(content).stat().st_size
    elif isinstance(content, (bytes, bytearray)):
        size = len(content)
    elif hasattr(content, "getvalue"):
        data = content.getvalue()
        size = len(data) if hasattr(data, "__len__") else max_mb * 1024 * 1024
    else:
        return  # stream sin tamaño conocido: lo limita read_csv con nrows
    if size > max_mb * 1024 * 1024:
        raise ValueError(
            f"El CSV excede el límite de {max_mb} MB ({size / 1024 / 1024:.1f} MB recibidos)."
        )


def _is_safe_path(path: Path) -> bool:
    """Evita path traversal: solo se aceptan rutas dentro del proyecto."""
    try:
        from modules.config import PROJECT_ROOT
        resolved = path.resolve()
        root = Path(PROJECT_ROOT).resolve()
        return str(resolved).startswith(str(root))
    except Exception:
        return False


def load_csv(file, max_mb: int = DEFAULT_MAX_CSV_MB,
             max_rows: int = DEFAULT_MAX_ROWS) -> tuple[pd.DataFrame, dict[str, str]]:
    """Lee un archivo CSV subido y devuelve (DataFrame, columnas detectadas).

    Valida tamaño (50 MB por defecto), volumen de filas (200k) y columnas (80).
    Las rutas de archivo fuera del directorio del proyecto se rechazan.
    """
    # --- Validación de path traversal -------------------------------
    if isinstance(file, str):
        p = Path(file)
        if p.exists() and not _is_safe_path(p):
            raise ValueError("La ruta del archivo debe estar dentro del proyecto.")
    elif isinstance(file, Path):
        if not _is_safe_path(file):
            raise ValueError("La ruta del archivo debe estar dentro del proyecto.")

    content: object
    if hasattr(file, "getvalue"):
        content = file.getvalue()
    elif hasattr(file, "read"):
        content = file.read()
    elif isinstance(file, (bytes, bytearray)):
        content = file
    else:
        content = Path(file) if isinstance(file, str) else file  # ruta de archivo

    # --- Validación de tamaño -----------------------------------------
    _check_size(content, max_mb)

    if isinstance(content, bytes):
        content = io.BytesIO(content)

    try:
        df = pd.read_csv(content, encoding="utf-8-sig")
    except Exception:
        if hasattr(content, "seek"):
            content.seek(0)
        df = pd.read_csv(content, encoding="latin-1")

    # --- Validación de volumen filas/columnas --------------------------
    if len(df.columns) > MAX_COLUMNS:
        raise ValueError(f"El CSV tiene demasiadas columnas ({len(df.columns)} > {MAX_COLUMNS}).")
    if len(df) > max_rows:
        raise ValueError(
            f"El CSV excede el límite de {max_rows:,} filas ({len(df):,} recibidas)."
        )

    detected = detect_columns(df.columns.tolist())
    return df, detected


def _norm(value: object) -> str:
    """Devuelve una representación de texto en minúsculas y limpia del valor."""
    if pd.isna(value):
        return ""
    return str(value).strip()


def _fold(value: str) -> str:
    """Elimina acentos y diacríticos (mantiene el resto de caracteres)."""
    text = unicodedata.normalize("NFKD", value)
    return "".join(c for c in text if not unicodedata.combining(c))


def _normalize_severity(value: object) -> str:
    """Convierte cualquier valor de severidad a un nivel canónico (Est/Abreviado).

    Soporta:
    - Texto: 'CRITICAL'->'Critical', 'crítico'->'Critical', 'HIGH'->'High', ...
    - Regla de la organización (columna 'rule.level'):
        12, 13, 14 -> High, 15 -> Critical.
    - Niveles genéricos: 4-5 -> Critical, 3 -> High, 2 -> Medium, 1 -> Low.
    - Formatos mixtos: "12 - CRITICO", "Nivel 14", "Sev 15 (Crítico)" -> extrae el número.
    """
    low = _fold(_norm(value).casefold())
    # Palabras clave textuales (prioridad máxima).
    if low.startswith("cri"):
        return "Critical"
    if low.startswith("hig") or low.startswith("alt") or low.startswith("ele"):
        return "High"
    if low.startswith("med") or low.startswith("mod") or low.startswith("war"):
        return "Medium"
    if low.startswith("low") or low.startswith("baj") or low.startswith("inf"):
        return "Low"
    # Coincidencia exacta con claves conocidas (p. ej. 'p1', 'severe').
    if low in SEVERITY_MAP:
        return SEVERITY_MAP[low]
    # Extraer un número del valor (admite "12", "12.0", "Nivel 14", "13 (Crítico)").
    match = re.search(r"\d{1,3}", low)
    if match:
        level = int(match.group())
        for lo, hi, canonical in SEVERITY_LEVEL_RANGES:
            if lo <= level <= hi:
                return canonical
    return "Unknown"


def normalize_dataframe(df: pd.DataFrame, detected: dict[str, str]) -> pd.DataFrame:
    """Normaliza el DataFrame: renombra columnas canónicas y tipa severidad.

    Si la fuente de severidad es 'rule.level' y también existe una columna
    'severity', la columna canónica se reemplaza (rule.level tiene prioridad).
    """
    out = df.copy()

    # Copias técnicas antes del rename: 'rule.level' se usa como severidad,
    # pero el valor numérico se preserva en 'rule_level' para heurísticas
    # (p. ej. rule.level >= 12). 'rule.id' se conserva en 'rule_id'.
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
            # Evitar columnas duplicadas si ya existen como columna canónica.
            if canonical in out.columns:
                out = out.drop(columns=[canonical])

    if rename_map:
        out = out.rename(columns=rename_map)

    # Asegurar columnas canónicas que no existan (para código uniforme).
    for canonical in CANONICAL_FIELDS:
        if canonical not in out.columns:
            out[canonical] = ""

    out["severity"] = np.vectorize(_normalize_severity)(out["severity"].values)
    out["agent"] = out["agent"].apply(_norm)
    out["timestamp"] = out["timestamp"].apply(_norm)
    if "user" in out.columns:
        out["user"] = out["user"].apply(_norm)
    return out


def get_free_text_columns(df: pd.DataFrame, detected: dict[str, str]) -> list[str]:
    """Devuelve las columnas de texto libre para el análisis de patrones.

    Prioriza las columnas descripción y rule, y agrega el resto si el archivo
    tiene pocas columnas (para no saturar la búsqueda regex).
    """
    preferred = []
    for field in ("description", "rule", "cve"):
        if field in detected:
            preferred.append(detected[field])
    # Columnas de texto que podrían contener la descripción lógica.
    text_candidates = [c for c in df.columns if df[c].dtype == object]
    for candidate in text_candidates:
        if candidate not in preferred and candidate not in detected.values():
            preferred.append(candidate)
    return preferred[:6]