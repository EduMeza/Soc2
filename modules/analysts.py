"""Gestión de analistas con persistencia en JSON.

Los analistas se guardan en data/analysts.json. La primera vez se crea el
archivo con los analistas predefinidos. Un fichero se mantiene como fuente de
verdad y se sincroniza con session_state de Streamlit.
"""
from __future__ import annotations

import json

from modules.config import ANALYSTS_FILE, DEFAULT_ANALYSTS


def _load_analysts_from_disk() -> list[str]:
    """Lee la lista de analistas desde el JSON de persistencia.

    Si el archivo no existe, lo inicializa con los analistas predefinidos.
    Devuelve siempre una lista de analistas con nombre no vacío y sin duplicados.
    """
    try:
        if not ANALYSTS_FILE.exists():
            _save_analysts_to_disk(DEFAULT_ANALYSTS)
            return list(DEFAULT_ANALYSTS)

        with ANALYSTS_FILE.open("r", encoding="utf-8") as fh:
            data = json.load(fh)

        analysts = data.get("analysts", []) if isinstance(data, dict) else data
        analysts = [str(a).strip() for a in analysts if str(a).strip()]
        if not analysts:
            _save_analysts_to_disk(DEFAULT_ANALYSTS)
            return list(DEFAULT_ANALYSTS)

        # Deduplicar preservando orden.
        seen, unique = set(), []
        for name in analysts:
            if name.casefold() not in seen:
                seen.add(name.casefold())
                unique.append(name)
        return unique
    except (OSError, json.JSONDecodeError):
        return list(DEFAULT_ANALYSTS)


def _save_analysts_to_disk(analysts: list[str]) -> None:
    """Guarda la lista de analistas en el JSON de persistencia."""
    ANALYSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = ANALYSTS_FILE.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as fh:
        json.dump({"analysts": [a for a in analysts if a]}, fh, ensure_ascii=False, indent=2)
    temp.replace(ANALYSTS_FILE)


def ensure_analysts_initialized(session_state) -> None:
    """Inicializa session_state con los analistas y el analista por defecto."""
    if "analysts" not in session_state:
        session_state.analysts = _load_analysts_from_disk()
    if "current_analyst" not in session_state:
        session_state.current_analyst = session_state.analysts[0] if session_state.analysts else ""
    # Mantener coherencia por si el archivo fue modificado externamente.
    session_state.analysts = _load_analysts_from_disk()


def get_analysts(session_state) -> list[str]:
    """Devuelve la lista de analistas disponibles."""
    ensure_analysts_initialized(session_state)
    return session_state.analysts


def add_analyst(session_state, full_name: str) -> tuple[bool, str]:
    """Registra un nuevo analista.

    Devuelve (ok, mensaje). Si el nombre ya existe (ignorando mayúsculas) no lo
    agrega de nuevo.
    """
    name = (full_name or "").strip()
    if not name:
        return False, "El nombre del analista no puede estar vacío."

    existing = {a.casefold() for a in session_state.analysts}
    if name.casefold() in existing:
        return False, f"El analista '{name}' ya está registrado."

    session_state.analysts.append(name)
    _save_analysts_to_disk(session_state.analysts)
    return True, f"Analista '{name}' registrado correctamente."


def remove_analyst(session_state, full_name: str) -> tuple[bool, str]:
    """Elimina un analista de la lista persistente."""
    if full_name not in session_state.analysts:
        return False, "El analista seleccionado no existe."
    session_state.analysts.remove(full_name)
    if session_state.current_analyst == full_name and session_state.analysts:
        session_state.current_analyst = session_state.analysts[0]
    _save_analysts_to_disk(session_state.analysts)
    return True, f"Analista '{full_name}' eliminado."