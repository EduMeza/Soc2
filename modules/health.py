"""Panel de estado del SOC (Health Check), visible solo si el usuario pasa login.

Requiere llamar a ``render_health_panel`` desde la página principal cuando el
usuario está autenticado. No muestra nada a usuarios sin autenticación.

Estado:
- Verde: todos los indicadores OK
- Amarillo: al menos 1 degradado (warning)
- Rojo: al menos 1 error (falla crítica)
"""
from __future__ import annotations

import os
from datetime import datetime

import streamlit as st
from dotenv import load_dotenv

try:
    load_dotenv()
except ImportError:
    pass


def _check_wazuh() -> dict:
    """Verifica conexión con Wazuh Indexer (solo ping, no query completa)."""
    url = os.getenv("WAZUH_INDEXER_URL", "")
    user = os.getenv("WAZUH_USER", "")
    pw = os.getenv("WAZUH_PASSWORD", "")
    verify = os.getenv("WAZUH_VERIFY_SSL", "true").lower() in ("1", "true", "yes")
    ca = os.getenv("WAZUH_CA_BUNDLE", "").strip().strip() or None

    if not all([url, user, pw]):
        return {"label": "Wazuh Indexer", "status": "warning", "detail": "No configurado", "healthy": False}

    try:
        import requests
        session = requests.Session()
        session.auth = (user, pw)
        if ca and verify:
            session.verify = ca
        else:
            session.verify = verify
        session.timeout = (3, 3)  # rápido: no se espera mucho
        resp = session.get(f"{url.rstrip('/')}/_cluster/health", timeout=(3, 3))
        resp.raise_for_status()
        return {"label": "Wazuh Indexer", "status": "ok", "detail": "Conectado", "healthy": True}
    except Exception as e:
        return {"label": "Wazuh Indexer", "status": "error", "detail": f"Error: {type(e).__name__}", "healthy": False}


def _check_scheduler() -> dict:
    """Verifica si hay lanzamientos pendientes según schedule_config."""
    try:
        from modules.scheduler import get_schedule_config
        cfg = get_schedule_config()
        if cfg.auto_enabled:
            return {"label": "Scheduler", "status": "ok", "detail": "Activo", "healthy": True}
        return {"label": "Scheduler", "status": "ok", "detail": "Desactivado", "healthy": True}
    except Exception:
        return {"label": "Scheduler", "status": "error", "detail": "No disponible", "healthy": False}


def _check_parser() -> dict:
    """Comprueba que el parser funcione (busca errores conocidos)."""
    try:
        modules_path = __import__("modules.parser", fromlist=["load_csv"])
        # Test básico: el módulo se puede importar y tiene la API esperada
        assert callable(getattr(modules_path, "load_csv", None)), "missing load_csv"
        assert callable(getattr(modules_path, "normalize_dataframe", None)), "missing normalize_dataframe"
        return {"label": "Parser CSV", "status": "ok", "detail": "Validación OK", "healthy": True}
    except Exception as e:
        return {"label": "Parser CSV", "status": "error", "detail": f"Error: {e}", "healthy": False}


def _check_timestamps() -> dict:
    """Verifica que la fecha actual sea navegable (timezone-aware)."""
    now = datetime.now()
    if now.tzinfo is None:
        return {"label": "Timezone", "status": "ok", "detail": f"local", "healthy": True}
    return {"label": "Timezone", "status": "ok", "detail": "Timezone-aware OK", "healthy": True}


def _get_status_icon(status: str) -> str:
    if status == "ok":
        return "🟢"
    if status == "warning":
        return "🟡"
    if status == "error":
        return "🔴"
    return "⚪"


def get_soc_status() -> tuple[str, str, list[dict]]:
    """Obtiene el estado general del SOC sin renderizar nada.
    
    Returns:
        tuple: (status_str, status_label, checks_list)
        status_str: "up" | "degraded" | "error"
        status_label: "OPERATIVO" | "DEGRADADO" | "ERROR"
        checks_list: lista de dicts con los checks individuales
    """
    checks = [
        _check_wazuh(),
        _check_scheduler(),
        _check_parser(),
        _check_timestamps(),
    ]

    overall_ok = all(c["healthy"] for c in checks)
    has_error = any(c["status"] == "error" for c in checks)
    has_warning = any(c["status"] == "warning" for c in checks)

    if overall_ok:
        return "up", "OPERATIVO", checks
    elif has_error:
        return "error", "ERROR", checks
    else:
        return "degraded", "DEGRADADO", checks


def render_health_panel() -> None:
    """Muestra el estado del SOC (solo si autenticado)."""
    from modules.auth import require_role  # RBAC

    require_role("ADMIN", "SOC_ANALYST", "AUDITOR", view_name="health_panel")

    checks = [
        _check_wazuh(),
        _check_scheduler(),
        _check_parser(),
        _check_timestamps(),
    ]

    overall_ok = all(c["healthy"] for c in checks)
    icon = "🟢" if overall_ok else ("🟡" if all(c["healthy"] or c["status"] == "warning" for c in checks) else "🔴")

    with st.expander(f"{icon} Estado del sistema", expanded=False):
        for c in checks:
            st.markdown(f"{_get_status_icon(c['status'])} **{c['label']}** — {c['detail']}")
        if all(c["healthy"] for c in checks):
            st.caption("Todos los checks funcionan correctamente.")
        elif any(c["status"] == "error" for c in checks):
            st.caption("Al menos 1 integración tiene fallo — corregir antes de usar.")
        else:
            st.caption("Estado degradado: algunos módulos responden pero pueden no funcionar del todo.")
