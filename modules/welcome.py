"""Pantalla de bienvenida del SOC 24x7 (se ve antes del login)."""
from __future__ import annotations

import streamlit as st

from modules.ui import chip_html, section_title


PLATFORM_VERSION = "1.0.0"
PLATFORM_NAME = "SOC 24x7"


def render_welcome() -> None:
    """Pantalla de bienvenida que se muestra antes del login."""

    # No mostrar sidebar para no-autenticados (evita acceso parcial)
    st.markdown("""
    <style>
    [data-testid="stSidebar"] { display: none; }
    [data-testid="stSidebarCollapsedControl"] { display: none; }
    </style>
    """, unsafe_allow_html=True)

    col_l, col_r = st.columns([1, 2], gap="large")

    with col_l:
        st.markdown(f"""
<div class='soc-brand' style='font-size:2.1rem;margin-bottom:1rem;'>
  <span class='dot'>🛡️</span> {PLATFORM_NAME}
</div>
<p style='color:var(--muted);font-size:.95rem;max-width:360px'>
  Plataforma centralizada para monitoreo, análisis y gestión de eventos de seguridad.
</p>
""", unsafe_allow_html=True)

    with col_r:
        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        st.caption(f"Versión {PLATFORM_VERSION} · Plataforma corporativa")

        chips = chip_html("Seguridad garantizada", "ok") + chip_html("24x7", "info") + chip_html("Monitoreo continuo", "neutral")
        st.markdown(chips, unsafe_allow_html=True)


def render_login_gate() -> None:
    """Muestra welcome + botón para ir al login (control de acceso primero).
    
    Flujo:
    1. Primera visita: muestra welcome + botón "INGRESAR AL SOC"
    2. Click en botón: setea _show_login=True y rerun
    3. Segunda pasada: salta welcome y llama a gate_login() para mostrar formulario de login
    4. Login exitoso: setea authentication_status=True, _show_login=False, rerun
    5. Próxima pasada: usuario ya autenticado, retorna y continua al dashboard
    """

    # Si ya está autenticado, no mostrar welcome ni login - continuar al dashboard
    if st.session_state.get("authentication_status", False):
        return

    # Inicializar estado si no existe
    if "_show_login" not in st.session_state:
        st.session_state["_show_login"] = False

    # Si ya se pidió mostrar login, saltamos welcome y mostramos login real
    if st.session_state.get("_show_login", False):
        from modules.auth import gate_login
        gate_login()
        return

    # Mostrar welcome (primera visita)
    render_welcome()

    st.markdown("<div style='height:12px'></div>", unsafe_allow_html=True)

    col_l, col_r = st.columns([1, 1], gap="large")

    with col_l:
        st.markdown("""
**Para acceder al sistema:**

- Solicita tus credenciales al administrador del SOC.
- La contraseña temporal debe cambiarse en tu primer acceso.

> Acceso restringido a personal autorizado.
""")

    with col_r:
        st.markdown("<div style='height:20px'></div>", unsafe_allow_html=True)
        # Botón simple y directo - sin formularios, sin callbacks
        if st.button("▶ INGRESAR AL SOC", type="primary", width="stretch", key="btn_enter_soc"):
            st.session_state["_show_login"] = True
            st.rerun()

    # Si todavía no se pidió mostrar login, cortamos aquí (no mostramos login)
    if not st.session_state.get("_show_login", False):
        st.stop()