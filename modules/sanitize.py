"""Utilidades de escape para prevenir XSS en st.markdown(unsafe_allow_html=True).

Cualquier texto que provenga del usuario (nombres de analistas, agentes,
IPs, CVEs, descripciones de eventos, etc.) debe pasar por esc() antes de
renderizarse con HTML crudo.
"""
from __future__ import annotations

import html


def esc(value) -> str:
    """Escapa HTML entities. Safe para texto plano del usuario."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)
