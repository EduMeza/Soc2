"""Componentes de interfaz y hoja de estilos del dashboard SOC 24x7.

Tema oscuro profesional con colores neón:
- Verde neón (#00FF00) para métricas positivas/OK
- Rojo intenso (#FF0000) para alertas críticas
- Amarillo (#FFD700) para advertencias
- Tipografía: Inter/Roboto, títulos en mayúsculas
- Bordes finos en gris claro
"""
from __future__ import annotations

import math
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# Paleta de colores neón SOC
NEON_GREEN = "#00FF00"
NEON_RED = "#FF0000"
NEON_YELLOW = "#FFD700"
NEON_CYAN = "#00FFFF"
NEON_ORANGE = "#FF8C00"
NEON_PURPLE = "#BC13FE"

# Colores de severidad
SEV_COLORS = {
    "Critical": NEON_RED,
    "High": NEON_ORANGE,
    "Medium": NEON_YELLOW,
    "Low": NEON_GREEN,
    "Unknown": "#6B7280",
}

# Colores para MITRE ATT&CK
MITRE_COLORS = {
    "Reconocimiento": NEON_YELLOW,
    "Ejecución": NEON_RED,
    "Persistencia": NEON_PURPLE,
    "Evasión de defensas": NEON_ORANGE,
    "Exfiltración": NEON_CYAN,
    "Comando y Control": NEON_GREEN,
}

SOC_CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {{
    /* SOC Neon Dark Theme */
    --bg-primary: #000000;
    --bg-secondary: #0A0A0A;
    --bg-panel: #111111;
    --bg-panel-hover: #1A1A1A;
    --bg-elevated: #1A1A1A;
    
    --border-primary: #2A2A2A;
    --border-secondary: #333333;
    --border-accent: #3A3A3A;
    
    --text-primary: #FFFFFF;
    --text-secondary: #B0B0B0;
    --text-muted: #6A6A6A;
    --text-dim: #4A4A4A;
    
    --neon-green: {NEON_GREEN};
    --neon-red: {NEON_RED};
    --neon-yellow: {NEON_YELLOW};
    --neon-cyan: {NEON_CYAN};
    --neon-orange: {NEON_ORANGE};
    --neon-purple: {NEON_PURPLE};
    
    --shadow-glow-green: 0 0 20px rgba(0, 255, 0, 0.3);
    --shadow-glow-red: 0 0 20px rgba(255, 0, 0, 0.3);
    --shadow-glow-yellow: 0 0 20px rgba(255, 215, 0, 0.3);
    --shadow-panel: 0 4px 24px rgba(0, 0, 0, 0.5);
    
    --radius-sm: 6px;
    --radius-md: 10px;
    --radius-lg: 16px;
    --radius-xl: 24px;
}}

/* ===== CENTRAL TAB BAR ===== */
.soc-tab-bar {{
    display: flex; 
    gap: 8px; 
    flex-wrap: wrap; 
    justify-content: center;
    padding: 16px 24px; 
    background: var(--bg-panel); 
    border: 1px solid var(--border-primary); 
    border-radius: var(--radius-lg);
    margin: 16px 0; 
    box-shadow: var(--shadow-panel);
}}
.soc-tab-btn {{
    display: flex; 
    align-items: center; 
    gap: 8px;
    padding: 12px 20px; 
    border-radius: var(--radius-md);
    background: var(--bg-secondary); 
    border: 1px solid var(--border-primary);
    color: var(--text-secondary); 
    font-weight: 600; 
    font-size: 13px;
    cursor: pointer; 
    transition: all 0.2s cubic-bezier(0.4,0,0.2,1);
    transform: perspective(500px) rotateX(0deg);
    transform-style: preserve-3d;
}}
.soc-tab-btn:hover {{
    background: var(--bg-panel-hover); 
    color: var(--text-primary);
    border-color: var(--neon-green); 
    transform: perspective(500px) rotateX(-3deg) translateY(-2px);
    box-shadow: 0 8px 24px rgba(0,255,0,0.15);
}}
.soc-tab-btn.active {{
    background: linear-gradient(135deg, rgba(0,255,0,0.15), rgba(0,255,255,0.1));
    color: var(--neon-green); 
    border-color: var(--neon-green);
    box-shadow: 0 0 20px rgba(0,255,0,0.3);
}}
.soc-tab-btn .tab-icon {{
    font-size: 16px; 
    width: 24px; 
    text-align: center;
    display: inline-flex;
    align-items: center;
    justify-content: center;
}}

/* ===== EXPANDABLE SECTION PANEL ===== */
.soc-section-panel {{
    overflow: hidden; 
    border-radius: var(--radius-lg);
    border: 1px solid var(--border-primary); 
    background: var(--bg-panel);
    margin: 8px 0; 
    box-shadow: var(--shadow-panel);
    transform-style: preserve-3d;
    perspective: 1000px;
}}
.soc-section-header {{
    display: flex; 
    align-items: center; 
    justify-content: space-between;
    padding: 16px 20px; 
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border-primary); 
    cursor: pointer;
    transition: background 0.2s ease;
}}
.soc-section-header:hover {{
    background: var(--bg-panel-hover);
}}
.soc-section-title-row {{
    display: flex; 
    align-items: center; 
    gap: 12px;
}}
.soc-section-icon {{
    font-size: 20px; 
    width: 32px; 
    height: 32px;
    display: flex; 
    align-items: center; 
    justify-content: center;
    background: linear-gradient(135deg, var(--neon-green), var(--neon-cyan));
    border-radius: var(--radius-sm);
    color: #000;
    font-weight: 700;
}}
.soc-section-title {{
    font-family: 'Inter', sans-serif;
    font-size: 15px; 
    font-weight: 700; 
    letter-spacing: 0.05em;
    color: var(--text-primary); 
    text-transform: uppercase;
}}
.soc-section-chevron {{
    font-size: 18px; 
    color: var(--text-muted);
    transition: transform 0.3s cubic-bezier(0.4,0,0.2,1);
    transform: rotate(0deg);
}}
.soc-section-chevron.open {{
    transform: rotate(180deg);
}}
.soc-section-content {{
    max-height: 0; 
    opacity: 0; 
    overflow: hidden;
    transition: max-height 0.5s cubic-bezier(0.4,0,0.2,1), 
                opacity 0.3s ease, 
                transform 0.4s cubic-bezier(0.4,0,0.2,1),
                padding 0.4s cubic-bezier(0.4,0,0.2,1);
    transform: translateY(-10px);
    padding: 0 20px;
}}
.soc-section-content.open {{
    max-height: 5000px; 
    opacity: 1; 
    transform: translateY(0);
    padding: 20px;
}}

/* ===== 3D HOVER EFFECTS ===== */
.soc-panel-3d {{
    transform-style: preserve-3d; 
    perspective: 1000px;
    transition: transform 0.3s cubic-bezier(0.4,0,0.2,1), box-shadow 0.3s ease;
}}
.soc-panel-3d:hover {{
    transform: rotateY(2deg) rotateX(-2deg) scale(1.015);
    box-shadow: 0 20px 40px rgba(0,0,0,0.4), 0 0 30px rgba(0,255,0,0.1);
}}

/* ===== ANIMATION KEYFRAMES ===== */
@keyframes soc-fade-in-up {{
    from {{ opacity: 0; transform: translateY(20px); }}
    to {{ opacity: 1; transform: translateY(0); }}
}}
@keyframes soc-pulse-glow {{
    0%, 100% {{ box-shadow: 0 0 20px rgba(0,255,0,0.3); }}
    50% {{ box-shadow: 0 0 40px rgba(0,255,0,0.5), 0 0 60px rgba(0,255,255,0.2); }}
}}
@keyframes soc-float {{
    0%, 100% {{ transform: translateY(0); }}
    50% {{ transform: translateY(-5px); }}
}}
.soc-animate-fade-in-up {{
    animation: soc-fade-in-up 0.6s cubic-bezier(0.4,0,0.2,1) forwards;
}}
.soc-glow-pulse {{
    animation: soc-pulse-glow 2s ease-in-out infinite;
}}
.soc-float {{
    animation: soc-float 3s ease-in-out infinite;
}}

/* Staggered animation delays */
.soc-stagger-1 {{ animation-delay: 0.1s; }}
.soc-stagger-2 {{ animation-delay: 0.2s; }}
.soc-stagger-3 {{ animation-delay: 0.3s; }}
.soc-stagger-4 {{ animation-delay: 0.4s; }}
.soc-stagger-5 {{ animation-delay: 0.5s; }}
.soc-stagger-6 {{ animation-delay: 0.6s; }}

html, body, [class*="css"], .stApp {{
    font-family: 'Inter', 'Segoe UI', Roboto, system-ui, -apple-system, sans-serif;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
}}

.stApp {{ 
    background: var(--bg-primary); 
    color: var(--text-primary); 
}}
section.main {{ background: var(--bg-primary); }}
</style>
"""


# Secciones del nuevo dashboard
SECTIONS = [
    "Centro de Mando",
    "Gestión de Casos", 
    "Último Ataque Detectado",
    "Incidentes Críticos",
    "Panorama",
    "Detección & Caza",
    "Operaciones",
    "Inteligencia & Vigilancia",
    "DFIR & Respuesta",
    "Infraestructura",
    "Administración"
]

# Estructura del sidebar por categorías
SIDEBAR_SECTIONS = {
    "PANORAMA": ["Centro de Mando", "Gobernanza CSF"],
    "DETECCIÓN & CAZA": ["Detección", "Hunt Pivots", "Threat Hunting"],
    "OPERACIONES": ["Campañas", "Operaciones SOC", "Tickets"],
    "INTELIGENCIA & VIGILANCIA": ["Vigilancia Digital", "Defacement"],
    "DFIR & RESPUESTA": ["Activos & Respuesta"],
    "INFRAESTRUCTURA": ["Estado de Fuentes", "Registro de Activos"],
    "ADMINISTRACIÓN": ["Mi Perfil SOC", "Ajustes"],
}


def apply_style() -> None:
    """Inyecta la hoja de estilos global del dashboard."""
    st.markdown(SOC_CSS, unsafe_allow_html=True)


from modules.sanitize import esc


def render_header(
    last_analysis: str = "—",
    user_name: str = "Analista SOC",
    user_role: str = "SOC_ANALYST",
    soc_state: str = "ok",
    critical_count: int = 0
) -> None:
    """Header principal tipo Centro de Mando con estado en tiempo real."""
    
    state_config = {
        "ok": ("OPERATIVO", "ok", NEON_GREEN),
        "degraded": ("DEGRADADO", "warning", NEON_YELLOW),
        "error": ("CRÍTICO", "critical", NEON_RED),
        "unknown": ("SIN DATOS", "unknown", "#6A6A6A"),
    }
    state_label, state_class, state_color = state_config.get(soc_state, state_config["unknown"])
    
    st.markdown(f"""
    <div class="soc-header soc-animate-fade">
        <div class="soc-header-brand">
            <div class="soc-header-logo">🛡️</div>
            <div>
                <div class="soc-header-title">SOC 24x7</div>
                <div class="soc-header-subtitle">Centro de Operaciones de Seguridad</div>
            </div>
        </div>
        <div class="soc-header-status">
            <div class="soc-status-item">
                <span class="soc-status-dot {state_class}"></span>
                <span>{state_label}</span>
            </div>
            <div class="soc-status-item">
                <span class="soc-status-dot critical" style="animation: blink 1s infinite;"></span>
                <span style="color: var(--neon-red); font-weight: 700;">{critical_count} CRÍTICOS</span>
            </div>
            <div class="soc-status-item">
                <span>{esc(user_name)}</span>
                <span style="color: var(--neon-green); font-weight: 600; font-size: 11px; text-transform: uppercase;">{esc(user_role)}</span>
            </div>
            <div class="soc-status-item">
                <span style="color: var(--text-muted);">Último análisis:</span>
                <span style="font-family: 'JetBrains Mono', monospace; color: var(--neon-cyan);">{esc(last_analysis)}</span>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_sidebar_navigation(current_section: str, user_role: str = "SOC_ANALYST", user_name: str = "") -> str:
    """Renderiza la navegación lateral por categorías."""
    
    # CSS para navegación custom
    st.sidebar.markdown("""
    <style>
    .soc-sidebar-nav { padding: 0 8px; }
    .soc-nav-section-label { 
        font-size: 10px; font-weight: 700; letter-spacing: 0.1em; 
        color: var(--text-dim); text-transform: uppercase; 
        margin: 20px 8px 8px 8px; padding: 0 8px;
        border-left: 2px solid var(--neon-green); padding-left: 6px;
    }
    .soc-nav-btn {
        display: flex; align-items: center; gap: 10px;
        width: 100%; padding: 10px 14px; margin: 2px 0;
        background: transparent; border: 1px solid transparent;
        border-radius: 8px; color: var(--text-secondary);
        font-size: 13px; font-weight: 500; cursor: pointer;
        text-align: left; transition: all 0.15s ease;
    }
    .soc-nav-btn:hover {
        background: var(--bg-panel-hover); color: var(--text-primary);
        border-color: var(--border-accent);
    }
    .soc-nav-btn.active {
        background: linear-gradient(90deg, rgba(0, 255, 0, 0.1), transparent);
        color: var(--neon-green); border-color: var(--neon-green);
        box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
    }
    .soc-nav-btn .nav-icon { font-size: 15px; width: 20px; text-align: center; }
    .soc-nav-btn .nav-badge {
        margin-left: auto; font-size: 9px; font-weight: 700;
        padding: 2px 6px; border-radius: 100px;
        background: var(--neon-red); color: #000;
    }
    </style>
    """, unsafe_allow_html=True)
    
    # User info at top
    initials = "".join([n[0] for n in user_name.split()[:2]]).upper() if user_name else "AN"
    st.sidebar.markdown(f"""
    <div class="soc-user-info">
        <div class="soc-user-avatar">{initials}</div>
        <div class="soc-user-details">
            <div class="soc-user-name">{esc(user_name)}</div>
            <div class="soc-user-role">{esc(user_role)}</div>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Navigation sections
    for category, sections in SIDEBAR_SECTIONS.items():
        st.sidebar.markdown(f'<div class="soc-nav-section-label">{category}</div>', unsafe_allow_html=True)
        for section in sections:
            active = "active" if section == current_section else ""
            icon_map = {
                "Centro de Mando": "🎯", "Gobernanza CSF": "📊",
                "Detección": "🔍", "Hunt Pivots": "🎯", "Threat Hunting": "🕵️",
                "Campañas": "📋", "Operaciones SOC": "⚙️", "Tickets": "🎫",
                "Vigilancia Digital": "🌐", "Defacement": "🛡️",
                "Activos & Respuesta": "💻",
                "Estado de Fuentes": "📡", "Registro de Activos": "📦",
                "Mi Perfil SOC": "👤", "Ajustes": "⚙️",
            }
            icon = icon_map.get(section, "•")
            
            if st.sidebar.button(
                f"{icon}  {section}", 
                key=f"nav_{section}", 
                width="stretch",
                type="primary" if active else "secondary"
            ):
                return section
    
    return current_section


def section_header(title: str, subtitle: str = "", action_html: str = "") -> None:
    """Encabezado de sección estilo SOC."""
    action = f'<div class="soc-panel-action">{action_html}</div>' if action_html else ""
    st.markund(f"""
    <div class="soc-panel-header soc-animate-fade">
        <div class="soc-panel-title">{esc(title)}</div>
        {action}
    </div>
    """, unsafe_allow_html=True)
    if subtitle:
        st.markdown(f'<div style="color: var(--text-muted); font-size: 13px; margin-bottom: 16px;">{esc(subtitle)}</div>', unsafe_allow_html=True)


def kpi_card(label: str, value: str, accent: str = NEON_GREEN, icon: str = "", trend: str = "", trend_type: str = "neutral") -> str:
    """Genera HTML para una tarjeta KPI con estilo neón."""
    glow_map = {
        NEON_GREEN: "rgba(0, 255, 0, 0.3)",
        NEON_RED: "rgba(255, 0, 0, 0.3)",
        NEON_YELLOW: "rgba(255, 215, 0, 0.3)",
        NEON_CYAN: "rgba(0, 255, 255, 0.3)",
    }
    trend_html = ""
    if trend:
        trend_html = f'<div class="soc-kpi-trend {trend_type}">{trend}</div>'
    return f"""
    <div class="soc-kpi-card" style="--accent-color: {accent}; --accent-glow: {glow_map.get(accent, 'rgba(0,255,0,0.3)')}">
        <div class="soc-kpi-icon">{icon}</div>
        <div class="soc-kpi-value">{esc(value)}</div>
        <div class="soc-kpi-label">{esc(label)}</div>
        {trend_html}
    </div>
    """


def render_kpi_grid(cards: list[dict]) -> None:
    """Renderiza una grilla de 4 KPI cards."""
    html = '<div class="soc-kpi-grid">'
    for card in cards:
        html += kpi_card(
            card.get("label", ""), card.get("value", ""),
            card.get("accent", NEON_GREEN), card.get("icon", ""),
            card.get("trend", ""), card.get("trend_type", "neutral")
        )
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


def risk_score_bar(score: float, max_score: float = 100.0, label: str = "SCORE DE RIESGO") -> None:
    """Barra de score de riesgo con estilo neón."""
    score = max(0.0, min(float(score or 0.0), max_score))
    pct = score / max_score * 100
    
    if pct >= 70:
        color = NEON_RED; glow = "rgba(255, 0, 0, 0.5)"
    elif pct >= 40:
        color = NEON_YELLOW; glow = "rgba(255, 215, 0, 0.5)"
    else:
        color = NEON_GREEN; glow = "rgba(0, 255, 0, 0.5)"
    
    st.markdown(f"""
    <div class="soc-risk-bar soc-animate-fade">
        <div class="soc-risk-bar-label">
            <span>{label}</span>
            <span style="color: {color}; font-family: 'JetBrains Mono', monospace;">{score:.1f} / {max_score:.0f}</span>
        </div>
        <div class="soc-risk-bar-track">
            <div class="soc-risk-bar-fill" style="width: {pct:.1f}%; background: linear-gradient(90deg, {color}, {color}); box-shadow: 0 0 10px {glow};"></div>
        </div>
        <div class="soc-risk-bar-markers">
            <span>BAJO</span><span>MEDIO</span><span>ALTO</span><span>CRÍTICO</span>
        </div>
    </div>
    """, unsafe_allow_html=True)


def chip(text: str, kind: str = "info") -> str:
    """Chip/badge estilo neón."""
    kind_map = {
        "critical": "critical", "high": "high", "medium": "medium",
        "low": "low", "ok": "low", "info": "info", "warning": "high",
        "neutral": "neutral"
    }
    cls = kind_map.get(kind, "neutral")
    return f'<span class="soc-chip {cls}">{esc(text)}</span>'


def chip_row(chips: list[tuple[str, str]]) -> str:
    """Fila de chips."""
    return "".join(chip(t, k) for t, k in chips)


def empty_state(title: str, detail: str = "", icon: str = "📭") -> None:
    """Estado vacío estilo SOC."""
    st.markdown(f"""
    <div class="soc-empty-state soc-animate-fade">
        <div class="soc-empty-icon">{icon}</div>
        <div class="soc-empty-title">{esc(title)}</div>
        <div class="soc-empty-desc">{esc(detail)}</div>
    </div>
    """, unsafe_allow_html=True)


def critical_alert_box(count: int, label: str = "INCIDENTES CRÍTICOS ACTIVOS") -> None:
    """Caja roja para incidentes críticos."""
    st.markdown(f"""
    <div class="soc-critical-box soc-animate-fade soc-glow-pulse">
        <div class="soc-critical-count">{count}</div>
        <div class="soc-critical-label">{esc(label)}</div>
    </div>
    """, unsafe_allow_html=True)


def attack_chain(nodes: list[dict]) -> None:
    """
    Renderiza un diagrama de cadena de ataque.
    nodes: lista de dicts con keys: icon, label, count, type (critical/warning/info/ok)
    """
    html = '<div class="soc-attack-chain soc-animate-fade">'
    for i, node in enumerate(nodes):
        html += f"""
        <div class="soc-attack-node {node.get('type', 'info')}">
            <div class="soc-attack-node-icon">{node.get('icon', '🔴')}</div>
            <div class="soc-attack-node-label">{esc(node.get('label', ''))}</div>
            <div class="soc-attack-node-count">{node.get('count', 0)}</div>
        </div>
        """
        if i < len(nodes) - 1:
            html += '<div class="soc-attack-arrow">→</div>'
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


def timeline(events: list[dict]) -> None:
    """
    Renderiza timeline horizontal.
    events: lista de dicts con keys: time, title, description, type (critical/warning/info/ok)
    """
    html = '<div class="soc-timeline soc-animate-fade">'
    for i, event in enumerate(events):
        accent = {
            "critical": NEON_RED, "warning": NEON_YELLOW,
            "info": NEON_CYAN, "ok": NEON_GREEN
        }.get(event.get("type", "info"), NEON_CYAN)
        
        html += f"""
        <div class="soc-timeline-item soc-float" style="--accent-color: {accent}; animation-delay: {i*0.15}s;">
            <div class="soc-timeline-time">{esc(event.get('time', ''))}</div>
            <div class="soc-timeline-content">
                <strong>{esc(event.get('title', ''))}</strong>
                <div style="margin-top: 4px; color: var(--text-muted);">{esc(event.get('description', ''))}</div>
            </div>
        </div>
        """
    html += '</div>'
    st.markdown(html, unsafe_allow_html=True)


def stat_block(label: str, value: str, accent: str = "") -> str:
    """Bloque estadístico simple."""
    color = accent or "var(--text-primary)"
    return f"""
    <div style="padding: 8px 0;">
        <div style="font-size: 10px; font-weight: 600; letter-spacing: 0.08em; color: var(--text-muted); text-transform: uppercase;">{esc(label)}</div>
        <div style="font-size: 24px; font-weight: 800; color: {color}; letter-spacing: -0.02em; font-family: 'JetBrains Mono', monospace;">{esc(value)}</div>
    </div>
    """


# Alias de compatibilidad
SOC_CSS_FEY = SOC_CSS
NAV_ITEMS = ["Mis reportes", "Informes", "Agenda", "Integraciones", "Portal de Estado"]
soc_card = lambda label, value, accent="#2196F3": f"<div style='border-left:4px solid {accent};padding:8px 12px;background:#111;border-radius:6px;margin:4px;'><div style='font-size:.75rem;color:#8FA3BF'>{esc(label)}</div><div style='font-size:1.2rem;font-weight:700;color:#fff'>{esc(value)}</div></div>"
risk_score_bar_html = lambda score, max_score=100.0: None
chip_html = chip
chip_row_html = chip_row
section_title = lambda text: st.markdown(f'<div class="soc-section-title">{esc(text)}</div>', unsafe_allow_html=True)
status_badge_html = lambda label, status: f'<span class="soc-chip {status}">{esc(label)}</span>'
status_badge = lambda label, status: st.markdown(status_badge_html(label, status), unsafe_allow_html=True)
kpi_card_html = kpi_card
render_kpi_row = lambda *args, **kwargs: None
kpi_mini_html = lambda value, label: f"<div style='padding:8px;background:var(--bg-panel);border:1px solid var(--border-primary);border-radius:8px;text-align:center;'><div style='font-size:1.2rem;font-weight:700'>{esc(value)}</div><div style='font-size:10px;color:var(--text-muted);text-transform:uppercase'>{esc(label)}</div></div>"
render_kpi_minis = lambda items: st.markdown(''.join([kpi_mini_html(v, l) for v, l in items]), unsafe_allow_html=True)
delta_html = lambda change_pct, good_when_down=True: ""
chip_column = lambda col, title, items, max_visible=6, empty_msg="Sin elementos": None
section_header = section_header
stat_block = stat_block
mitre_blocks_html = lambda mitre_df: None
severity_styler = lambda df, column="nivel": df.style
_style_severity = lambda value: ""


# ===== CENTRAL TAB NAVIGATION =====
def render_central_tabs(sections: list[dict], active_key: str) -> str | None:
    """
    Renderiza barra de tabs central con animaciones 3D.
    sections: lista de dicts con keys: key, title, icon, badge (opcional)
    active_key: key del tab activo
    Returns: key del tab clickeado o None
    """
    # CSS inline para tabs
    st.markdown("""
    <style>
    .soc-tab-bar { display: flex; gap: 8px; flex-wrap: wrap; justify-content: center; padding: 16px 24px; background: var(--bg-panel); border: 1px solid var(--border-primary); border-radius: var(--radius-lg); margin: 16px 0; box-shadow: var(--shadow-panel); }
    .soc-tab-btn { display: flex; align-items: center; gap: 8px; padding: 12px 20px; border-radius: var(--radius-md); background: var(--bg-secondary); border: 1px solid var(--border-primary); color: var(--text-secondary); font-weight: 600; font-size: 13px; cursor: pointer; transition: all 0.2s cubic-bezier(0.4,0,0.2,1); transform: perspective(500px) rotateX(0deg); transform-style: preserve-3d; }
    .soc-tab-btn:hover { background: var(--bg-panel-hover); color: var(--text-primary); border-color: var(--neon-green); transform: perspective(500px) rotateX(-3deg) translateY(-2px); box-shadow: 0 8px 24px rgba(0,255,0,0.15); }
    .soc-tab-btn.active { background: linear-gradient(135deg, rgba(0,255,0,0.15), rgba(0,255,255,0.1)); color: var(--neon-green); border-color: var(--neon-green); box-shadow: 0 0 20px rgba(0,255,0,0.3); }
    .soc-tab-btn .tab-icon { font-size: 16px; width: 24px; text-align: center; display: inline-flex; align-items: center; justify-content: center; }
    </style>
    """, unsafe_allow_html=True)
    
    html = '<div class="soc-tab-bar">'
    for i, section in enumerate(sections):
        active = "active" if section["key"] == active_key else ""
        badge_html = f'<span class="soc-tab-badge">{section["badge"]}</span>' if section.get("badge") else ""
        html += f'''
        <button class="soc-tab-btn {active}" onclick="window.parent.postMessage({{type: \"streamlit:setComponentValue\", value: \"{section['key']}\"}}, \"*\")" style="background:none;border:none;cursor:pointer;padding:0;margin:0;">
            <span class="tab-icon">{section["icon"]}</span>
            <span>{section["title"]}</span>
            {badge_html}
        </button>'''
    html += '</div>'
    
    # Use st.button approach instead for Streamlit compatibility
    cols = st.columns(len(sections), gap="small")
    clicked = None
    for i, section in enumerate(sections):
        with cols[i]:
            active = section["key"] == active_key
            btn_type = "primary" if active else "secondary"
            if st.button(
                f'{section["icon"]} {section["title"]}',
                key=f'central_tab_{section["key"]}',
                type=btn_type,
                width="stretch"
            ):
                clicked = section["key"]
    return clicked


def render_expandable_section(key: str, title: str, icon: str, content_fn, default_expanded: bool = False) -> None:
    """
    Renderiza sección expandible con animaciones suaves.
    key: clave única para session_state
    title: título de la sección
    icon: emoji/icono
    content_fn: función que renderiza el contenido
    default_expanded: si está expandida por defecto
    """
    # Initialize state
    if f"expanded_{key}" not in st.session_state:
        st.session_state[f"expanded_{key}"] = default_expanded
    
    is_expanded = st.session_state[f"expanded_{key}"]
    
    st.markdown(f"""
    <div class="soc-section-panel soc-panel-3d">
        <div class="soc-section-header" onclick="this.parentElement.querySelector('.soc-section-content').classList.toggle('open'); this.querySelector('.soc-section-chevron').classList.toggle('open');">
            <div class="soc-section-title-row">
                <span class="soc-section-icon">{icon}</span>
                <span class="soc-section-title">{title}</span>
            </div>
            <span class="soc-section-chevron{' open' if is_expanded else ''}">▼</span>
        </div>
        <div class="soc-section-content{' open' if is_expanded else ''}" id="section_{key}">
    """, unsafe_allow_html=True)
    
    # Use a button to toggle since we can't use onclick in Streamlit easily
    col_toggle, col_content = st.columns([1, 20])
    with col_toggle:
        if st.button("▼" if not is_expanded else "▲", key=f"toggle_{key}", width="stretch"):
            st.session_state[f"expanded_{key}"] = not is_expanded
            st.rerun()
    
    if is_expanded:
        content_fn()
    
    st.markdown("""
        </div>
    </div>
    """, unsafe_allow_html=True)


# ===== 3D VISUALIZATIONS =====
def create_mitre_3d_matrix(mitre_summary: dict) -> go.Figure:
    """Crea matriz MITRE 3D interactiva: tácticas en X, técnicas en Y, count en Z."""
    tactics = []
    techniques = []
    counts = []
    colors = []
    
    for tactic, info in MITRE_TECHNIQUES.items():
        tactic_info = mitre_summary.get(tactic, {})
        count = tactic_info.get("count", 0)
        if count > 0:
            for tech in info.get("techniques", []):
                tactics.append(tactic)
                techniques.append(tech)
                counts.append(count)
                colors.append(MITRE_COLORS.get(tactic, NEON_GREEN))
    
    if not tactics:
        fig = go.Figure()
        fig.add_annotation(text="Sin hallazgos MITRE ATT&CK", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(color="#6A6A6A", size=16))
        fig.update_layout(template="plotly_dark", height=400, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        return fig
    
    fig = go.Figure(data=[go.Scatter3d(
        x=tactics,
        y=techniques,
        z=counts,
        mode='markers',
        marker=dict(
            size=[max(10, c*2) for c in counts],
            color=colors,
            opacity=0.8,
            line=dict(width=1, color="#000"),
            colorscale='Viridis',
            showscale=True,
            colorbar=dict(title="Eventos", thickness=15)
        ),
        text=[f"Táctica: {t}<br>Técnica: {tech}<br>Eventos: {c}" for t, tech, c in zip(tactics, techniques, counts)],
        hovertemplate="%{text}<extra></extra>",
    )])
    
    fig.update_layout(
        template="plotly_dark",
        height=450,
        margin=dict(l=0, r=0, t=30, b=0),
        title=dict(text="MATRIZ MITRE ATT&CK 3D", font=dict(color="#FFFFFF", size=16)),
        scene=dict(
            xaxis=dict(title="Táctica", color="#6A6A6A", gridcolor="#1A1A2A"),
            yaxis=dict(title="Técnica", color="#6A6A6A", gridcolor="#1A1A2A"),
            zaxis=dict(title="Eventos", color="#6A6A6A", gridcolor="#1A1A2A"),
            camera=dict(eye=dict(x=1.5, y=1.5, z=1.2)),
            bgcolor="#0A0A0A",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def create_timeline_3d(events: list[dict]) -> go.Figure:
    """Crea timeline 3D en espiral/helice."""
    if not events:
        fig = go.Figure()
        fig.add_annotation(text="Sin eventos en timeline", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(color="#6A6A6A", size=16))
        fig.update_layout(template="plotly_dark", height=400, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        return fig
    
    # Convert to 3D helix coordinates
    n = len(events)
    angles = [i * 4 * 3.14159 / n for i in range(n)]
    radius = [max(1, 5 - i * 0.1) for i in range(n)]
    z = [i * 0.5 for i in range(n)]
    
    x = [r * math.cos(a) for r, a in zip(radius, angles)]
    y = [r * math.sin(a) for r, a in zip(radius, angles)]
    
    colors = []
    for e in events:
        typ = e.get("type", "info")
        if typ == "critical": colors.append(NEON_RED)
        elif typ == "warning": colors.append(NEON_YELLOW)
        elif typ == "info": colors.append(NEON_CYAN)
        else: colors.append(NEON_GREEN)
    
    fig = go.Figure(data=[go.Scatter3d(
        x=x, y=y, z=z,
        mode='markers+lines',
        marker=dict(size=10, color=colors, opacity=0.9, line=dict(width=1, color="#000")),
        line=dict(color="#2A2A2A", width=2, dash="dot"),
        text=[f"{e.get('time', '')}<br>{e.get('title', '')}<br>{e.get('description', '')}" for e in events],
        hovertemplate="%{text}<extra></extra>",
    )])
    
    fig.update_layout(
        template="plotly_dark",
        height=450,
        margin=dict(l=0, r=0, t=30, b=0),
        title=dict(text="TIMELINE 3D - ESPIRAL DE ATAQUE", font=dict(color="#FFFFFF", size=16)),
        scene=dict(
            xaxis=dict(visible=False), yaxis=dict(visible=False), zaxis=dict(title="Tiempo", color="#6A6A6A", gridcolor="#1A1A2A"),
            camera=dict(eye=dict(x=1.5, y=1.5, z=1.2)),
            bgcolor="#0A0A0A",
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
    )
    return fig


def create_attack_chain_3d(nodes: list[dict], edges: list[tuple]) -> go.Figure:
    """Crea cadena de ataque 3D tipo force-directed graph."""
    if not nodes:
        fig = go.Figure()
        fig.add_annotation(text="Sin cadena de ataque", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(color="#6A6A6A", size=16))
        fig.update_layout(template="plotly_dark", height=400, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        return fig
    
    # Generate 3D positions for nodes
    import random
    random.seed(42)
    positions = {node["id"]: (random.uniform(-5,5), random.uniform(-5,5), random.uniform(-2,2)) for node in nodes}
    
    # Node traces
    node_traces = []
    type_colors = {"critical": NEON_RED, "warning": NEON_YELLOW, "info": NEON_CYAN, "ok": NEON_GREEN}
    type_sizes = {"critical": 25, "warning": 20, "info": 18, "ok": 18}
    
    for ntype in ["critical", "warning", "info", "ok"]:
        subset = [n for n in nodes if n["type"] == ntype]
        if not subset: continue
        x_vals = [positions[n["id"]][0] for n in subset]
        y_vals = [positions[n["id"]][1] for n in subset]
        z_vals = [positions[n["id"]][2] for n in subset]
        node_traces.append(go.Scatter3d(
            x=x_vals, y=y_vals, z=z_vals,
            mode="markers+text",
            text=[n["label"] for n in subset],
            textposition="bottom center",
            marker=dict(size=[type_sizes[ntype]]*len(subset), color=type_colors[ntype], opacity=0.9, line=dict(width=2, color="#000")),
            name=ntype.capitalize(),
            hovertemplate="<b>%{text}</b><br>Eventos: %{customdata[0]}<br>Técnicas: %{customdata[1]}<extra></extra>",
            customdata=[[n["count"], ", ".join(n.get("techniques", [])) if n.get("techniques") else "—"] for n in subset],
        ))
    
    # Edge traces
    edge_traces = []
    for src, dst in edges:
        if src in positions and dst in positions:
            x0, y0, z0 = positions[src]
            x1, y1, z1 = positions[dst]
            edge_traces.append(go.Scatter3d(
                x=[x0, x1], y=[y0, y1], z=[z0, z1],
                mode="lines",
                line=dict(color="#2A2A2A", width=2, dash="dot"),
                hoverinfo="none", showlegend=False,
            ))
    
    fig = go.Figure(data=edge_traces + node_traces)
    fig.update_layout(
        template="plotly_dark",
        height=500,
        margin=dict(l=0, r=0, t=30, b=0),
        title=dict(text="CADENA DE ATAQUE 3D", font=dict(color="#FFFFFF", size=16)),
        scene=dict(
            xaxis=dict(visible=False), yaxis=dict(visible=False), zaxis=dict(visible=False),
            camera=dict(eye=dict(x=1.5, y=1.5, z=1.2)),
            bgcolor="#0A0A0A",
            aspectratio=dict(x=1, y=1, z=0.6),
        ),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(x=0.85, y=0.95, bgcolor="rgba(17,17,17,0.9)", bordercolor="#2A2A2A", borderwidth=1, font=dict(color="#B0B0B0", size=10)),
    )
    return fig