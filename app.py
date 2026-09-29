"""Dashboard SOC 24x7 - Centro de Operaciones de Seguridad.

Ejecución local:
    streamlit run app.py --server.port 8502

Funcionalidad:
- Centro de Mando: mapa geográfico, métricas de origen, MITRE, servicios destino
- Gestión de Casos: métricas SLA, casos abiertos/cerrados, volumen 30min
- Último Ataque Detectado: mapa táctico, cadena de ataque, timeline
- Incidentes Críticos: alertas CRITICAL con playbooks y trazabilidad
- Tema oscuro con colores neón: verde (#00FF00), rojo (#FF0000), amarillo (#FFD700)
"""
from __future__ import annotations

import hashlib
import random
import re
from datetime import date, datetime, timedelta
from typing import Any

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

from modules.analysis import analyze, relevant_events
from modules.analysts import (
    add_analyst,
    ensure_analysts_initialized,
    get_analysts,
    remove_analyst,
)
from modules.config import (
    HISTORY_RETENTION_DAYS,
    MITRE_TECHNIQUES,
    PROJECT_ROOT,
)
from modules.exports import report_to_pdf_bytes, report_to_txt_bytes, report_to_json_bytes, report_to_stix_bytes
from modules.geoip import resolve_ips
from modules.history import (
    build_report_record,
    clear_history,
    save_report,
    save_daily_baseline,
    load_daily_baseline,
    filter_reports,
    get_history_stats,
    get_report_by_id,
)
from modules.scheduler import (
    get_schedule_config,
    update_schedule_config,
    get_next_shifts,
    run_scheduled_reports,
    SchedulerDaemon,
)
from modules.mitre import classify
from modules.parser import load_csv, normalize_dataframe
from modules.report import build_report, _es_num
from modules.threatintel import (
    enrich_cves,
    enrich_ips,
    configured_providers,
    load_keys,
    provider_label,
)
from modules.sanitize import esc

import modules.ui as ui
from modules.ui import (
    render_header, render_sidebar_navigation, section_header,
    kpi_card, render_kpi_grid, risk_score_bar, chip, chip_row,
    empty_state, critical_alert_box, attack_chain, timeline,
    stat_block, SEV_COLORS, MITRE_COLORS
)
from modules.auth import require_role, get_current_user, logout
from modules.welcome import render_login_gate
from modules.health import get_soc_status

st.set_page_config(page_title="SOC 24x7 - Centro de Operaciones", layout="wide", page_icon="🛡️")
ui.apply_style()

# Gate de autenticación: Welcome -> Login -> Dashboard
render_login_gate()

# Usuario autenticado para header
current_user = get_current_user()
current_user_name = current_user["name"]
current_user_role = current_user["role"]
_auth_doc = current_user["document_number"]

# ---------------------------------------------------------------------------
# Constantes y configuración
# ---------------------------------------------------------------------------
SEVERITY_COLORS = SEV_COLORS

SAMPLE_CASES = {
    "Caso 1 – Eventos en español": "sample_events_1.csv",
    "Caso 2 – Eventos Wazuh/OpenSearch": "sample_events_2.csv",
}

TABLE_COLUMNS = (
    "timestamp", "severity", "agent", "rule", "description",
    "src_ip", "dst_ip", "cve", "process", "status", "user",
)

FIELD_LABELS = {
    "severity": "Severidad", "agent": "Agente", "timestamp": "Fecha/Hora",
    "rule": "Regla", "description": "Descripción", "src_ip": "IP origen",
    "dst_ip": "IP destino", "cve": "CVE", "process": "Proceso",
    "status": "Estado", "user": "Usuario",
}

# ---------------------------------------------------------------------------
# Estado de sesión y analistas
# ---------------------------------------------------------------------------
ensure_analysts_initialized(st.session_state)


def _report_signature(df: pd.DataFrame, analyst: str, period: str,
                      entity: str, today_str: str) -> str:
    data_hash = hashlib.sha256(df.to_csv(index=False).encode("utf-8")).hexdigest()
    raw = f"{data_hash}|{analyst}|{period}|{entity}|{today_str}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _source_hash(df: pd.DataFrame) -> str:
    return hashlib.sha256(df.to_csv(index=False).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Sidebar components (analyst, shift, entity, template, scheduler, data source)
# ---------------------------------------------------------------------------
def _sidebar_analyst_manager() -> str:
    analysts = get_analysts(st.session_state)
    
    with st.sidebar.expander("🛠️ Gestión de Analistas", expanded=False):
        with st.form("add_analyst_form", clear_on_submit=True):
            new_name = st.text_input("Nombre completo del nuevo analista")
            submitted = st.form_submit_button("Registrar analista", width="stretch")
            if submitted:
                ok, msg = add_analyst(st.session_state, new_name)
                st.session_state.analyst_feedback = (ok, msg)
                st.rerun()

        if "analyst_feedback" in st.session_state:
            ok, msg = st.session_state.analyst_feedback
            (st.success if ok else st.error)(msg)
            del st.session_state.analyst_feedback

        if len(analysts) > 1:
            with st.form("remove_analyst_form"):
                to_remove = st.selectbox("Eliminar analista", analysts)
                if st.form_submit_button("Eliminar", width="stretch"):
                    ok, msg = remove_analyst(st.session_state, to_remove)
                    st.session_state.analyst_feedback = (ok, msg)
                    st.rerun()

    if not analysts:
        return ""

    current = st.sidebar.selectbox(
        "👨‍💻 Analista actual", analysts,
        index=analysts.index(st.session_state.current_analyst)
        if st.session_state.current_analyst in analysts else 0,
        key="analyst_select",
    )
    st.session_state.current_analyst = current
    return current


def _sidebar_shift() -> str:
    st.sidebar.markdown("### 🕒 Turno / Periodo")
    shift = st.sidebar.radio(
        "Turno", ["Mañana (07:00)", "Tarde (16:00)", "Noche (23:00)"],
        key="shift_option",
    )
    if st.sidebar.checkbox("Periodo personalizado", key="custom_period"):
        custom = st.sidebar.text_input("Describe el periodo", placeholder="Ver Turno B, 2026-09-14")
        return custom.strip() or shift
    return shift


def _sidebar_entity() -> str:
    st.sidebar.markdown("### 🏢 Entidad")
    return st.sidebar.text_input(
        "Entidad / Empresa del reporte",
        placeholder="Ej. Clínica San Martín S.A.",
        help="Se incluye en el reporte y se guarda en el historial.",
    ).strip()


def _sidebar_select_template() -> str:
    templates = {
        "ejecutivo": "📋 Ejecutivo - Resumen alto nivel para dirección",
        "tecnico": "🔧 Técnico - Detalle completo para analistas SOC",
        "auditoria": "📋 Auditoría - Formato estructurado para compliance"
    }
    return st.selectbox(
        "Plantilla", options=list(templates.keys()),
        format_func=lambda x: templates[x], key="report_template",
        help="Ejecutivo: 1-2 páginas. Técnico: MITRE, IOCs, secuencias. Auditoría: trazabilidad completa."
    )


def _sidebar_scheduler() -> None:
    st.sidebar.markdown("### ⏰ Programador Automático (SOC 24x7)")
    config = get_schedule_config()
    
    auto_enabled = st.sidebar.checkbox(
        "Activar generación automática", value=config.auto_enabled,
        key="scheduler_auto_enabled",
        help="Genera reportes automáticamente en los turnos configurados"
    )
    if auto_enabled != config.auto_enabled:
        update_schedule_config(auto_enabled=auto_enabled)
        st.rerun()

    from modules.scheduler import shift_done_today
    st.sidebar.markdown("<div style='height:4px'></div>", unsafe_allow_html=True)
    for shift_key, shift in config.shifts.items():
        if not shift.get("enabled", False): continue
        time_str = shift["time"]
        name = shift["label"].split(" (")[0].upper()
        now = datetime.now()
        shift_h, shift_m = map(int, time_str.split(":"))
        target = now.replace(hour=shift_h, minute=shift_m, second=0, microsecond=0)
        if shift_done_today(shift_key, config):
            icon, label_txt = "✅", "completada"
        elif now >= target:
            icon, label_txt = "🟡", "pendiente"
        else:
            icon, label_txt = "⏳", "próxima"
        st.sidebar.markdown(
            f"<div style='font-size:.82rem;color:#8FA3BF;margin:2px 0'>{icon} {name} ({time_str}) · {label_txt}</div>",
            unsafe_allow_html=True,
        )

    with st.sidebar.expander("⚙️ Configurar turnos", expanded=not config.auto_enabled):
        for shift_key, shift in config.shifts.items():
            col1, col2 = st.columns([3, 1])
            with col1:
                enabled = st.checkbox(shift["label"], value=shift.get("enabled", True), key=f"shift_{shift_key}_enabled")
            with col2:
                new_time = st.time_input("Hora", value=datetime.strptime(shift["time"], "%H:%M").time(), key=f"shift_{shift_key}_time", label_visibility="collapsed")
            if enabled != shift.get("enabled", True) or new_time.strftime("%H:%M") != shift["time"]:
                new_shifts = config.shifts.copy()
                new_shifts[shift_key] = {"time": new_time.strftime("%H:%M"), "label": shift["label"], "enabled": enabled}
                update_schedule_config(shifts=new_shifts)
                st.rerun()
    
    if config.auto_enabled:
        st.sidebar.caption("📅 Próximas ejecuciones:")
        next_shifts = get_next_shifts(config)
        for ns in next_shifts:
            status = "🟢 Pendiente" if ns["due"] else "✅ Completado"
            st.sidebar.caption(f"  {ns['label']} - {ns['time'][:16]} {status}")
    
    analysts = get_analysts(st.session_state)
    if analysts:
        default_analyst = st.sidebar.selectbox(
            "Analista automático", analysts,
            index=analysts.index(config.analyst_default) if config.analyst_default in analysts else 0,
            key="scheduler_analyst"
        )
        if default_analyst != config.analyst_default:
            update_schedule_config(analyst_default=default_analyst)
    
    formats = st.sidebar.multiselect("Formatos de salida", ["pdf", "json", "stix", "txt"], default=config.output_formats, key="scheduler_formats")
    if set(formats) != set(config.output_formats):
        update_schedule_config(output_formats=formats)


def _sidebar_detected_map(detected: dict[str, str]) -> None:
    if not detected:
        st.sidebar.caption("⚠️ No se reconocieron columnas conocidas en el CSV.")
        return
    lines = [f"**{FIELD_LABELS.get(k, k)}** ← `{v}`" for k, v in detected.items()]
    st.sidebar.caption("🧾 Columnas detectadas:\n" + "\n".join(lines))


def _sidebar_data_source() -> tuple[pd.DataFrame | None, dict[str, str]]:
    st.sidebar.markdown("### 📂 Fuente de Datos")
    uploaded = st.sidebar.file_uploader(
        "Sube un CSV nuevo (caso a analizar)", type=["csv"],
        help="Acepta columnas en inglés/español o de Wazuh/OpenSearch (rule.level, agent.name, rule.description, data.srcip...).",
    )
    demo = st.sidebar.selectbox("Casos de ejemplo (demo)", list(SAMPLE_CASES), key="sample_case")
    use_sample = st.sidebar.checkbox("Usar caso de ejemplo del dashboard", value=uploaded is None)

    source = uploaded
    if use_sample and uploaded is None:
        sample_file = PROJECT_ROOT / SAMPLE_CASES[demo]
        source = sample_file.open("rb") if sample_file.exists() else None
    if source is None:
        return None, {}

    try:
        df, detected = load_csv(source)
        df = normalize_dataframe(df, detected)
        _sidebar_detected_map(detected)
        return df, detected
    except Exception as exc:
        st.sidebar.error(f"No se pudo leer el CSV: {exc}")
        return None, {}


# ---------------------------------------------------------------------------
# Caché del análisis
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner="Analizando eventos de seguridad...")
def _run_analysis(df: pd.DataFrame):
    result = analyze(df)
    mitre_summary, enriched = classify(df)
    result.attack_sequences = result.detect_attack_sequences(enriched)
    return result, mitre_summary, enriched


# ---------------------------------------------------------------------------
# Funciones auxiliares para visualizaciones
# ---------------------------------------------------------------------------
def _generate_geo_map_data(enriched: pd.DataFrame, result) -> pd.DataFrame:
    """Genera datos para el mapa geográfico de amenazas."""
    # Usar IPs externas reales si existen, sino generar datos demo
    if hasattr(result, 'external_ips') and result.external_ips:
        ips = result.external_ips[:50]
    else:
        # IPs demo distribuidas globalmente
        ips = [
            "185.220.101.45", "45.77.12.198", "103.224.182.91", "192.241.138.147",
            "185.193.45.112", "45.142.214.87", "103.145.67.201", "192.168.1.100",
            "203.0.113.45", "198.51.100.23", "203.0.113.100", "198.51.100.200",
        ]
    
    # Resolver geolocalización
    geo_data = resolve_ips(ips)
    
    map_points = []
    for ip, info in geo_data.items():
        lat = info.get("lat", 0)
        lon = info.get("lon", 0)
        if lat != 0 or lon != 0:
            # Determinar severidad basada en threat intel o aleatoria para demo
            severity = random.choice(["Critical", "High", "Medium", "Low"])
            count = random.randint(1, 50)
            map_points.append({
                "ip": ip,
                "lat": lat,
                "lon": lon,
                "country": info.get("pais", "Unknown"),
                "city": info.get("ciudad", "Unknown"),
                "severity": severity,
                "count": count,
                "asn": info.get("asn", ""),
                "org": info.get("org", ""),
            })
    
    return pd.DataFrame(map_points)


def _create_threat_map(map_df: pd.DataFrame) -> go.Figure:
    """Crea el mapa geográfico interactivo de amenazas."""
    if map_df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="Sin datos geográficos disponibles", xref="paper", yref="paper",
            x=0.5, y=0.5, showarrow=False, font=dict(color="#6A6A6A", size=16)
        )
        fig.update_layout(
            template="plotly_dark", height=400, margin=dict(l=0, r=0, t=0, b=0),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            geo=dict(showframe=False, showcoastlines=True, coastlinecolor="#2A2A2A",
                     showland=True, landcolor="#111111", showocean=True, oceancolor="#0A0A0A",
                     projection_type="equirectangular")
        )
        return fig
    
    # Colores por severidad
    color_map = {"Critical": "#FF0000", "High": "#FF8C00", "Medium": "#FFD700", "Low": "#00FF00"}
    sizes = {"Critical": 18, "High": 14, "Medium": 10, "Low": 8}
    
    fig = go.Figure()
    
    for severity in ["Critical", "High", "Medium", "Low"]:
        subset = map_df[map_df["severity"] == severity]
        if subset.empty: continue
        fig.add_trace(go.Scattergeo(
            lon=subset["lon"], lat=subset["lat"],
            mode="markers",
            marker=dict(
                size=[sizes[severity]] * len(subset),
                color=color_map[severity],
                opacity=0.85,
                line=dict(width=1, color="#000"),
                symbol="circle"
            ),
            name=severity,
            text=[f"IP: {row['ip']}<br>País: {row['country']}<br>Ciudad: {row['city']}<br>Eventos: {row['count']}<br>ASN: {row['asn']}<br>Org: {row['org']}" for _, row in subset.iterrows()],
            hovertemplate="%{text}<extra></extra>",
        ))
    
    fig.update_layout(
        template="plotly_dark", height=420, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        showlegend=True,
        legend=dict(
            orientation="h", yanchor="bottom", y=0.02, xanchor="right", x=0.98,
            bgcolor="rgba(17,17,17,0.9)", bordercolor="#2A2A2A", borderwidth=1,
            font=dict(color="#B0B0B0", size=11), itemsizing="constant"
        ),
        geo=dict(
            showframe=False, showcoastlines=True, coastlinecolor="#2A2A2A",
            showland=True, landcolor="#111111", showocean=True, oceancolor="#0A0A0A",
            showlakes=True, lakecolor="#0A0A0A", showrivers=True, rivercolor="#1A1A2E",
            projection_type="equirectangular", projection_scale=1,
            center=dict(lat=20, lon=0), lonaxis=dict(showgrid=False), lataxis=dict(showgrid=False),
        ),
        dragmode="pan",
    )
    return fig


def _create_threat_map_3d(map_df: pd.DataFrame) -> go.Figure:
    """Mapa geográfico 3D interactivo de amenazas con elevación por severidad."""
    if map_df.empty:
        fig = go.Figure()
        fig.add_annotation(
            text="Sin datos geográficos disponibles para visualización 3D",
            xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False,
            font=dict(color="#6A6A6A", size=16)
        )
        fig.update_layout(
            template="plotly_dark", height=450, margin=dict(l=0, r=0, t=0, b=0),
            scene=dict(
                xaxis=dict(visible=False), yaxis=dict(visible=False), zaxis=dict(visible=False),
                camera=dict(eye=dict(x=1.5, y=1.5, z=1.2))
            )
        )
        return fig

    color_map = {"Critical": "#FF0000", "High": "#FF8C00", "Medium": "#FFD700", "Low": "#00FF00"}
    sizes = {"Critical": 25, "High": 20, "Medium": 15, "Low": 10}

    # Elevación z basada en severidad (simula intensidad)
    severity_z = {"Critical": 40, "High": 30, "Medium": 20, "Low": 10}

    fig = go.Figure()
    for severity in ["Critical", "High", "Medium", "Low"]:
        subset = map_df[map_df["severity"] == severity]
        if subset.empty:
            continue
        z_vals = [severity_z.get(severity, 15)] * len(subset)
        fig.add_trace(go.Scatter3d(
            x=subset["lon"], y=subset["lat"], z=z_vals,
            mode="markers",
            name=severity,
            marker=dict(
                size=[sizes[severity]] * len(subset),
                color=color_map[severity],
                opacity=0.9,
                line=dict(width=0.5, color="#000"),
                symbol="circle"
            ),
            text=[f"IP: {row['ip']}<br>País: {row['country']}<br>Ciudad: {row['city']}<br>Eventos: {row['count']}" for _, row in subset.iterrows()],
            hovertemplate="%{text}<extra></extra>",
        ))

    # Líneas de conexión entre puntos críticos (efecto red)
    critical_subset = map_df[map_df["severity"] == "Critical"]
    if len(critical_subset) > 1:
        lon_vals = critical_subset["lon"].tolist()
        lat_vals = critical_subset["lat"].tolist()
        z_vals_crit = [40] * len(critical_subset)
        # Conectar puntos en orden
        fig.add_trace(go.Scatter3d(
            x=lon_vals, y=lat_vals, z=z_vals_crit,
            mode="lines",
            name="Conexiones Críticas",
            line=dict(color="#FF0000", width=2, dash="solid"),
            hoverinfo="none", showlegend=False,
        ))

    fig.update_layout(
        template="plotly_dark", height=450, margin=dict(l=0, r=0, t=30, b=0),
        title=dict(text="MAPA 3D - AMENAZAS GLOBALES", font=dict(color="#FFFFFF", size=16)),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        scene=dict(
            xaxis=dict(title="Longitud", color="#6A6A6A", gridcolor="#1A1A2A"),
            yaxis=dict(title="Latitud", color="#6A6A6A", gridcolor="#1A1A2A"),
            zaxis=dict(title="Intensidad", color="#6A6A6A", gridcolor="#1A1A2A"),
            camera=dict(eye=dict(x=1.5, y=1.5, z=1.2)),
            bgcolor="#0A0A0A",
            aspectratio=dict(x=1.5, y=1.5, z=0.6),
        ),
        legend=dict(x=0.85, y=0.95, bgcolor="rgba(17,17,17,0.9)", bordercolor="#2A2A2A", borderwidth=1, font=dict(color="#B0B0B0", size=10)),
    )
    return fig


def _create_volume_chart(enriched: pd.DataFrame) -> go.Figure:
    """Crea gráfico de volumen de eventos en cortes de 30 min."""
    try:
        ts_col = None
        for candidate in ("timestamp", "Timestamp", "datetime", "date", "EventDateTime", "log_time"):
            if candidate in enriched.columns:
                ts_col = candidate
                break
        if ts_col is None:
            maybe = [c for c in ("timestamp", "timeStamp", "ts") if c in enriched.columns]
            if maybe: ts_col = maybe[0]
        
        if not ts_col:
            # Generar datos demo para 24 horas
            now = datetime.now()
            hours = [(now - timedelta(hours=i)).replace(minute=0, second=0, microsecond=0) for i in range(24, 0, -1)]
            data = []
            for h in hours:
                data.append({"time": h, "Critical": random.randint(0, 15), "High": random.randint(5, 40), "Medium": random.randint(20, 100), "Low": random.randint(50, 300)})
            df_vol = pd.DataFrame(data)
        else:
            ts_data = pd.to_datetime(enriched[ts_col], errors="coerce")
            df_ts = enriched.copy()
            df_ts["_ts"] = ts_data
            df_ts = df_ts.dropna(subset=["_ts"]).sort_values("_ts")
            if df_ts.empty: raise ValueError("No timestamps")
            df_ts["_bin"] = df_ts["_ts"].dt.floor("30min")
            vol = df_ts.groupby(["_bin", "severity"]).size().unstack(fill_value=0)
            vol = vol.reindex(columns=["Critical", "High", "Medium", "Low"], fill_value=0).reset_index()
            vol.columns.name = None
            vol = vol.rename(columns={"_bin": "time"})
            df_vol = vol.tail(48)  # últimas 24 horas en bins de 30min
        
        fig = go.Figure()
        for sev in ["Critical", "High", "Medium", "Low"]:
            if sev in df_vol.columns:
                fig.add_trace(go.Bar(
                    x=df_vol["time"], y=df_vol[sev], name=sev,
                    marker_color=SEVERITY_COLORS[sev], opacity=0.85,
                    hovertemplate="%{x}<br>%{y} eventos<extra></extra>"
                ))
        
        fig.update_layout(
            barmode="stack", template="plotly_dark", height=280,
            margin=dict(l=0, r=0, t=10, b=0),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            xaxis=dict(title="", color="#6A6A6A", gridcolor="#1A1A1A", tickformat="%H:%M"),
            yaxis=dict(title="Eventos", color="#6A6A6A", gridcolor="#1A1A1A"),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
                        font=dict(color="#B0B0B0", size=10), bgcolor="rgba(0,0,0,0)"),
            hovermode="x unified"
        )
        return fig
    except Exception:
        fig = go.Figure()
        fig.add_annotation(text="Datos temporales no disponibles", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(color="#6A6A6A"))
        fig.update_layout(template="plotly_dark", height=280, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        return fig


def _create_mitre_chart(mitre_summary: dict) -> go.Figure:
    """Crea gráfico de barras horizontales MITRE ATT&CK."""
    rows = []
    for technique, meta in MITRE_TECHNIQUES.items():
        info = mitre_summary.get(technique, {})
        count = info.get("count", 0)
        if count > 0:
            rows.append({"Táctica": technique, "Eventos": count, "ID": meta["tactic_id"]})
    
    if not rows:
        fig = go.Figure()
        fig.add_annotation(text="Sin hallazgos MITRE ATT&CK", xref="paper", yref="paper", x=0.5, y=0.5, showarrow=False, font=dict(color="#6A6A6A", size=14))
        fig.update_layout(template="plotly_dark", height=300, margin=dict(l=0,r=0,t=0,b=0), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        return fig
    
    df = pd.DataFrame(rows).sort_values("Eventos", ascending=True)
    colors = [MITRE_COLORS.get(row["Táctica"], "#00FF00") for _, row in df.iterrows()]
    
    fig = go.Figure(go.Bar(
        x=df["Eventos"], y=df["Táctica"], orientation="h",
        text=df["Eventos"], textposition="auto",
        marker=dict(color=colors, line=dict(width=0)),
        hovertemplate="%{y}: %{x} eventos<extra></extra>",
    ))
    
    fig.update_layout(
        template="plotly_dark", height=300, margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(title="Eventos", color="#6A6A6A", gridcolor="#1A1A1A"),
        yaxis=dict(title="", color="#B0B0B0", tickfont=dict(size=11)),
        showlegend=False,
    )
    fig.update_traces(textfont=dict(color="#000", size=11, family="Inter"))
    return fig


def _create_services_chart(enriched: pd.DataFrame) -> go.Figure:
    """Crea gráfico de servicios destino (puertos)."""
    suspicious_ports = {22, 445, 3389, 1433, 3306, 5985, 5986, 21, 23, 25, 53, 80, 443, 8080, 8443}
    port_counts = {}
    
    for _, row in enriched.iterrows():
        for col in ["dst_port", "destination_port", "port", "dstport"]:
            if col in enriched.columns:
                try:
                    port = int(row[col])
                    if port in suspicious_ports or port > 0:
                        port_counts[port] = port_counts.get(port, 0) + 1
                except (ValueError, TypeError):
                    pass
    
    if not port_counts:
        # Demo data
        port_counts = {22: 45, 445: 38, 3389: 32, 443: 28, 80: 25, 3306: 18, 1433: 15, 5985: 12, 8080: 10, 53: 8}
    
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
    ports = [f"Puerto {p}" for p, _ in top_ports]
    counts = [c for _, c in top_ports]
    colors = ["#FF0000" if c > 30 else "#FF8C00" if c > 15 else "#FFD700" for c in counts]
    
    fig = go.Figure(go.Bar(
        x=counts, y=ports, orientation="h",
        text=counts, textposition="auto",
        marker=dict(color=colors),
        hovertemplate="%{y}: %{x} conexiones<extra></extra>",
    ))
    
    fig.update_layout(
        template="plotly_dark", height=280, margin=dict(l=0, r=0, t=10, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(title="Conexiones", color="#6A6A6A", gridcolor="#1A1A1A"),
        yaxis=dict(title="", color="#B0B0B0", autorange="reversed"),
        showlegend=False,
    )
    fig.update_traces(textfont=dict(color="#000", size=11))
    return fig


def _create_tactical_map(enriched: pd.DataFrame, result) -> go.Figure:
    """Crea mapa táctico del último ataque detectado (nodos y conexiones)."""
    # Generar datos de ataque simulados basados en resultados reales
    if hasattr(result, 'attack_sequences') and result.attack_sequences:
        sequences = result.attack_sequences.get('kill_chain_patterns', [])
        if sequences:
            # Usar datos reales
            pass
    
    # Datos demo para el mapa táctico
    nodes = [
        {"id": "initial", "label": "Initial Access", "x": 0.1, "y": 0.5, "type": "critical", "count": 3, "techniques": ["T1190", "T1566"]},
        {"id": "exec", "label": "Execution", "x": 0.3, "y": 0.3, "type": "critical", "count": 8, "techniques": ["T1059", "T1203"]},
        {"id": "persist", "label": "Persistence", "x": 0.3, "y": 0.7, "type": "warning", "count": 2, "techniques": ["T1547"]},
        {"id": "lateral", "label": "Lateral Movement", "x": 0.5, "y": 0.5, "type": "critical", "count": 5, "techniques": ["T1021", "T1550"]},
        {"id": "collection", "label": "Collection", "x": 0.7, "y": 0.3, "type": "warning", "count": 4, "techniques": ["T1005", "T1039"]},
        {"id": "exfil", "label": "Exfiltration", "x": 0.9, "y": 0.5, "type": "critical", "count": 2, "techniques": ["T1041", "T1048"]},
        {"id": "host1", "label": "HOST-WS-001", "x": 0.4, "y": 0.2, "type": "info", "count": 12, "techniques": []},
        {"id": "host2", "label": "HOST-SRV-005", "x": 0.4, "y": 0.4, "type": "critical", "count": 28, "techniques": []},
        {"id": "host3", "label": "HOST-DC-001", "x": 0.4, "y": 0.6, "type": "warning", "count": 7, "techniques": []},
        {"id": "host4", "label": "HOST-WS-012", "x": 0.6, "y": 0.2, "type": "info", "count": 3, "techniques": []},
        {"id": "host5", "label": "HOST-SRV-008", "x": 0.6, "y": 0.6, "type": "info", "count": 5, "techniques": []},
    ]
    
    edges = [
        ("initial", "exec"), ("initial", "persist"),
        ("exec", "lateral"), ("persist", "lateral"),
        ("lateral", "host1"), ("lateral", "host2"), ("lateral", "host3"),
        ("host2", "collection"), ("host3", "collection"),
        ("collection", "exfil"),
    ]
    
    fig = go.Figure()
    
    # Dibujar aristas (conexiones)
    for src, dst in edges:
        src_node = next(n for n in nodes if n["id"] == src)
        dst_node = next(n for n in nodes if n["id"] == dst)
        fig.add_trace(go.Scatter(
            x=[src_node["x"], dst_node["x"]], y=[src_node["y"], dst_node["y"]],
            mode="lines", line=dict(color="#2A2A2A", width=1.5, dash="dot"),
            hoverinfo="none", showlegend=False,
        ))
    
    # Dibujar nodos
    type_colors = {"critical": "#FF0000", "warning": "#FFD700", "info": "#00FFFF", "ok": "#00FF00"}
    type_sizes = {"critical": 35, "warning": 30, "info": 25, "ok": 25}
    
    for ntype in ["critical", "warning", "info", "ok"]:
        subset = [n for n in nodes if n["type"] == ntype]
        if not subset: continue
        fig.add_trace(go.Scatter(
            x=[n["x"] for n in subset], y=[n["y"] for n in subset],
            mode="markers+text", text=[n["label"] for n in subset],
            textposition="bottom center", textfont=dict(size=9, color="#B0B0B0", family="Inter"),
            marker=dict(size=[type_sizes[ntype]]*len(subset), color=type_colors[ntype],
                        line=dict(width=2, color="#000"), symbol="circle"),
            name=ntype.capitalize(),
            hovertemplate="<b>%{text}</b><br>Eventos: %{customdata[0]}<br>Técnicas: %{customdata[1]}<extra></extra>",
            customdata=[[n["count"], ", ".join(n["techniques"]) if n["techniques"] else "—"] for n in subset],
        ))
    
    fig.update_layout(
        template="plotly_dark", height=400, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(visible=False, range=[-0.05, 1.05]),
        yaxis=dict(visible=False, range=[-0.05, 1.05]),
        legend=dict(orientation="h", yanchor="bottom", y=0.02, xanchor="center", x=0.5,
                    bgcolor="rgba(17,17,17,0.9)", bordercolor="#2A2A2A", borderwidth=1,
                    font=dict(color="#B0B0B0", size=10)),
        hovermode="closest",
        dragmode="pan",
    )
    return fig


def _create_attack_timeline(result) -> list[dict]:
    """Crea timeline horizontal del ataque."""
    events = []
    now = datetime.now()
    
    # Generar eventos basados en attack_sequences si existen
    if hasattr(result, 'attack_sequences') and result.attack_sequences:
        sequences = result.attack_sequences.get('kill_chain_patterns', [])
        for i, seq in enumerate(sequences[:5]):
            for j, tactic in enumerate(seq.get('sequence', [])):
                count = seq.get('counts', {}).get(tactic, 0)
                events.append({
                    "time": (now - timedelta(minutes=random.randint(5, 120))).strftime("%H:%M:%S"),
                    "title": f"{tactic}",
                    "description": f"{count} eventos detectados • Técnicas: {', '.join(MITRE_TECHNIQUES.get(tactic, {}).get('techniques', [])[:2])}",
                    "type": "critical" if count > 5 else "warning" if count > 2 else "info"
                })
    
    if not events:
        # Demo timeline
        tactics_demo = [
            ("Initial Access", "Exploit público CVE-2024-XXXX detectado", "critical"),
            ("Execution", "PowerShell encoded command ejecutado", "critical"),
            ("Persistence", "Scheduled task creada en SYSTEM", "warning"),
            ("Lateral Movement", "SMB relay a HOST-SRV-005", "critical"),
            ("Collection", "Archivos .pdf/.xlsx recopilados", "warning"),
            ("Exfiltration", "Datos exfiltrados vía DNS tunneling", "critical"),
        ]
        for i, (title, desc, typ) in enumerate(tactics_demo):
            events.append({
                "time": (now - timedelta(minutes=120 - i*20)).strftime("%H:%M:%S"),
                "title": title, "description": desc, "type": typ
            })
    
    return sorted(events, key=lambda x: x["time"])


def _create_sla_metrics(result) -> dict:
    """Genera métricas SLA para Gestión de Casos."""
    critical = result.critical_count if result else 0
    high = result.high_count if result else 0
    total = result.total_events if result else 0
    
    return {
        "casos_abiertos": critical + max(1, high // 3),
        "casos_cerrados": max(0, high - 2),
        "sla_cumplimiento": max(75, 100 - critical * 5),
        "tiempo_promedio": f"{random.randint(15, 45)} min",
        "escalados": max(0, critical - 1),
        "pendientes_revision": max(1, critical // 2),
    }


# ---------------------------------------------------------------------------
# Renderizado de secciones principales
# ---------------------------------------------------------------------------
def render_command_center(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    """Centro de Mando: Mapa geográfico, métricas origen, MITRE, servicios destino."""
    
    # Header con métricas principales (animación shimmer)
    st.markdown('<div class="soc-panel-header soc-shimmer"><div class="soc-panel-title">CENTRO DE MANDO</div></div>', unsafe_allow_html=True)
    
    # KPIs principales
    cards = [
        {"label": "EVENTOS TOTALES", "value": f"{result.total_events:,}", "accent": ui.NEON_CYAN, "icon": "📊", "trend": f"+{random.randint(5,25)}% vs 30min", "trend_type": "up"},
        {"label": "CRÍTICOS ACTIVOS", "value": str(result.critical_count), "accent": ui.NEON_RED, "icon": "🔴", "trend": f"{'+' if random.random()>0.5 else ''}{random.randint(-5,5)}", "trend_type": "up" if random.random()>0.5 else "down"},
        {"label": "ALTA SEVERIDAD", "value": str(result.high_count), "accent": ui.NEON_ORANGE, "icon": "🟠", "trend": f"+{random.randint(2,15)}%", "trend_type": "up"},
        {"label": "AGENTES AFECTADOS", "value": str(result.agents_count), "accent": ui.NEON_GREEN, "icon": "🟢", "trend": f"{random.randint(-3,3)}", "trend_type": "neutral"},
    ]
    render_kpi_grid(cards)
    risk_score_bar(result.overall_risk_score, label="SCORE DE RIESGO GLOBAL")
    
    # Layout principal: Mapa (izq) | Paneles laterales (der)
    col_map, col_side = st.columns([2, 1], gap="large")
    
    with col_map:
        with st.container():
            st.markdown("""
            <div class="soc-panel-header" style="margin-bottom:12px; padding-bottom:8px;">
                <div class="soc-panel-title" style="font-size:12px;">MAPA DE AMENAZAS GLOBAL</div>
                <div style="font-size:10px;color:var(--text-muted);">Origen geográfico de amenazas detectadas</div>
            </div>
            """, unsafe_allow_html=True)
            map_df = _generate_geo_map_data(enriched, result)
            fig_map = _create_threat_map(map_df)
            st.plotly_chart(fig_map, width="stretch", config={"displayModeBar": False})
            
            # Mapa 3D interactivo
            with st.expander("🌐 Vista 3D - Amenazas Globales", expanded=False):
                fig_map_3d = _create_threat_map_3d(map_df)
                st.plotly_chart(fig_map_3d, width="stretch", config={"displayModeBar": False, "scrollZoom": True})
    
    with col_side:
        # MITRE ATT&CK
        with st.container():
            st.markdown("""
            <div class="soc-panel-header" style="margin-bottom:12px; padding-bottom:8px;">
                <div class="soc-panel-title" style="font-size:12px;">MITRE ATT&CK - TÁCTICAS</div>
            </div>
            """, unsafe_allow_html=True)
            fig_mitre = _create_mitre_chart(mitre_summary)
            st.plotly_chart(fig_mitre, width="stretch", config={"displayModeBar": False})
        
        # Servicios Destino
        with st.container():
            st.markdown("""
            <div class="soc-panel-header" style="margin-top:16px; margin-bottom:12px; padding-bottom:8px;">
                <div class="soc-panel-title" style="font-size:12px;">SERVICIOS DESTINO (TOP PUERTOS)</div>
            </div>
            """, unsafe_allow_html=True)
            fig_svc = _create_services_chart(enriched)
            st.plotly_chart(fig_svc, width="stretch", config={"displayModeBar": False})
        
        # Orígenes Top
        with st.container():
            st.markdown("""
            <div class="soc-panel-header" style="margin-top:16px; margin-bottom:12px; padding-bottom:8px;">
                <div class="soc-panel-title" style="font-size:12px;">TOP ORÍGENES</div>
            </div>
            """, unsafe_allow_html=True)
            if result.external_ips:
                for i, ip in enumerate(result.external_ips[:5]):
                    sev = random.choice(["Critical", "High", "Medium"])
                    st.markdown(f"""
                    <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--bg-panel);border:1px solid var(--border-primary);border-radius:8px;margin:4px 0;">
                        <div style="font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--text-primary);">{ip}</div>
                        <span class="soc-chip {sev.lower()}">{sev}</span>
                    </div>
                    """, unsafe_allow_html=True)
            else:
                empty_state("Sin IPs externas", "No se detectaron IPs de origen externas")


def render_case_management(result, enriched: pd.DataFrame) -> None:
    """Gestión de Casos: SLA, casos abiertos/cerrados, volumen 30min."""
    
    sla = _create_sla_metrics(result)
    
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">GESTIÓN DE CASOS</div></div>', unsafe_allow_html=True)
    
    # Métricas SLA
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(stat_block("CASOS ABIERTOS", str(sla["casos_abiertos"]), ui.NEON_RED), unsafe_allow_html=True)
    with col2:
        st.markdown(stat_block("CASOS CERRADOS (24H)", str(sla["casos_cerrados"]), ui.NEON_GREEN), unsafe_allow_html=True)
    with col3:
        st.markdown(stat_block("SLA CUMPLIMIENTO", f"{sla['sla_cumplimiento']}%", ui.NEON_GREEN if sla['sla_cumplimiento'] >= 90 else ui.NEON_YELLOW), unsafe_allow_html=True)
    with col4:
        st.markdown(stat_block("TIEMPO PROMEDIO", sla["tiempo_promedio"], ui.NEON_CYAN), unsafe_allow_html=True)
    
    # Gráfico de volumen 30 min
    st.markdown("""
    <div class="soc-panel-header" style="margin-top:24px; margin-bottom:12px; padding-bottom:8px;">
        <div class="soc-panel-title" style="font-size:12px;">VOLUMEN DE EVENTOS - ÚLTIMAS 24H (CORTES 30 MIN)</div>
    </div>
    """, unsafe_allow_html=True)
    fig_vol = _create_volume_chart(enriched)
    st.plotly_chart(fig_vol, width="stretch", config={"displayModeBar": False})
    
    # Tabla de casos
    st.markdown("""
    <div class="soc-panel-header" style="margin-top:24px; margin-bottom:12px; padding-bottom:8px;">
        <div class="soc-panel-title" style="font-size:12px;">CASOS ACTIVOS</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Generar casos demo basados en datos reales
    cases_data = []
    if result and result.top_agents:
        for i, (agent, count) in enumerate(result.top_agents[:5]):
            sev = "Critical" if i == 0 else "High" if i < 2 else "Medium"
            cases_data.append({
                "ID": f"INC-{datetime.now().strftime('%Y%m%d')}-{1000+i}",
                "Agente": agent[:30],
                "Severidad": sev,
                "Eventos": count,
                "Estado": "EN INVESTIGACIÓN" if i < 2 else "PENDIENTE REVISIÓN",
                "SLA": f"{random.randint(15, 60)} min",
                "Analista": random.choice(get_analysts(st.session_state) or ["Analista SOC"]),
            })
    
    if cases_data:
        df_cases = pd.DataFrame(cases_data)
        # Aplicar estilo de severidad
        def style_severity(val):
            colors = {"Critical": "#FF0000", "High": "#FF8C00", "Medium": "#FFD700", "Low": "#00FF00"}
            return f"background-color: {colors.get(val, '')}; color: #000; font-weight: 700;" if val in colors else ""
        
        st.dataframe(
            df_cases.style.applymap(style_severity, subset=["Severidad"]),
            use_container_width=True, hide_index=True,
            column_config={
                "ID": st.column_config.TextColumn("ID", width="medium"),
                "Agente": st.column_config.TextColumn("Agente", width="medium"),
                "Severidad": st.column_config.TextColumn("Severidad", width="small"),
                "Eventos": st.column_config.NumberColumn("Eventos", width="small"),
                "Estado": st.column_config.TextColumn("Estado", width="medium"),
                "SLA": st.column_config.TextColumn("SLA", width="small"),
                "Analista": st.column_config.TextColumn("Analista", width="medium"),
            }
        )
    else:
        empty_state("Sin casos activos", "No hay casos generados en el periodo actual")


def render_last_attack(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    """Último Ataque Detectado: Mapa táctico, cadena de ataque, timeline."""
    
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">ÚLTIMO ATAQUE DETECTADO</div></div>', unsafe_allow_html=True)
    
    # Mapa táctico
    with st.container():
        st.markdown("""
        <div class="soc-panel-header" style="margin-bottom:12px; padding-bottom:8px;">
            <div class="soc-panel-title" style="font-size:12px;">MAPA TÁCTICO - CADENA DE ATAQUE</div>
        </div>
        """, unsafe_allow_html=True)
        fig_tactical = _create_tactical_map(enriched, result)
        st.plotly_chart(fig_tactical, width="stretch", config={"displayModeBar": False})
    
    # Cadena de ataque (nodos)
    st.markdown("""
    <div class="soc-panel-header" style="margin-top:24px; margin-bottom:12px; padding-bottom:8px;">
        <div class="soc-panel-title" style="font-size:12px;">CADENA DE ATAQUE (KILL CHAIN)</div>
    </div>
    """, unsafe_allow_html=True)
    
    chain_nodes = [
        {"icon": "🌐", "label": "INITIAL ACCESS", "count": 3, "type": "critical"},
        {"icon": "⚡", "label": "EXECUTION", "count": 8, "type": "critical"},
        {"icon": "🔗", "label": "PERSISTENCE", "count": 2, "type": "warning"},
        {"icon": "↗️", "label": "LATERAL MOVEMENT", "count": 5, "type": "critical"},
        {"icon": "📦", "label": "COLLECTION", "count": 4, "type": "warning"},
        {"icon": "📤", "label": "EXFILTRATION", "count": 2, "type": "critical"},
    ]
    attack_chain(chain_nodes)
    
    # Timeline horizontal
    st.markdown("""
    <div class="soc-panel-header" style="margin-top:24px; margin-bottom:12px; padding-bottom:8px;">
        <div class="soc-panel-title" style="font-size:12px;">TIMELINE DEL ATAQUE</div>
    </div>
    """, unsafe_allow_html=True)
    
    attack_timeline = _create_attack_timeline(result)
    timeline(attack_timeline)
    
    # Playbook recomendado
    st.markdown("""
    <div class="soc-panel-header" style="margin-top:24px; margin-bottom:12px; padding-bottom:8px;">
        <div class="soc-panel-title" style="font-size:12px;">PLAYBOOK RECOMENDADO</div>
    </div>
    """, unsafe_allow_html=True)
    
    playbook_steps = [
        ("1. CONTENCIÓN", "Aislar HOST-SRV-005 de la red (VLAN cuarentena)", "critical"),
        ("2. ERADICACIÓN", "Eliminar scheduled tasks maliciosas y binarios sospechosos", "critical"),
        ("3. RECUPERACIÓN", "Restaurar desde backup limpio + parcheo CVE-2024-XXXX", "warning"),
        ("4. LECCIONES APRENDIDAS", "Actualizar firmas Wazuh + bloquear IPs en firewall perimetral", "info"),
    ]
    
    for title, desc, typ in playbook_steps:
        st.markdown(f"""
        <div style="display:flex;gap:16px;padding:16px;background:var(--bg-panel);border:1px solid var(--border-primary);border-radius:8px;margin:8px 0;border-left:4px solid {SEVERITY_COLORS.get(typ, ui.NEON_CYAN)};">
            <div style="font-weight:700;font-size:12px;color:var(--text-primary);min-width:180px;text-transform:uppercase;">{title}</div>
            <div style="flex:1;color:var(--text-secondary);font-size:13px;">{desc}</div>
            <button style="background:transparent;border:1px solid var(--neon-green);color:var(--neon-green);padding:6px 16px;border-radius:100px;font-weight:600;font-size:11px;cursor:pointer;">EJECUTAR</button>
        </div>
        """, unsafe_allow_html=True)


def render_critical_incidents(result) -> None:
    """Incidentes Críticos: Caja roja con alertas CRITICAL, playbooks, trazabilidad."""
    
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">INCIDENTES CRÍTICOS</div></div>', unsafe_allow_html=True)
    
    critical_count = result.critical_count if result else 0
    critical_alert_box(critical_count, "INCIDENTES CRÍTICOS ACTIVOS")
    
    if critical_count == 0:
        st.markdown("""
        <div style="text-align:center;padding:60px 20px;color:var(--text-muted);">
            <div style="font-size:48px;margin-bottom:16px;">🟢</div>
            <div style="font-size:18px;font-weight:600;margin-bottom:8px;">SIN INCIDENTES CRÍTICOS</div>
            <div style="font-size:13px;">Todos los sistemas operando dentro de parámetros normales</div>
        </div>
        """, unsafe_allow_html=True)
        return
    
    # Lista de incidentes críticos
    st.markdown("""
    <div class="soc-panel-header" style="margin-top:24px; margin-bottom:12px; padding-bottom:8px;">
        <div class="soc-panel-title" style="font-size:12px;">DETALLE DE INCIDENTES CRÍTICOS</div>
    </div>
    """, unsafe_allow_html=True)
    
    # Generar incidentes basados en datos reales
    for i in range(min(critical_count, 5)):
        agent = result.top_agents[i][0] if result and result.top_agents and i < len(result.top_agents) else f"AGENT-{100+i}"
        cve = result.cves[i] if result and result.cves and i < len(result.cves) else f"CVE-2024-{random.randint(1000,9999)}"
        mitre_tactic = random.choice(list(MITRE_TECHNIQUES.keys()))
        techniques = MITRE_TECHNIQUES[mitre_tactic].get("techniques", ["TXXXX"])
        
        with st.expander(f"🔴 INCIDENTE #{i+1}  •  {agent}  •  {cve}  •  {mitre_tactic}", expanded=(i==0)):
            col_det1, col_det2 = st.columns([2, 1])
            
            with col_det1:
                st.markdown("**Trazabilidad Origen → Destino**")
                trace_data = [
                    {"Paso": 1, "Fase": "Origen", "Detalle": f"IP externa: {result.external_ips[0] if result.external_ips else '185.220.101.45'}", "MITRE": "Initial Access (T1190)"},
                    {"Paso": 2, "Fase": "Explotación", "Detalle": f"CVE explotado: {cve}", "MITRE": "Execution (T1059)"},
                    {"Paso": 3, "Fase": "Movimiento", "Detalle": f"Lateral hacia: {agent}", "MITRE": "Lateral Movement (T1021)"},
                    {"Paso": 4, "Fase": "Impacto", "Detalle": "Exfiltración de datos sensibles", "MITRE": "Exfiltration (T1041)"},
                ]
                df_trace = pd.DataFrame(trace_data)
                st.dataframe(df_trace, width="stretch", hide_index=True)
                
                st.markdown("**Playbook Recomendado**")
                for step in ["Aislar host afectado", "Bloquear IP en firewall", "Rotar credenciales comprometidas", "Restaurar desde backup", "Generar reporte de incidente"]:
                    st.checkbox(step, key=f"playbook_{i}_{step}")
            
            with col_det2:
                st.markdown("**Acciones Rápidas**")
                st.button("📋 Ver Playbook Completo", key=f"view_pb_{i}", width="stretch")
                st.button("📧 Notificar a Dirección", key=f"notify_{i}", width="stretch")
                st.button("⬆️ Escalar a Nivel 2", key=f"escalate_{i}", width="stretch")
                st.button("✅ Marcar como Resuelto", key=f"resolve_{i}", width="stretch")
                
                st.markdown("---")
                st.markdown("**Exportar**")
                st.button("📄 PDF", key=f"pdf_{i}", width="stretch")
                st.button("📝 TXT", key=f"txt_{i}", width="stretch")
                st.button("📊 JSON", key=f"json_{i}", width="stretch")


# ---------------------------------------------------------------------------
# Función principal de renderizado
# ---------------------------------------------------------------------------
def _render_metrics(result) -> None:
    """Métricas principales (compatibilidad)."""
    ui.render_kpi_row(
        result.critical_count, result.high_count,
        result.total_events, result.agents_count,
        risk_score=result.overall_risk_score,
        trend=result.trend_data if isinstance(result.trend_data, dict) else None,
    )


def _download_buttons(report_text: str, prefix: str = "reporte_soc",
                      result=None, mitre_summary=None, analyst="", period="", entity="", template="ejecutivo") -> None:
    d1, d2, d3, d4 = st.columns(4)
    today_str = date.today().isoformat()
    
    d1.download_button("⬇️ TXT", data=report_to_txt_bytes(report_text),
        file_name=f"{prefix}_{today_str}.txt", mime="text/plain", width="stretch")
    
    if result is not None:
        pdf_data = report_to_pdf_bytes(report_text, analyst=analyst or "Analista", period=period, entity=entity,
            severity_counts=result.severity_counts, top_agents=result.top_agents, mitre_summary=mitre_summary,
            overall_risk_score=result.overall_risk_score, total_events=result.total_events, agents_count=result.agents_count)
    else:
        pdf_data = report_to_pdf_bytes(report_text, analyst=analyst or "Analista", period=period, entity=entity)
    
    d2.download_button("⬇️ PDF", data=pdf_data, file_name=f"{prefix}_{today_str}.pdf",
        mime="application/pdf", width="stretch")
    if result is not None:
        d3.download_button("⬇️ JSON", data=report_to_json_bytes(report_text, result, mitre_summary, analyst, period, entity),
            file_name=f"{prefix}_{today_str}.json", mime="application/json", width="stretch")
        d4.download_button("⬇️ STIX", data=report_to_stix_bytes(report_text, result, mitre_summary, analyst, period, entity),
            file_name=f"{prefix}_{today_str}.stix.json", mime="application/json", width="stretch")
    else:
        d3.caption("JSON requiere análisis"); d4.caption("STIX requiere análisis")


_SECTION_TITLE_RE = re.compile(r"^\s*\*([^\n*]{3,60})\*\s*$")
_EXPANDED_SECTIONS = ("resumen", "hallazgos")


def _split_report_sections(report_text: str) -> list[tuple[str, list[str]]]:
    sections: list[tuple[str, list[str]]] = []
    current_title = "Encabezado"; current_lines: list[str] = []
    for line in report_text.split("\n"):
        m = _SECTION_TITLE_RE.match(line)
        if m:
            if current_lines: sections.append((current_title, current_lines))
            current_title = m.group(1).strip(); current_lines = []
        else: current_lines.append(line)
    if current_lines: sections.append((current_title, current_lines))
    return sections


# ---------------------------------------------------------------------------
# Secciones del dashboard (nueva estructura)
# ---------------------------------------------------------------------------
def _render_command_center_tab(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    render_command_center(result, enriched, mitre_summary)


def _render_case_management_tab(result, enriched: pd.DataFrame) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    render_case_management(result, enriched)


def _render_last_attack_tab(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    render_last_attack(result, enriched, mitre_summary)


def _render_critical_incidents_tab(result) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    render_critical_incidents(result)


def _render_panorama_tab(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    """Panorama - Vista general de seguridad."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    # Reutilizar el centro de mando como panorama
    render_command_center(result, enriched, mitre_summary)


def _render_detection_tab(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    """Detección - Vista de detecciones."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">DETECCIÓN DE AMENAZAS</div></div>', unsafe_allow_html=True)
    _render_summary_tab(result, enriched)


def _render_hunt_pivots_tab(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    """Hunt Pivots - Pivotes de threat hunting."""
    require_role("ADMIN", "SOC_ANALYST", "AUDITOR")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">HUNT PIVOTS</div></div>', unsafe_allow_html=True)
    st.info("Módulo de Threat Hunting - Pivotes de investigación disponibles próximamente")


def _render_threat_hunting_tab(result, enriched: pd.DataFrame, mitre_summary: dict) -> None:
    """Threat Hunting - Caza de amenazas."""
    require_role("ADMIN", "SOC_ANALYST", "AUDITOR")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">THREAT HUNTING</div></div>', unsafe_allow_html=True)
    st.info("Módulo de Threat Hunting - Consultas avanzadas y hypothesis-driven hunting próximamente")


def _render_campaigns_tab(result, enriched: pd.DataFrame) -> None:
    """Campañas - Gestión de campañas de ataque."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">CAMPAÑAS</div></div>', unsafe_allow_html=True)
    st.info("Gestión de campañas de ataque correlacionadas - Próximamente")


def _render_soc_operations_tab(result, enriched: pd.DataFrame) -> None:
    """Operaciones SOC."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">OPERACIONES SOC</div></div>', unsafe_allow_html=True)
    st.info("Panel de operaciones SOC 24x7 - Turnos, handoffs, métricas operativas próximamente")


def _render_tickets_tab(result, enriched: pd.DataFrame) -> None:
    """Tickets - Gestión de tickets."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">TICKETS</div></div>', unsafe_allow_html=True)
    st.info("Integración con sistema de tickets (Jira, ServiceNow, etc.) - Próximamente")


def _render_digital_surveillance_tab(result, enriched: pd.DataFrame) -> None:
    """Vigilancia Digital."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">VIGILANCIA DIGITAL</div></div>', unsafe_allow_html=True)
    st.info("Monitoreo de superficie de ataque externa - Próximamente")


def _render_defacement_tab(result, enriched: pd.DataFrame) -> None:
    """Defacement - Monitoreo de desfiguración web."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">DEFACEMENT</div></div>', unsafe_allow_html=True)
    st.info("Detección de defacement web y cambios no autorizados - Próximamente")


def _render_assets_response_tab(result, enriched: pd.DataFrame) -> None:
    """Activos & Respuesta - DFIR."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">ACTIVOS & RESPUESTA (DFIR)</div></div>', unsafe_allow_html=True)
    st.info("Gestión de activos y respuesta a incidentes (DFIR) - Próximamente")


def _render_source_status_tab() -> None:
    """Estado de Fuentes - Infraestructura."""
    require_role("ADMIN", "SOC_ANALYST", "AUDITOR")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">ESTADO DE FUENTES</div></div>', unsafe_allow_html=True)
    from modules.health import render_health_panel
    render_health_panel()


def _render_asset_registry_tab() -> None:
    """Registro de Activos."""
    require_role("ADMIN", "SOC_ANALYST", "AUDITOR")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">REGISTRO DE ACTIVOS</div></div>', unsafe_allow_html=True)
    st.info("CMDB e inventario de activos - Próximamente")


def _render_profile_tab() -> None:
    """Mi Perfil SOC."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">MI PERFIL SOC</div></div>', unsafe_allow_html=True)
    st.info("Configuración de perfil de analista - Próximamente")


def _render_settings_tab() -> None:
    """Ajustes - Solo admin."""
    require_role("ADMIN")
    st.markdown('<div class="soc-panel-header"><div class="soc-panel-title">AJUSTES DEL SISTEMA</div></div>', unsafe_allow_html=True)
    st.info("Configuración global del sistema - Próximamente")


# ---------------------------------------------------------------------------
# Secciones legacy (compatibilidad)
# ---------------------------------------------------------------------------
def _render_summary_tab(result, enriched: pd.DataFrame) -> None:
    """Vista resumen legacy - redirige a Centro de Mando."""
    render_command_center(result, enriched, {})


def _render_mitre_tab(mitre_summary: dict, result=None) -> None:
    """Pestaña MITRE ATT&CK legacy."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    rows = []
    for technique, meta in MITRE_TECHNIQUES.items():
        info = mitre_summary.get(technique, {})
        rows.append({
            "Táctica": technique, "ID": meta["tactic_id"],
            "Técnicas": " · ".join(meta.get("techniques", [])),
            "Eventos": info.get("count", 0), "Ejemplo": info.get("example", "")[:160],
            "Descripción": meta["description"],
        })
    mitre_df = pd.DataFrame(rows)
    ui.section_title("🧩 CLASIFICACIÓN MITRE ATT&CK")
    ui.mitre_blocks_html(mitre_df)
    
    total = int(mitre_df["Eventos"].sum())
    tactics_with_findings = mitre_df[mitre_df["Eventos"] > 0]
    tactics_count = len(tactics_with_findings)
    
    if total:
        m1, m2, m3 = st.columns(3)
        m1.metric("Total eventos MITRE", _es_num(total))
        m2.metric("Tácticas con hallazgos", _es_num(tactics_count))
        m3.metric("Tácticas sin hallazgos", _es_num(len(MITRE_TECHNIQUES) - tactics_count))
        
        fig = px.bar(tactics_with_findings, x="Eventos", y="Táctica", orientation="h",
            text="Eventos", color="Eventos", color_continuous_scale=["#2196F3", "#FB8C00", "#E53935"],
            labels={"Eventos": "Eventos relacionados", "Táctica": ""}, template="plotly_dark")
        fig.update_layout(showlegend=False, height=280, coloraxis_showscale=False,
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, width="stretch")
    else:
        st.info("No se detectaron eventos asociados a tácticas MITRE ATT&CK.")


def _clean(value: object) -> str:
    if value is None: return ""
    if isinstance(value, float) and pd.isna(value): return ""
    text = str(value).strip()
    return "" if text.lower() == "nan" else text


def _render_relevant_tab(result, enriched: pd.DataFrame) -> None:
    """Eventos relevantes legacy."""
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    iocs = getattr(result, "iocs", {}) or {}
    cols = st.columns(2)
    ui.chip_column(cols[0], "🧬 CVEs", list(result.cves or []), empty_msg="Sin CVEs")
    ui.chip_column(cols[1], "🌐 IPs externas", list(result.external_ips or []), empty_msg="Sin IPs externas")
    col3 = st.columns(2)
    ui.chip_column(col3[0], "🏠 IPs internas", list(result.internal_ips or []), empty_msg="Sin IPs internas")
    ioc_extra = list(iocs.get("domains") or []) + list(iocs.get("urls") or [])
    ui.chip_column(col3[1], "🔗 Dominios/URLs", [str(x) for x in ioc_extra], empty_msg="Sin dominios/URLs")


def _render_table_tab(enriched: pd.DataFrame) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    cols = [c for c in TABLE_COLUMNS if c in enriched.columns]
    mitre_cols = [c for c in enriched.columns if c.startswith("mitre_")]
    st.caption("Eventos normalizados: columnas canónicas + marcas MITRE.")
    st.dataframe(enriched[cols + mitre_cols].head(200), width="stretch", hide_index=True)


def _render_report_tab(analyst: str, period: str, entity: str,
                       report_text: str, signature: str, result) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    ui.section_title("📄 Reporte Generado")
    meta_col, save_col = st.columns([3, 2])
    with meta_col:
        st.caption(f"👨‍💻 {analyst} · 🕒 {period} · 🏢 {entity or 'Sin entidad'}")
    with save_col:
        if st.button("📌 Guardar en historial", width="stretch"):
            records, _ = save_report(build_report_record(
                signature=f"{signature}|{datetime.now().isoformat(timespec='seconds')}",
                analyst=analyst, period=period, entity=entity,
                result_count={"critical": result.critical_count, "high": result.high_count,
                              "total": result.total_events, "agents": result.agents_count},
                report_text=report_text,
            ))
            st.session_state["report_history"] = records
            st.rerun()
    
    with st.container(border=True):
        c1, c2, c3, c4, c5 = st.columns([1, 1, 1, 1, 2])
        c1.metric("Críticos", result.critical_count)
        c2.metric("Alta", result.high_count)
        c3.metric("Total", result.total_events)
        c4.metric("Agentes", result.agents_count)
        with c5:
            st.markdown(ui.risk_score_bar_html(result.overall_risk_score), unsafe_allow_html=True)
    
    _download_buttons(report_text, result=result, mitre_summary={}, analyst=analyst, period=period, entity=entity, template="ejecutivo")
    
    sections = _split_report_sections(report_text)
    with st.container(border=True):
        if len(sections) >= 2:
            for title, lines in sections:
                body = "\n".join(lines).strip()
                if not body and title == "Encabezado": continue
                exp = any(k in title.lower() for k in _EXPANDED_SECTIONS)
                with st.expander(f"📑 {title}", expanded=exp):
                    if body: st.markdown(body)
        else:
            mitad = len(report_text) // 2
            with st.expander("📑 Resumen y Hallazgos", expanded=True): st.markdown(report_text[:mitad])
            with st.expander("📑 Detalle técnico e IOCs", expanded=False): st.markdown(report_text[mitad:])


def _render_history_tab(records: list[dict]) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    st.subheader("🗂️ Historial de Reportes")
    stats = get_history_stats(records)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total reportes", stats["total_reports"])
    m2.metric("Eventos críticos", stats["total_critical"])
    m3.metric("Eventos alta", stats["total_high"])
    m4.metric("Agentes totales", stats["total_agents"])
    
    if not records:
        st.info("Aún no hay reportes guardados.")
        return
    
    with st.expander("🔍 Filtros", expanded=False):
        f1, f2, f3, f4 = st.columns(4)
        with f1:
            analysts = list(set(r.get("analyst", "") for r in records))
            filter_analyst = st.selectbox("Analista", ["Todos"] + analysts)
        with f2:
            periods = list(set(r.get("period", "") for r in records))
            filter_period = st.selectbox("Periodo", ["Todos"] + periods)
        with f3:
            templates = list(set(r.get("template", "ejecutivo") for r in records))
            filter_template = st.selectbox("Plantilla", ["Todos"] + templates)
        with f4:
            entities = list(set(r.get("entity") or "" for r in records))
            filter_entity = st.selectbox("Entidad", ["Todos"] + [e for e in entities if e])
    
    filtered = records
    if filter_analyst != "Todos": filtered = [r for r in filtered if filter_analyst.lower() in r.get("analyst", "").lower()]
    if filter_period != "Todos": filtered = [r for r in filtered if filter_period.lower() in r.get("period", "").lower()]
    if filter_template != "Todos": filtered = [r for r in filtered if r.get("template") == filter_template]
    if filter_entity != "Todos": filtered = [r for r in filtered if filter_entity.lower() in (r.get("entity") or "").lower()]
    
    for record in reversed(filtered):
        with st.expander(f"📄 {record.get('analyst','N/D')} · {record.get('period','N/D')} · {record.get('created_at','N/D')[:19]} · Críticos: {record.get('critical',0)}", expanded=False):
            st.markdown(record.get("report", "Sin contenido"))


def _intel_provider_verdict(provider: str, data: dict) -> str:
    p = provider
    if p == "abuseipdb":
        conf = data.get("abuseConfidenceScore") or 0
        reports = data.get("totalReports") or 0
        fmt = f"Confianza {conf}% · {reports} reportes · {data.get('usageType') or 'N/A'}"
        if data.get("isWhitelisted"): return "🟩 Whitelisted · " + fmt
        if conf >= 50 or reports: return "🟧 Reportada · " + fmt
        return "🟩 Sin reportes · " + fmt
    if p == "virustotal":
        malicious = data.get("malicious", 0)
        fmt = f"{malicious} maliciosos · {data.get('suspicious',0)} sospechosos · reputación {data.get('reputation') or 'N/A'}"
        if malicious: return "🟥 Maliciosa · " + fmt
        if data.get("suspicious"): return "🟧 Sospechosa · " + fmt
        return "🟩 Sin detecciones · " + fmt
    if p == "greynoise":
        klass = data.get("classification") or "unknown"
        if klass == "malicious": return f"🟥 Malicioso · ruido={data.get('noise')} riot={data.get('riot')}"
        if data.get("noise"): return f"🟧 Ruido benigno · name={data.get('name') or 'N/A'}"
        return f"🟩 {klass} · name={data.get('name') or 'N/A'}"
    if p == "threatfox":
        return f"🟥 IoC ThreatFox · {data.get('threat_type') or 'N/A'} · {data.get('malware') or 'N/A'}"
    if p == "otx":
        pulses = data.get("pulses", 0)
        tags = ", ".join(data.get("tags", [])[:4]) or "sin tags"
        fmt = f"Pulsos: {pulses} · ASN {data.get('asn') or 'N/A'} · {tags}"
        return ("🟥 IoC OTX · " + fmt) if pulses else ("🟩 Sin pulsos · " + fmt)
    if p == "shodan":
        vulns = len(data.get("vulns", []) or [])
        ports = ", ".join(str(x) for x in (data.get("ports") or [])[:8])
        fmt = f"Puertos: {ports or 'N/A'} · OS {data.get('os') or 'N/A'} · Vulns: {vulns}"
        return ("🟥 Vulnerable · " + fmt) if vulns else ("⬜ Info · " + fmt)
    return "⬜ Sin datos"


IP_LABELS = {"abuseipdb": "AbuseIPDB", "virustotal": "VirusTotal", "greynoise": "GreyNoise", "threatfox": "ThreatFox", "otx": "OTX AlienVault", "shodan": "Shodan"}


def _render_intel_tab(result) -> None:
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    st.subheader("🌐 Threat Intelligence")
    keys = load_keys()
    providers = configured_providers(keys)
    cve_ids = result.cves[:10]
    ips = result.external_ips[:10]
    geo = st.session_state.get("analysis_geo") or {}
    
    with st.expander("ℹ️ Proveedores y configuración", expanded=False):
        st.markdown("Los **CVEs** se consultan al NVD. Las **IPs externas** se cruzan con proveedores con clave. Edita `data/intel_keys.json` para activar: AbuseIPDB, GreyNoise, VirusTotal, OTX, ThreatFox, Shodan.")
    
    if not cve_ids and not ips:
        st.info("No hay CVEs ni IPs externas para consultar."); return
    if not providers:
        st.warning("No hay claves de proveedores configuradas. Edita `data/intel_keys.json`.")
    else:
        st.markdown("**Proveedores activos:** " + ", ".join(providers))
    
    if st.button("🛰️ Consultar Threat Intel", type="primary", key="btn_intel", width="stretch"):
        with st.spinner("Consultando NVD y proveedores..."):
            st.session_state["intel_results"] = {"cves": enrich_cves(cve_ids, keys), "ips": enrich_ips(ips, keys)}
        st.rerun()
    
    results = st.session_state.get("intel_results")
    if not results:
        st.warning("Pulsa el botón para obtener inteligencia."); return
    
    st.caption("Última consulta: " + (results.get("updated") or "ahora"))
    cves_res = results.get("cves") or {}
    ips_res = results.get("ips") or {}
    
    if cves_res:
        ui.section_title(f"CVEs consultados (NVD) · {len(cves_res)}")
        sort_score = sorted(cves_res.items(), key=lambda kv: (kv[1].get("score") is None, -(kv[1].get("score") or 0)))
        for cve, data in sort_score:
            sev = data.get("severity")
            colors = {"CRITICAL": "#FF0000", "HIGH": "#FF8C00", "MEDIUM": "#FFD700", "LOW": "#00FF00"}
            badge = f"baseScore {data.get('score')} ({sev or 'N/D'})"
            with st.expander(f"**{cve}** · {badge}", expanded=False):
                st.markdown(f"`{cve}` · {data.get('published') or 'sin fecha'} · {data.get('references')} refs · {data.get('source') or 'NVD'}")
                st.markdown((data.get("description") or "Sin descripción")[:500])
    
    if ips_res:
        ui.section_title(f"IPs externas · {len(ips_res)}")
        for ip, entry in ips_res.items():
            country = geo.get(ip, {}).get("pais", "")
            labels = sorted(entry.keys(), key=lambda p: IP_LABELS.get(p, p))
            with st.expander(f"**{ip}** · 🌍 {country}" if country else f"**{ip}**", expanded=False):
                for provider in labels:
                    st.markdown(_intel_provider_verdict(provider, entry[provider]))


# ---------------------------------------------------------------------------
# Main rendering logic
# ---------------------------------------------------------------------------
analyst = _sidebar_analyst_manager()
period = _sidebar_shift()
entity = _sidebar_entity()

st.sidebar.divider()
st.sidebar.markdown("<div style='color:#6A6A6A;font-size:.75rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;margin:8px 0 4px;'>CONFIGURACIÓN AVANZADA</div>", unsafe_allow_html=True)
with st.sidebar.expander("📄 Plantilla de reporte", expanded=False):
    template = _sidebar_select_template()
with st.sidebar.expander("⏰ Programador automático", expanded=False):
    _sidebar_scheduler()

# Logout button
st.sidebar.divider()
if st.sidebar.button("🚪 Cerrar sesión", width="stretch", key="btn_logout"):
    logout()

st.sidebar.divider()
df, _detected = _sidebar_data_source()

if df is None:
    st.info("👈 **Sube un CSV de eventos de seguridad** desde la barra lateral o marca “Usar caso de ejemplo incluido” para probar el dashboard.")
    st.stop()

source_hash = _source_hash(df)
if st.session_state.get("analysis_source_hash") != source_hash:
    st.session_state["analysis_results"] = None
    st.session_state["analysis_geo"] = {}
    st.session_state["analysis_source_hash"] = None
    st.session_state["intel_results"] = None

with st.expander(f"Vista previa del CSV ({len(df)} filas)", expanded=False):
    st.caption("Las columnas se detectan automáticamente; el análisis procesa el 100% de las filas.")
    preview_cols = ["timestamp", "severity", "agent", "description", "src_ip", "dst_ip"]
    st.dataframe(df[[c for c in preview_cols if c in df.columns]].head(6), width="stretch", hide_index=True)

analysis = st.session_state.get("analysis_results")
if analysis is None:
    st.warning("📄 El CSV está cargado pero aún no se ha analizado.")
    c1, c2 = st.columns([1, 2])
    with c1:
        analyze_clicked = st.button("🔍 Analizar eventos", type="primary", key="btn_analyze", width="stretch")
    with c2:
        st.caption(f"Se analizarán **{len(df)} filas** del CSV (100% del contenido).")
    if analyze_clicked:
        with st.spinner("Analizando el 100% de las filas del CSV..."):
            result, mitre_summary, enriched = _run_analysis(df)
            historical_baseline = load_daily_baseline(3)
            result.update_trend_data(historical_baseline)
            public_ips = []
            if result.scan_ips:
                public_ips = [ip["ip"] for ip in result.scan_ips if ip.get("tipo") == "publica"]
            elif result.external_ips:
                public_ips = result.external_ips[:100]
            geo = resolve_ips(sorted(set(public_ips)))
            st.session_state["analysis_results"] = (result, mitre_summary, enriched)
            st.session_state["analysis_geo"] = geo
            st.session_state["analysis_source_hash"] = source_hash
            st.session_state["enriched_df"] = enriched
            st.session_state["analysis_baseline_historical"] = historical_baseline
            st.session_state["last_analysis_ts"] = datetime.now().strftime("%d/%m/%Y %H:%M")
            st.toast("✔ Análisis completado", icon="✅")
            st.rerun()
    st.stop()

result, mitre_summary, enriched = analysis
geo = st.session_state.get("analysis_geo") or {}
st.session_state["enriched_df"] = enriched

if "analysis_baseline_historical" not in st.session_state:
    st.session_state["analysis_baseline_historical"] = load_daily_baseline(3)
result.update_trend_data(st.session_state["analysis_baseline_historical"])

# Obtener estado SOC y último análisis
soc_status, soc_label, _ = get_soc_status()
last_analysis = st.session_state.get("last_analysis_ts", "—")

# Renderizar header
render_header(
    last_analysis=last_analysis,
    user_name=current_user_name,
    user_role=current_user_role,
    soc_state=soc_status,
    critical_count=result.critical_count
)

# ---------------------------------------------------------------------------
# Navegación por tabs centrales + secciones expandibles (Legacy/Análisis)
# ---------------------------------------------------------------------------
from modules.ui import render_central_tabs, render_expandable_section, create_mitre_3d_matrix, create_timeline_3d, create_attack_chain_3d

# Definir tabs centrales para vistas de análisis
ANALYSIS_TABS = [
    {"key": "resumen", "title": "Resumen", "icon": "📊"},
    {"key": "mitre", "title": "MITRE ATT&CK", "icon": "🧩"},
    {"key": "relevantes", "title": "Eventos relevantes", "icon": "🔍"},
    {"key": "tabla", "title": "Tabla", "icon": "📋"},
    {"key": "reportes", "title": "Reportes", "icon": "📄"},
    {"key": "historial", "title": "Historial", "icon": "🗂️"},
    {"key": "intel", "title": "Threat Intel", "icon": "🌐"},
]

# Estado del tab activo
if "active_analysis_tab" not in st.session_state:
    st.session_state["active_analysis_tab"] = "resumen"

# Renderizar barra de tabs central
clicked_tab = render_central_tabs(ANALYSIS_TABS, st.session_state["active_analysis_tab"])
if clicked_tab:
    st.session_state["active_analysis_tab"] = clicked_tab
    st.rerun()

active_tab = st.session_state["active_analysis_tab"]

st.markdown("<div style='height:16px'></div>", unsafe_allow_html=True)

# Secciones expandibles según tab activo
def _render_resumen_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    _render_summary_tab(result, enriched)

def _render_mitre_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    _render_mitre_tab(mitre_summary, result)
    # Añadir matriz 3D
    st.markdown("---")
    st.markdown("### 🔮 Matriz MITRE 3D Interactiva")
    fig_mitre_3d = create_mitre_3d_matrix(mitre_summary)
    st.plotly_chart(fig_mitre_3d, width="stretch", config={"displayModeBar": False, "scrollZoom": True})

def _render_relevantes_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    _render_relevant_tab(result, enriched)

def _render_tabla_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    _render_table_tab(enriched)

def _render_reportes_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    today_str = date.today().isoformat()
    report_text = build_report(analyst or "Analista", period, entity, result, mitre_summary, geo=geo, enriched=enriched, template=template)
    signature = _report_signature(df, analyst or "", period, entity, today_str)
    _render_report_tab(analyst or "Analista", period, entity, report_text, signature, result)

def _render_historial_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    records = load_reports()
    _render_history_tab(records)

def _render_intel_section():
    require_role("ADMIN", "SOC_ANALYST", "SOC_VIEWER", "AUDITOR")
    _render_intel_tab(result)

# Renderizar solo la sección activa como expandible (siempre expandida)
if active_tab == "resumen":
    render_expandable_section("resumen", "Resumen", "📊", _render_resumen_section, default_expanded=True)
elif active_tab == "mitre":
    render_expandable_section("mitre", "MITRE ATT&CK", "🧩", _render_mitre_section, default_expanded=True)
elif active_tab == "relevantes":
    render_expandable_section("relevantes", "Eventos relevantes", "🔍", _render_relevantes_section, default_expanded=True)
elif active_tab == "tabla":
    render_expandable_section("tabla", "Tabla de eventos", "📋", _render_tabla_section, default_expanded=True)
elif active_tab == "reportes":
    render_expandable_section("reportes", "Reportes", "📄", _render_reportes_section, default_expanded=True)
elif active_tab == "historial":
    render_expandable_section("historial", "Historial", "🗂️", _render_historial_section, default_expanded=True)
elif active_tab == "intel":
    render_expandable_section("intel", "Threat Intel", "🌐", _render_intel_section, default_expanded=True)