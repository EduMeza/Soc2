"""Exportación de reportes: descarga en TXT, PDF, JSON y STIX.

El TXT conserva el formato exacto del reporte (emojis y asteriscos estilo
WhatsApp). El PDF usa fpdf2 con formato profesional: encabezado, métricas,
gráficos (severidad, agentes, MITRE), pie de página.

JSON y STIX permiten integración con SIEM/SOAR.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, date
from typing import Any, Optional
from io import BytesIO

from fpdf import FPDF

# Gráficos
import matplotlib
matplotlib.use('Agg')  # Backend sin GUI
import matplotlib.pyplot as plt


# Mapeo de emojis a texto plano para el PDF
EMOJI_REPLACEMENTS = {
    "📊": "[REPORTE]",
    "🔴": "[CRITICO]",
    "🟠": "[ALTA]",
    "💻": "[AGENTES]",
    "⚠️": "[ALERTA]",
    "🧩": "[MITRE]",
    "✅": "[OK]",
    "📄": "[PDF]",
    "👨‍💻": "[ANALISTA]",
    "📅": "[FECHA]",
    "🕒": "[PERIODO]",
    "•": "-",
}


def clean_text_for_pdf(text: str) -> str:
    """Reemplaza emojis por texto plano y elimina caracteres no Latin-1.
    
    Helvetica solo soporta Latin-1 (U+0000 a U+00FF).
    """
    # Primero reemplazar emojis conocidos
    for emoji, replacement in EMOJI_REPLACEMENTS.items():
        text = text.replace(emoji, replacement)
    # Luego eliminar caracteres no Latin-1
    try:
        text = text.encode('latin-1', errors='ignore').decode('latin-1')
    except Exception:
        pass
    return text


def _result_to_dict(result) -> dict:
    """Convierte un AnalysisResult a un dict simple JSON-serializable.

    Extrae solo atributos primitivos (int, float, list, dict) evitando
    objetos no serializables como DataFrames de pandas.
    """
    if result is None:
        return {}

    def _safe_int(value, default: int = 0) -> int:
        try:
            if isinstance(value, dict):
                value = value.get("count", 0) or 0
            return int(value or 0)
        except (TypeError, ValueError):
            return default

    def _safe_float(value, default: float = 0.0) -> float:
        try:
            return float(value or 0.0)
        except (TypeError, ValueError):
            return default

    def _safe_list(value) -> list:
        if isinstance(value, (list, tuple)):
            return list(value)
        return []

    def _safe_dict(value) -> dict:
        if isinstance(value, dict):
            return {str(k): _safe_int(v) if isinstance(v, (int, float, dict)) else str(v)
                    for k, v in value.items()}
        return {}

    return {
        "total_events": _safe_int(getattr(result, "total_events", 0)),
        "critical_count": _safe_int(getattr(result, "critical_count", 0)),
        "high_count": _safe_int(getattr(result, "high_count", 0)),
        "agents_count": _safe_int(getattr(result, "agents_count", 0)),
        "overall_risk_score": _safe_float(getattr(result, "overall_risk_score", 0.0)),
        "severity_counts": _safe_dict(getattr(result, "severity_counts", {})),
        "top_agents": [list(t) for t in _safe_list(getattr(result, "top_agents", []))],
        "cves": [str(c) for c in _safe_list(getattr(result, "cves", []))],
        "internal_ips": [str(ip) for ip in _safe_list(getattr(result, "internal_ips", []))],
        "external_ips": [str(ip) for ip in _safe_list(getattr(result, "external_ips", []))],
        "scan_events": _safe_int(getattr(result, "scan_events", 0)),
        "auth_events": _safe_int(getattr(result, "auth_events", 0)),
        "suspicious_events": _safe_int(getattr(result, "suspicious_events", 0)),
        "suspicious_processes": [str(p) for p in _safe_list(getattr(result, "suspicious_processes", []))],
        "service_events": _safe_int(getattr(result, "service_events", 0)),
    }


def _mitre_to_simple_dict(mitre_summary) -> dict:
    """Normaliza mitre_summary a un dict simple JSON-serializable.

    Maneja valores tipo int o dict {'count': n, 'techniques': [...], 'rule_ids': [...]}
    """
    if not isinstance(mitre_summary, dict):
        return {}
    out: dict = {}
    for tactic, val in mitre_summary.items():
        key = str(tactic)
        if isinstance(val, (int, float)):
            out[key] = int(val)
        elif isinstance(val, dict):
            try:
                count = int(val.get("count", 0) or 0)
            except (TypeError, ValueError):
                count = 0
            entry: dict = {"count": count}
            techniques = val.get("techniques") or []
            rule_ids = val.get("rule_ids") or []
            if techniques:
                entry["techniques"] = [str(t) for t in techniques]
            if rule_ids:
                entry["rule_ids"] = [str(r) for r in rule_ids]
            out[key] = entry
        else:
            out[key] = str(val)
    return out


def report_to_txt_bytes(report_text: str) -> bytes:
    """Devuelve el reporte como bytes en UTF-8 (formato exacto con emojis)."""
    return report_text.encode("utf-8")


def report_to_json_bytes(
    report_text: str,
    result=None,
    mitre_summary=None,
    analyst: str = "",
    period: str = "",
    entity: str = "",
) -> bytes:
    """Devuelve el reporte como bytes JSON para analistas/SIEM."""
    data = {
        "report_text": report_text,
        "analyst": analyst,
        "period": period,
        "entity": entity,
    }
    if result is not None:
        data["result"] = _result_to_dict(result)
    data["mitre_summary"] = _mitre_to_simple_dict(mitre_summary)
    return json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")


def report_to_stix_bytes(
    report_text: str,
    result=None,
    mitre_summary=None,
    analyst: str = "",
    period: str = "",
    entity: str = "",
) -> bytes:
    """Devuelve el reporte como bytes STIX 2.1 para TIP."""
    stix = {
        "report_text": report_text,
        "generated_by": analyst,
        "timestamp": datetime.now().isoformat(),
    }
    if result is not None:
        stix["result"] = _result_to_dict(result)
    stix["mitre_summary"] = _mitre_to_simple_dict(mitre_summary)
    return json.dumps(stix, ensure_ascii=False, indent=2).encode("utf-8")


def report_to_pdf_bytes(
    report_text: str,
    analyst: str = "",
    period: str = "",
    entity: str = "",
    severity_counts: Optional[dict] = None,
    top_agents: Optional[list] = None,
    mitre_summary: Optional[dict] = None,
    overall_risk_score: float = 0.0,
    total_events: int = 0,
    agents_count: int = 0
) -> bytes:
    """Genera un PDF profesional SOC 24x7, limpio y listo para el cliente.

    Estructura: encabezado, resumen ejecutivo (tarjetas + barra de riesgo),
    3 graficos (severidades, top agentes, MITRE), secciones de contenido
    (agentes, hallazgos, IPs, MITRE detallado, prioridad) y pie de pagina
    en todas las paginas.

    Args:
        report_text: Texto del reporte
        analyst: Nombre del analista
        period: Turno/periodo
        entity: Entidad/cliente
        severity_counts: Dict con conteos por severidad (int o {'count': n})
        top_agents: Lista de tuplas (agent, count) ordenada
        mitre_summary: Dict con resumen MITRE por tactica
        overall_risk_score: Score de riesgo general 0-100
        total_events: Total de eventos
        agents_count: Numero de agentes afectados

    Returns:
        bytes del PDF
    """
    from datetime import date, datetime

    # ------------------------------------------------------------------
    # Datos basicos y limpieza
    # ------------------------------------------------------------------
    today = date.today()
    now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
    clean_report = clean_text_for_pdf(report_text)

    # ------------------------------------------------------------------
    # Normalizacion de parametros (evita TypeError con valores nested)
    # ------------------------------------------------------------------
    def _safe_count(value) -> int:
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, dict):
            try:
                return int(value.get("count", 0) or 0)
            except (TypeError, ValueError):
                return 0
        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0

    # mitre_counts: {tactica: int}
    mitre_counts = {}
    if isinstance(mitre_summary, dict):
        for tactic, val in mitre_summary.items():
            n = _safe_count(val)
            if n > 0:
                mitre_counts[str(tactic)] = n

    # severidades normalizadas a int
    critical = _safe_count(severity_counts.get("Critical", 0)) if isinstance(severity_counts, dict) else 0
    high = _safe_count(severity_counts.get("High", 0)) if isinstance(severity_counts, dict) else 0
    medium = _safe_count(severity_counts.get("Medium", 0)) if isinstance(severity_counts, dict) else 0
    low = _safe_count(severity_counts.get("Low", 0)) if isinstance(severity_counts, dict) else 0

    # top_agents normalizado a lista de (str, int)
    agents_norm = []
    if isinstance(top_agents, (list, tuple)):
        for item in top_agents:
            try:
                name, cnt = item[0], _safe_count(item[1])
                agents_norm.append((str(name), cnt))
            except (TypeError, ValueError, IndexError):
                continue

    # escalares
    try:
        overall_risk_score = float(overall_risk_score or 0)
    except (TypeError, ValueError):
        overall_risk_score = 0.0
    try:
        total_events = int(total_events or 0)
    except (TypeError, ValueError):
        total_events = 0
    try:
        agents_count = int(agents_count or 0)
    except (TypeError, ValueError):
        agents_count = 0

    # Datos derivados del texto del reporte
    cve_list = sorted(set(re.findall(r"CVE-\w{3,}", clean_report)))
    ip_list = sorted(set(re.findall(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}", clean_report)))

    # ------------------------------------------------------------------
    # Clase PDF con pie de pagina en todas las paginas
    # ------------------------------------------------------------------
    analyst_txt = clean_text_for_pdf(analyst or "Equipo SOC")
    footer_line = clean_text_for_pdf(
        f"Generado el {now_str} por {analyst or 'Equipo SOC'} - Equipo SOC 24x7"
    )

    class SocPDF(FPDF):
        def footer(self):
            self.set_y(-18)
            self.set_draw_color(33, 150, 243)
            self.set_line_width(0.4)
            self.line(15, self.get_y(), 195, self.get_y())
            self.ln(2)
            self.set_font("helvetica", "B", 8)
            self.set_text_color(33, 150, 243)
            self.cell(0, 5, clean_text_for_pdf("Estado: Notificado para revision"),
                      align="C", new_x="LMARGIN", new_y="NEXT")
            self.set_font("helvetica", "", 7)
            self.set_text_color(130, 130, 130)
            self.cell(0, 4, footer_line, align="C", new_x="LMARGIN", new_y="NEXT")
            self.cell(0, 4, f"Pagina {self.page_no()}/{{nb}}", align="C")

    pdf = SocPDF(format="A4")
    pdf.alias_nb_pages()
    pdf.set_auto_page_break(auto=True, margin=28)  # espacio para el footer
    pdf.set_margins(15, 15, 15)
    pdf.add_page()

    def _txt(s) -> str:
        return clean_text_for_pdf(str(s))

    # Titulo de seccion con barra de acento
    def _section(title: str):
        pdf.ln(2)
        pdf.set_fill_color(33, 150, 243)
        pdf.rect(15, pdf.get_y(), 3, 7, style="F")
        pdf.set_x(20)
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(33, 33, 33)
        pdf.cell(0, 7, _txt(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(220, 220, 220)
        pdf.set_line_width(0.2)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(3)

    # Garantiza que hay al menos h_mm mm libres antes de dibujar
    def _ensure_space(h_mm: float):
        if pdf.get_y() + h_mm > 255:
            pdf.add_page()

    # ==================================================================
    # 1. ENCABEZADO
    # ==================================================================
    pdf.set_fill_color(33, 150, 243)
    pdf.rect(0, 0, 210, 4, style="F")

    pdf.ln(8)
    pdf.set_font("helvetica", "B", 22)
    pdf.set_text_color(33, 150, 243)
    pdf.cell(0, 11, "REPORTE SOC 24x7", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", "", 11)
    pdf.set_text_color(120, 120, 120)
    pdf.cell(0, 7, _txt("Informe Tecnico-Ejecutivo"), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Metadatos en grid 2x2
    meta_items = [
        ("> Analista:", analyst or "No especificado"),
        ("> Fecha:", today.strftime("%d/%m/%Y")),
        ("> Periodo:", period or "No especificado"),
        ("> Entidad:", entity or "No especificada"),
    ]
    pdf.set_fill_color(245, 248, 251)
    box_y = pdf.get_y()
    pdf.set_draw_color(33, 150, 243)
    pdf.set_line_width(0.3)
    pdf.rect(15, box_y, 180, 22, style="DF")
    for i, (label, value) in enumerate(meta_items):
        col = i % 2
        row = i // 2
        pdf.set_xy(19 + col * 90, box_y + 3 + row * 9)
        pdf.set_font("helvetica", "B", 9)
        pdf.set_text_color(33, 150, 243)
        pdf.cell(28, 6, _txt(label))
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(55, 6, _txt(value))
    pdf.set_xy(15, box_y + 26)
    pdf.ln(2)

    # ==================================================================
    # 2. RESUMEN EJECUTIVO
    # ==================================================================
    _section("Resumen Ejecutivo")

    # 4 tarjetas en una sola fila, todas del mismo tamano
    page_w = 180
    gap = 4
    card_w = (page_w - 3 * gap) / 4
    card_h = 22
    y0 = pdf.get_y()

    cards = [
        (_txt("Eventos Criticos"), str(critical), (229, 57, 53)),
        (_txt("Alta Severidad"), str(high), (251, 140, 0)),
        (_txt("Total de Eventos"), str(total_events), (33, 150, 243)),
        (_txt("Agentes Afectados"), str(agents_count), (142, 36, 170)),
    ]

    for i, (label, value, rgb) in enumerate(cards):
        x = 15 + i * (card_w + gap)
        pdf.set_fill_color(250, 250, 250)
        pdf.set_draw_color(*rgb)
        pdf.set_line_width(0.6)
        pdf.rect(x, y0, card_w, card_h, style="DF")
        # valor
        pdf.set_xy(x, y0 + 3)
        pdf.set_font("helvetica", "B", 16)
        pdf.set_text_color(*rgb)
        pdf.cell(card_w, 9, value, align="C", new_x="LMARGIN", new_y="NEXT")
        # etiqueta (auto-ajuste de tamano si es larga)
        pdf.set_x(x)
        pdf.set_font("helvetica", "", 7)
        pdf.set_text_color(90, 90, 90)
        pdf.cell(card_w, 5, label, align="C")

    pdf.set_xy(15, y0 + card_h + 5)

    # Barra de Score de Riesgo
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 6, _txt(f"Score de Riesgo General: {overall_risk_score:.1f}/100"),
             new_x="LMARGIN", new_y="NEXT")
    bar_y = pdf.get_y() + 1
    bar_w = 180
    pdf.set_fill_color(235, 235, 235)
    pdf.rect(15, bar_y, bar_w, 6, style="F")
    if overall_risk_score >= 70:
        risk_rgb = (229, 57, 53)
    elif overall_risk_score >= 40:
        risk_rgb = (251, 140, 0)
    else:
        risk_rgb = (76, 175, 80)
    fill_w = max(0, min(100, overall_risk_score)) / 100 * bar_w
    if fill_w > 0:
        pdf.set_fill_color(*risk_rgb)
        pdf.rect(15, bar_y, fill_w, 6, style="F")
    pdf.set_xy(15, bar_y + 10)

    # ==================================================================
    # 3. GRAFICOS (uno debajo del otro, sin superposicion)
    # ==================================================================
    BLUE = (33, 150, 243)

    # --- Grafico 1: Pie de severidades ---
    severity_dict = {}
    if critical > 0:
        severity_dict["Criticos"] = critical
    if high > 0:
        severity_dict["Alta"] = high
    if medium > 0:
        severity_dict["Medios"] = medium
    if low > 0:
        severity_dict["Bajos"] = low

    if severity_dict:
        # figsize fijo (sin bbox tight) para poder calcular la altura en el PDF
        fig_w, fig_h = 6.4, 3.4
        img_mm = 120.0
        img_h_mm = img_mm * (fig_h / fig_w)
        _ensure_space(img_h_mm + 26)
        _section("Distribucion de Severidades")

        labels = [f"{k} ({v})" for k, v in severity_dict.items()]
        sizes = list(severity_dict.values())
        pie_colors = ["#E53935", "#FB8C00", "#2196F3", "#66BB6A"][:len(labels)]

        fig, ax = plt.subplots(figsize=(fig_w, fig_h))
        ax.pie(sizes, labels=labels, colors=pie_colors, autopct="%1.0f%%",
               startangle=90, textprops={"fontsize": 9},
               wedgeprops={"edgecolor": "white", "linewidth": 1.5},
               labeldistance=1.1)
        ax.axis("equal")

        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=150, facecolor="white")
        buf.seek(0)
        plt.close(fig)

        chart_y = pdf.get_y()
        pdf.image(buf, x=(210 - img_mm) / 2, y=chart_y, w=img_mm, h=img_h_mm)
        pdf.set_y(chart_y + img_h_mm + 5)

    # --- Grafico 2: Top agentes (barras horizontales) ---
    if agents_norm:
        top_show = agents_norm[:10]
        names = [_txt(n) for n, _ in top_show]
        values = [c for _, c in top_show]

        fig_w = 8.8
        fig_h = max(2.8, 0.42 * len(names) + 1.2)
        img_mm = 180.0
        img_h_mm = img_mm * (fig_h / fig_w)

        _ensure_space(img_h_mm + 26)
        _section("Top Agentes Afectados")

        fig, ax = plt.subplots(figsize=(fig_w, fig_h))
        bars = ax.barh(range(len(names)), values, color="#2196F3", edgecolor="#1565C0")
        ax.set_yticks(range(len(names)))
        ax.set_yticklabels(names, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("Eventos", fontsize=8)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.bar_label(bars, padding=2, fontsize=8)

        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=130, facecolor="white")
        buf.seek(0)
        plt.close(fig)

        chart_y = pdf.get_y()
        pdf.image(buf, x=15, y=chart_y, w=img_mm, h=img_h_mm)
        pdf.set_y(chart_y + img_h_mm + 5)

    # --- Grafico 3: MITRE ATT&CK (barras horizontales) ---
    if mitre_counts:
        mitre_sorted = sorted(mitre_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        tactics = [_txt(t) for t, _ in mitre_sorted]
        counts = [c for _, c in mitre_sorted]

        fig_w = 8.8
        fig_h = max(2.8, 0.45 * len(tactics) + 1.2)
        img_mm = 180.0
        img_h_mm = img_mm * (fig_h / fig_w)

        _ensure_space(img_h_mm + 26)
        _section("Clasificacion MITRE ATT&CK")

        fig, ax = plt.subplots(figsize=(fig_w, fig_h))
        bars = ax.barh(range(len(tactics)), counts, color="#7E57C2", edgecolor="#512DA8")
        ax.set_yticks(range(len(tactics)))
        ax.set_yticklabels(tactics, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("Hallazgos", fontsize=8)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.bar_label(bars, padding=2, fontsize=8)

        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=130, facecolor="white")
        buf.seek(0)
        plt.close(fig)

        chart_y = pdf.get_y()
        pdf.image(buf, x=15, y=chart_y, w=img_mm, h=img_h_mm)
        pdf.set_y(chart_y + img_h_mm + 5)

    # ==================================================================
    # 4. AGENTES AFECTADOS (Top 12 + total)
    # ==================================================================
    _ensure_space(45)
    _section("Agentes Afectados")
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)

    if agents_norm:
        max_cnt = max((c for _, c in agents_norm), default=1) or 1
        for name, cnt in agents_norm[:12]:
            # nombre
            pdf.set_font("helvetica", "B", 9)
            pdf.cell(62, 6, _txt(name)[:38])
            # mini barra proporcional
            bar_w = (cnt / max_cnt) * 90
            pdf.set_fill_color(33, 150, 243)
            bx = pdf.get_x()
            by = pdf.get_y() + 1
            pdf.rect(bx, by, max(1.5, bar_w), 3.5, style="F")
            pdf.set_x(bx + 92)
            pdf.set_font("helvetica", "", 9)
            pdf.cell(0, 6, _txt(f"{cnt} eventos"), new_x="LMARGIN", new_y="NEXT")
        if len(agents_norm) > 12:
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 5, _txt(f"... y {len(agents_norm) - 12} agentes mas "
                                f"(total: {len(agents_norm)})"),
                     new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, _txt("No hay datos de agentes disponibles."),
                 new_x="LMARGIN", new_y="NEXT")

    # ==================================================================
    # 5. HALLAZGOS DESTACADOS (contenido real del reporte)
    # ==================================================================
    _ensure_space(40)
    _section("Hallazgos Destacados")
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)

    findings = []
    if cve_list:
        findings.append(_txt(
            f"Se detectaron {len(cve_list)} CVEs distintos, incluyendo "
            f"{', '.join(cve_list[:3])}{'...' if len(cve_list) > 3 else ''}."
        ))
    # Lineas de hallazgo reales del reporte (bullets del TXT)
    for raw in clean_report.split("\n"):
        line = raw.strip().lstrip("•-* ").strip()
        low = line.lower()
        if len(line) < 12:
            continue
        if any(k in low for k in ("escaneo", "proceso", "sospech", "autentic",
                                  "servicio", "fuerza bruta", "exfil")):
            if not any(line in f for f in findings):
                findings.append(_txt(line))
        if len(findings) >= 7:
            break

    if findings:
        for f_text in findings[:8]:
            pdf.set_x(15)
            pdf.multi_cell(180, 5, f"- {f_text}")
        if len(cve_list) > 3:
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 5, _txt(f"(Total CVEs detectados: {len(cve_list)})"),
                     new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, _txt("Sin hallazgos destacados en este periodo."),
                 new_x="LMARGIN", new_y="NEXT")

    # ==================================================================
    # 6. IPs RELEVANTES (Top 10)
    # ==================================================================
    _ensure_space(40)
    _section("IPs Relevantes Detectadas")
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(60, 60, 60)

    if ip_list:
        pdf.cell(0, 5, _txt(f"Se identificaron {len(ip_list)} IPs unicas en el periodo."),
                 new_x="LMARGIN", new_y="NEXT")
        for ip in ip_list[:10]:
            pdf.cell(0, 5, _txt(f"- {ip}"), new_x="LMARGIN", new_y="NEXT")
        if len(ip_list) > 10:
            pdf.set_text_color(120, 120, 120)
            pdf.cell(0, 5, _txt(f"... y {len(ip_list) - 10} IPs mas."),
                     new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 6, _txt("No se detectaron IPs relevantes en el periodo."),
                 new_x="LMARGIN", new_y="NEXT")

    # ==================================================================
    # 7. MITRE ATT&CK DETALLADO
    # ==================================================================
    _ensure_space(40)
    _section("Clasificacion MITRE ATT&CK Detallada")

    if mitre_counts:
        mitre_sorted = sorted(mitre_counts.items(), key=lambda kv: kv[1], reverse=True)
        max_cnt = mitre_sorted[0][1] or 1
        for tactic, count in mitre_sorted:
            pdf.set_font("helvetica", "B", 9)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(70, 6, _txt(tactic)[:42])
            bar_w = (count / max_cnt) * 80
            pdf.set_fill_color(126, 87, 194)
            bx = pdf.get_x()
            by = pdf.get_y() + 1
            pdf.rect(bx, by, max(1.5, bar_w), 3.5, style="F")
            pdf.set_x(bx + 82)
            pdf.set_font("helvetica", "", 9)
            pdf.cell(0, 6, _txt(f"{count} hallazgo(s)"), new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(60, 60, 60)
        pdf.cell(0, 6, _txt("No hay hallazgos MITRE clasificados en este periodo."),
                 new_x="LMARGIN", new_y="NEXT")

    # ==================================================================
    # 8. PRIORIDAD / RECOMENDACIONES
    # ==================================================================
    _ensure_space(50)
    _section("Prioridad / Recomendaciones")

    recommendations = []
    if overall_risk_score >= 70:
        recommendations.append("[ALERTA] Riesgo muy alto: investigar de inmediato los eventos criticos.")
    elif overall_risk_score >= 40:
        recommendations.append("[ALERTA] Riesgo medio-alto: priorizar eventos de alta severidad.")
    if critical > 0:
        recommendations.append(f"[CRITICO] {critical} eventos criticos: aislar y contener los sistemas afectados.")
    if high > 0:
        recommendations.append(f"[ALTA] {high} eventos de alta severidad: verificar legitimidad y alcance.")
    if mitre_counts:
        t_str = ", ".join(sorted(mitre_counts.keys())[:4])
        recommendations.append(f"[MITRE] Aplicar controles para las tacticas detectadas: {t_str}.")
    if agents_norm:
        recommendations.append(f"[AGENTES] Revisar en detalle el agente mas afectado: {_txt(agents_norm[0][0])}.")
    if cve_list:
        recommendations.append(f"[CVE] Programar actualizacion de {len(cve_list)} CVEs identificados.")
    recommendations.append("[OK] Mantener monitoreo continuo y actualizar firmas de deteccion.")

    pdf.set_font("helvetica", "", 9)
    for rec in recommendations[:8]:
        # bullet coloreado segun prefijo
        if "[ALERTA]" in rec:
            pdf.set_text_color(251, 140, 0)
        elif "[CRITICO]" in rec:
            pdf.set_text_color(229, 57, 53)
        elif "[ALTA]" in rec:
            pdf.set_text_color(245, 171, 53)
        else:
            pdf.set_text_color(60, 60, 60)
        pdf.set_x(15)
        pdf.multi_cell(180, 5, _txt(rec))
        pdf.ln(1)

    return bytes(pdf.output())
