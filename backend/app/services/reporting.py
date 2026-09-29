"""Reportes de cliente: PDF ejecutivo, TXT para WhatsApp y JSON estructurado."""
from __future__ import annotations

import io
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class ReportData:
    header: str = "Reporte SOC 24x7"
    entity: str = "No especificada"
    analyst: str = "Analista SOC"
    period: str = "No especificado"
    report_type: str = "ejecutivo"
    total_events: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    agents_affected: int = 0
    hosts_affected: int = 0
    risk_score: float = 0
    top_agents: list = field(default_factory=list)
    observed_ips: list = field(default_factory=list)
    events: list = field(default_factory=list)
    severity_counts: dict = field(default_factory=dict)
    mitre_tactics: dict = field(default_factory=dict)
    correlations: list = field(default_factory=list)
    iocs: dict = field(default_factory=dict)
    timeline: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    recommendations: list = field(default_factory=list)
    iocs_data: dict = field(default_factory=dict)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


def _date(data: ReportData) -> str:
    return datetime.fromisoformat(data.generated_at.replace("Z", "+00:00")).strftime("%d/%m/%Y %H:%M UTC")


def _plain(value) -> str:
    return " ".join(str(value).split())


def generate_txt_report(data: ReportData) -> str:
    # Avoid treating content from logs as WhatsApp formatting.
    def clean(value):
        return _plain(value).translate(str.maketrans({"*": "", "~": "", "`": ""}))

    lines = [
        "🛡️ *REPORTE SOC 24x7*", "",
        "Compartimos el resumen de los eventos de seguridad analizados.", "",
        f"🏢 *Cliente:* {clean(data.entity)}",
        f"👨‍💻 *Analista:* {clean(data.analyst)}",
        f"📅 *Emisión:* {_date(data)}",
        f"🕒 *Periodo de los registros:* {clean(data.period)}", "",
        "📊 *Resumen ejecutivo*",
        f"• Total de eventos: *{data.total_events:,}*",
        f"• 🔴 Críticos: *{data.critical:,}*",
        f"• 🟠 Altos: *{data.high:,}*",
        f"• 🟡 Medios: *{data.medium:,}* | 🟢 Bajos: *{data.low:,}*",
        f"• Agentes: *{data.agents_affected}* | Hosts: *{data.hosts_affected}*",
        f"• Índice de riesgo: *{data.risk_score:.1f}/100*", "",
        "📋 *Hallazgos principales*",
    ]
    lines.extend(f"• {clean(item)}" for item in data.findings[:5])
    if not data.findings:
        lines.append("• Sin hallazgos adicionales en los registros analizados.")
    if data.top_agents:
        lines.extend(["", "💻 *Agentes con mayor actividad*"])
        lines.extend(f"• {clean(row['agent'])}: *{row['count']} eventos*" for row in data.top_agents[:5])
    if data.observed_ips:
        lines.extend(["", "🌐 *IPs observadas — requieren contexto*"])
        lines.extend(f"• {clean(ip)}" for ip in data.observed_ips[:5])
    lines.extend(["", "📌 *Acciones recomendadas*"])
    lines.extend(f"• {clean(item)}" for item in data.recommendations[:4])
    lines.extend(["", "*Estado:* Pendiente de validación.",
                  "Los eventos detectados no equivalen a incidentes confirmados.",
                  "¿Podrían confirmar si la actividad corresponde a operaciones autorizadas?", "",
                  f"Atendido por {clean(data.analyst)} · Equipo SOC 24x7"])
    if len(data.findings) > 5 or len(data.top_agents) > 5 or len(data.observed_ips) > 5:
        lines.extend(["", "_Resumen: consulte el PDF/JSON para ampliar el detalle._"])
    return "\n".join(lines)


def generate_json_report(data: ReportData) -> str:
    result = asdict(data)
    result['summary'] = {key: getattr(data, key) for key in (
        'total_events', 'critical', 'high', 'medium', 'low',
        'agents_affected', 'hosts_affected', 'risk_score')}
    result['iocs'] = data.iocs_data
    result['status'] = 'Pendiente de validación'
    return json.dumps(result, indent=2, ensure_ascii=False)


def generate_pdf_report(data: ReportData) -> bytes:
    from fpdf import FPDF
    from .pdf_charts import (
        severity_donut_image, top_agents_bar_image, risk_gauge_image,
        mitre_tactics_bar_image, timeline_chart_image,
    )

    blue = (24, 115, 190)
    ink = (30, 41, 59)
    muted = (92, 108, 128)

    def text(value):
        return _plain(value).replace('→', ' > ').replace('—', '-').encode('latin-1', 'replace').decode('latin-1')

    class ClientPDF(FPDF):
        def header(self):
            self.set_fill_color(*blue)
            self.rect(0, 0, self.w, 3, 'F')
            self.set_font('Helvetica', 'B', 9)
            self.set_text_color(*blue)
            self.cell(0, 7, 'SOC 24x7  /  INFORME DE SEGURIDAD', new_x='LMARGIN', new_y='NEXT')
            self.ln(4)

        def footer(self):
            self.set_y(-19)
            self.set_draw_color(*blue)
            self.line(16, self.y, self.w - 16, self.y)
            self.set_font('Helvetica', '', 8)
            self.set_text_color(*muted)
            self.cell(0, 6, text(f'Emitido: {_date(data)} | Pendiente de validación'), align='C', new_x='LMARGIN', new_y='NEXT')
            self.cell(0, 5, f'Equipo SOC 24x7  |  Página {self.page_no()}/{{nb}}', align='C')

    pdf = ClientPDF()
    pdf.set_margins(16, 13, 16)
    pdf.set_auto_page_break(True, 25)
    pdf.alias_nb_pages()
    pdf.set_title(data.header)
    pdf.set_author(data.analyst)
    pdf.add_page()

    def body(value, bold=False, size=10):
        pdf.set_font('Helvetica', 'B' if bold else '', size)
        pdf.set_text_color(*ink)
        pdf.multi_cell(0, 5.5, text(value), new_x='LMARGIN', new_y='NEXT')

    def section(title):
        if pdf.get_y() > 244:
            pdf.add_page()
        pdf.ln(5)
        pdf.set_fill_color(235, 244, 251)
        pdf.set_text_color(*blue)
        pdf.set_font('Helvetica', 'B', 12)
        pdf.multi_cell(0, 9, text(title), fill=True, new_x='LMARGIN', new_y='NEXT')
        pdf.ln(3)

    def embed_image(img_bytes: bytes, width_ratio: float = 1.0):
        """Incusta una imagen PNG en el PDF, saltando de página si no cabe."""
        if not img_bytes:
            return
        if pdf.get_y() > 180:
            pdf.add_page()
        bio = io.BytesIO(img_bytes)
        pdf.image(bio, x=16, w=pdf.epw * width_ratio)
        pdf.ln(5)

    pdf.set_text_color(*blue)
    pdf.set_font('Helvetica', 'B', 25)
    pdf.cell(0, 14, 'REPORTE SOC 24x7', new_x='LMARGIN', new_y='NEXT')
    body({'ejecutivo': 'Informe ejecutivo', 'tecnico': 'Informe técnico', 'auditoria': 'Informe de auditoría'}.get(data.report_type, 'Informe de seguridad'), size=13)
    pdf.ln(5)
    for label, value in [('Cliente', data.entity), ('Responsable', data.analyst), ('Periodo de los registros', data.period), ('Emisión', _date(data))]:
        body(f'{label}: {value}')

    # ── PÁGINA 1: Resumen ejecutivo con gráficos ──
    section('01 / Resumen ejecutivo')
    body(f'Se analizaron {data.total_events:,} eventos de seguridad de {data.agents_affected} agentes y {data.hosts_affected} hosts. La severidad indica prioridad de revisión; no confirma por sí sola un incidente.')
    pdf.ln(5)

    # Tarjetas KPI
    y = pdf.get_y()
    cards = [
        ('Críticos', data.critical, (210, 55, 65)),
        ('Altos', data.high, (218, 126, 25)),
        ('Eventos', data.total_events, blue),
        ('Agentes', data.agents_affected, (121, 70, 170)),
    ]
    width = (pdf.epw - 9) / 4
    for index, (label, value, color) in enumerate(cards):
        x = 16 + index * (width + 3)
        pdf.set_draw_color(*color)
        pdf.set_fill_color(248, 250, 252)
        pdf.rect(x, y, width, 25, 'DF')
        pdf.set_xy(x, y + 3)
        pdf.set_font('Helvetica', 'B', 19)
        pdf.set_text_color(*color)
        pdf.cell(width, 10, str(value), align='C')
        pdf.set_xy(x, y + 15)
        pdf.set_font('Helvetica', '', 9)
        pdf.cell(width, 6, label, align='C')

    pdf.set_xy(16, y + 30)
    body(f'Índice de riesgo: {data.risk_score:.1f}/100', bold=True)

    # Gauge de riesgo
    embed_image(risk_gauge_image(data.risk_score), width_ratio=0.7)

    # Donut de severidades
    if data.severity_counts:
        embed_image(severity_donut_image(data.severity_counts))

    # ── PÁGINA 2: Agentes y MITRE ──
    pdf.add_page()
    section('02 / Agentes con mayor actividad')
    if data.top_agents:
        embed_image(top_agents_bar_image(data.top_agents))
        body(f'Se muestran {min(10, len(data.top_agents))} de {len(data.top_agents)} agentes. El volumen de eventos no equivale a riesgo confirmado.', size=8)
    else:
        body('No hay agentes identificados en los registros analizados.')

    # MITRE
    if data.mitre_tactics:
        pdf.add_page()
        section('Clasificación MITRE ATT&CK')
        body('Clasificación orientativa del motor; requiere validación con las reglas y registros de origen.', size=9)
        embed_image(mitre_tactics_bar_image(data.mitre_tactics))
    else:
        pdf.add_page()
        section('Clasificación MITRE ATT&CK')
        body('Sin clasificación disponible / evidencia insuficiente.')

    # ── PÁGINA 3+: Hallazgos, IOCs, Recomendaciones ──
    pdf.add_page()
    section('Hallazgos destacados')
    for finding in data.findings or ['Sin hallazgos adicionales en los registros analizados.']:
        body(f'- {finding}')
        pdf.ln(2)

    section('03 / Evidencia y acciones recomendadas')
    section('IPs observadas')
    body(', '.join(data.observed_ips) if data.observed_ips else 'No se dispone de IPs en los registros analizados.')
    body('La presencia de una IP no implica que sea maliciosa.', size=8)

    if data.iocs_data:
        section('Indicadores extraídos / pendientes de validación')
        for key, label in [('file_hashes', 'Hashes'), ('domains', 'Dominios'), ('urls', 'URLs')]:
            values = data.iocs_data.get(key, [])
            if values:
                body(f'{label}:', bold=True)
                for value in values[:10]:
                    body(value, size=9)
                if len(values) > 10:
                    body(f'Mostrados 10 de {len(values)}; detalle completo en JSON.', size=8)

    section('Recomendaciones priorizadas')
    for index, recommendation in enumerate(data.recommendations, 1):
        body(f'{index}. {recommendation}')
        pdf.ln(2)

    section('Alcance y estado')
    body('Pendiente de validación. El informe resume los registros disponibles en la plataforma. Los eventos y clasificaciones automáticas requieren corroboración; no se confirma una intrusión ni una notificación al cliente.')

    # Anexo técnico / auditoría con timeline
    if data.report_type in ('tecnico', 'auditoria') and data.timeline:
        pdf.add_page()
        section('Anexo / Evolución temporal')
        embed_image(timeline_chart_image(data.timeline))
        body(f'Muestra de {len(data.timeline)} registros. El JSON contiene los eventos utilizados en el análisis.', size=9)

    return bytes(pdf.output())


def generate_report_files(report_data: ReportData, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    report_id = f"soc_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S%f')}"
    results = {}
    for extension, content in [('txt', generate_txt_report(report_data)), ('json', generate_json_report(report_data))]:
        path = output_dir / f'{report_id}.{extension}'
        path.write_text(content, encoding='utf-8')
        results[extension] = str(path)
    try:
        path = output_dir / f'{report_id}.pdf'
        path.write_bytes(generate_pdf_report(report_data))
        results['pdf'] = str(path)
    except Exception as error:
        results['pdf_error'] = str(error)
    return {'report_id': report_id, 'files': results}