"""Generación del reporte SOC 24x7 optimizado para WhatsApp.

Estructura final:
1. Encabezado (analista, fecha, periodo, entidad).
2. Resumen Ejecutivo (bloques con conteos).
3. Agentes afectados.
4. Hallazgos destacados (narrativas automáticas legibles para el cliente).
5. IPs relevantes (privadas primero, luego públicas con bandera y conteo).
6. Clasificación MITRE ATT&CK (solo tácticas con hallazgos, técnicas y reglas).
7. Prioridad (recomendaciones automáticas).
8. Estado.

El texto usa negrita de WhatsApp (`*texto*`); el TXT queda listo para copiar
y el PDF convierte las negritas y elimina emojis.
"""
from __future__ import annotations

import re
import textwrap
from datetime import date

from modules.analysis import AnalysisResult
from modules.config import MITRE_TECHNIQUES
from modules.geoip import flag_from_country


def _es_num(number: int) -> str:
    """Número con separador de miles en español ('1009' -> '1.009')."""
    return f"{number:,}".replace(",", ".")


def _fmt_count(count: int) -> str:
    return "1 evento" if count == 1 else f"{_es_num(count)} eventos"


def _period_label(period: str) -> str:
    period = (period or "").strip()
    if not period:
        return "Sin especificar"
    if period.casefold().startswith("turno "):
        return period
    return f"Turno {period}"


def _wrap_inline(text: str, width: int = 60) -> list[str]:
    """Envuelve un listado inline (separado por comas) sin cortar palabras."""
    if not text:
        return [""]
    return textwrap.fill(
        text, width=width, break_long_words=False, break_on_hyphens=False
    ).splitlines()


def _agents_lines(agents: list[str]) -> list[str]:
    """Lista de agentes: un elemento por línea (móvil) o columnas si son muchos."""
    if not agents:
        return ["Sin agentes/hosts detectados en el archivo."]
    if len(agents) <= 12:
        return [f"• {agent}" for agent in agents]
    return _wrap_inline(", ".join(agents))


# ---------------------------------------------------------------------------
# IPs relevantes (privadas -> públicas, bandera y conteo)
# ---------------------------------------------------------------------------
def _report_ips(result: AnalysisResult, geo: dict) -> list[dict]:
    """IPs ordenadas: privadas (internas) primero, públicas después."""
    counts = (result.ip_counts or {})
    items: list[dict] = []
    for ip in result.internal_ips:
        items.append({"ip": ip, "tipo": "privada", "count": counts.get(ip, 0)})
    for ip in result.external_ips:
        items.append({"ip": ip, "tipo": "publica", "count": counts.get(ip, 0)})
    return items


def _format_ip_line(item: dict, geo: dict) -> str:
    """Línea estilo v2: IP en negrita, ícono/bandera, tipo o país y conteo."""
    count = _fmt_count(item.get("count", 0))
    ip = item["ip"]
    if item.get("tipo") == "privada":
        return f"• *{ip}* – 🔒 IP privada (Red interna) – *{count}*"
    info = (geo or {}).get(ip, {})
    if info and info.get("pais"):
        flag = flag_from_country(info.get("cc", ""))
        if flag:
            return f"• *{ip}* – {flag} {info['pais']} – *{count}*"
    return f"• *{ip}* – IP pública – *{count}*"


def _ips_block(result: AnalysisResult, geo: dict) -> tuple[str, list[str]]:
    """Encabezado + líneas de la sección de IPs relevantes."""
    items = _report_ips(result, geo)
    total = sum(item.get("count", 0) for item in items)
    title = f"*🌐 IPs relevantes detectadas ({_fmt_count(total)}):*"
    return title, [_format_ip_line(item, geo) for item in items]


# ---------------------------------------------------------------------------
# IOCs (Indicadores de Compromiso)
# ---------------------------------------------------------------------------
def _iocs_block(result: AnalysisResult) -> tuple[str, list[str]] | tuple[None, None]:
    """Encabezado + líneas de la sección de IOCs."""
    iocs = getattr(result, 'iocs', {}) or {}
    if not any(iocs.values()):
        return None, None
    
    lines = []
    if iocs.get('file_hashes'):
        lines.append(f"• 📁 *Hashes de archivos:* {', '.join(iocs['file_hashes'][:10])}")
        if len(iocs['file_hashes']) > 10:
            lines.append(f"  ... y {len(iocs['file_hashes']) - 10} más")
    if iocs.get('domains'):
        lines.append(f"• 🌐 *Dominios:* {', '.join(iocs['domains'][:10])}")
        if len(iocs['domains']) > 10:
            lines.append(f"  ... y {len(iocs['domains']) - 10} más")
    if iocs.get('urls'):
        lines.append(f"• 🔗 *URLs:* {', '.join(iocs['urls'][:5])}")
        if len(iocs['urls']) > 5:
            lines.append(f"  ... y {len(iocs['urls']) - 5} más")
    
    if lines:
        title = f"*🔍 Indicadores de Compromiso (IOCs) detectados:*"
        return title, lines
    return None, None


# ---------------------------------------------------------------------------
# Secuencias de ataque (Kill Chain)
# ---------------------------------------------------------------------------
def _attack_sequences_block(result: AnalysisResult) -> tuple[str, list[str]] | tuple[None, None]:
    """Encabezado + líneas de la sección de secuencias de ataque detectadas."""
    sequences = getattr(result, 'attack_sequences', {}) or {}
    if not sequences or not sequences.get('kill_chain_patterns'):
        return None, None
    
    lines = []
    tactics_with_events = sequences.get('tactics_with_events', {})
    detected_sequence = sequences.get('detected_sequence', [])
    
    if detected_sequence:
        lines.append(f"• 📋 *Secuencia detectada:* {' → '.join(detected_sequence)}")
    
    for pattern in sequences.get('kill_chain_patterns', []):
        name = pattern.get('name', '')
        seq = pattern.get('sequence', [])
        counts = pattern.get('counts', {})
        count_str = ', '.join([f"{t} ({counts.get(t, 0)})" for t in seq])
        lines.append(f"• ⚠️ *Patrón Kill Chain:* {name} – {count_str}")
    
    if tactics_with_events:
        tactic_counts = ', '.join([f"{t} ({c})" for t, c in tactics_with_events.items()])
        lines.append(f"• 📊 *Tácticas con hallazgos:* {tactic_counts}")
    
    if lines:
        title = f"*⚔️ Correlación de Ataques Multi-fase:*"
        return title, lines
    return None, None


# ---------------------------------------------------------------------------
# MITRE ATT&CK (tácticas con hallazgos, técnicas oficiales y reglas Wazuh)
# ---------------------------------------------------------------------------
def _mitre_lines(summary: dict[str, dict]) -> list[str]:
    """Tácticas con hallazgos: conteo, frase, técnicas oficiales y rule.id."""
    lines: list[str] = []
    for technique, meta in MITRE_TECHNIQUES.items():
        info = summary.get(technique, {"count": 0})
        count = int(info.get("count", 0) or 0)
        if count == 0:
            continue
        count_txt = "1 hallazgo" if count == 1 else f"{_es_num(count)} hallazgos"
        phrase = meta.get("report_line") or meta["description"]
        techs = [t.split()[0] for t in (info.get("techniques") or []) if t]
        tech_txt = ", ".join(techs) or "Verificar documentación MITRE"
        rule_ids = info.get("rule_ids") or []
        rule_txt = f" · reglas Wazuh [{', '.join(str(r) for r in rule_ids)}]" if rule_ids else ""
        lines.append(f"• *{technique} ({count_txt}):* {phrase} · {tech_txt}{rule_txt}")
    if not lines:
        lines.append("• Sin hallazgos MITRE ATT&CK relevantes en este periodo.")
    return lines


# ---------------------------------------------------------------------------
# Narrativas automáticas (reporte humano, estilo v2)
# ---------------------------------------------------------------------------
def _cve_narrative(result: AnalysisResult,
                   enriched) -> str | None:
    if not result.cves:
        return None
    product = None
    if enriched is not None and "description" in enriched.columns:
        pat = re.compile(
            r"(?:affects?|afecta a|corresponde a)\s+([A-Z][A-Za-z0-9 ._\-]{1,45})", re.I
        )
        for desc in enriched["description"].dropna().astype(str):
            match = pat.search(desc)
            if match:
                product = match.group(1).strip()
                break
    head = ", ".join(f"*{c}*" for c in result.cves[:3])
    more = f" y {_es_num(len(result.cves) - 3)} más" if len(result.cves) > 3 else ""
    prod = f" asociadas principalmente a *{product}*" if product else ""
    return (f"• Se detectaron *{_es_num(len(result.cves))} CVEs* de alta severidad{prod}, "
            f"incluyendo {head}{more}. Se recomienda priorizar su actualización.")


def _scan_narrative(result: AnalysisResult, geo: dict) -> str | None:
    if not result.scan_events:
        return None
    counts = result.ip_counts or {}
    origins = result.scan_ips or []
    pool = [o for o in origins if o.get("tipo") == "publica"] or origins
    origin = ""
    if pool:
        top = max(pool, key=lambda o: counts.get(o["ip"], 0))
        top_count = counts.get(top["ip"], 0)
        if top_count > 1:
            origin = (f" La mayor concentración proviene de *{top['ip']}* "
                      f"({_fmt_count(top_count)}).")
    return (f"• Se registraron *{_es_num(result.scan_events)} eventos* de escaneo "
            f"agresivo de directorios / puertos.{origin}")


def _process_narrative(result: AnalysisResult) -> str | None:
    if not result.suspicious_events or not result.suspicious_processes:
        return None
    fragments = ", ".join(result.suspicious_processes[:4])
    return (f"• Se detectaron *{_fmt_count(result.suspicious_events)}* de procesos o "
            f"comandos sospechosos ({fragments}). Se recomienda validar su legitimidad "
            f"en los agentes afectados.")


def _service_narrative(result: AnalysisResult) -> str | None:
    if not result.service_events:
        return None
    return (f"• Se registraron *{_fmt_count(result.service_events)}* relacionados con "
            f"la creación de servicios de Windows. Se recomienda validar su legitimidad.")


def _auth_narrative(result: AnalysisResult) -> str | None:
    if not result.auth_events:
        return None
    return (f"• Se detectaron *{_fmt_count(result.auth_events)}* de autenticación o "
            f"credenciales sospechosas. Se recomienda revisar cuentas y habilitar MFA.")


def _narrative_lines(result: AnalysisResult, geo: dict,
                     enriched) -> list[str]:
    """Líneas narrativas de los hallazgos (un párrafo breve por tipo)."""
    lines = [fn() for fn in (
        lambda: _cve_narrative(result, enriched),
        lambda: _scan_narrative(result, geo),
        lambda: _process_narrative(result),
        lambda: _service_narrative(result),
        lambda: _auth_narrative(result),
    )]
    lines = [line for line in lines if line]
    if not lines:
        lines.append("• Sin hallazgos destacados en este periodo.")
    return lines


def _generate_executive_narratives(result: AnalysisResult, geo: dict) -> list[str]:
    """Genera narrativas automáticas para el resumen ejecutivo.
    Ejemplos: "Se detectó posible exfiltración en SRV01 con 3 intentos fallidos"
    """
    narratives = []

    if result.total_events == 0:
        return ["• No se detectaron eventos de seguridad en el periodo analizado."]

    # Narrativa 1: Agente con mayor riesgo o más eventos
    if result.agents and result.risk_score_per_agent:
        top_agent = max(result.risk_score_per_agent.items(), key=lambda x: x[1])
        agent_name, agent_score = top_agent
        if agent_score > 50:
            narratives.append(
                f"• El agente *{agent_name}* presenta el mayor score de riesgo ({int(agent_score)}/100), "
                f"concentrando la mayor actividad sospechosa del periodo."
            )
        elif result.high_count > 0:
            narratives.append(
                f"• *{agent_name}* mostró la mayor actividad de alta severidad "
                f"({_es_num(result.high_count)} eventos)."
            )

    # Narrativa 2: Patrón de ataque específico detectado
    # Fuerza bruta: muchos intentos de autenticación fallidos
    if result.auth_events >= 5:
        top_agent = ""
        if result.top_agents:
            top_agent = f" en *{result.top_agents[0][0]}*"
        narratives.append(
            f"• Se detectaron {_es_num(result.auth_events)} intentos de autenticación fallidos"
            f"{top_agent}, indicando posible *fuerza bruta*."
        )

    # Procesos sospechosos específicos (Mimikatz, PowerShell ofuscado, etc.)
    if result.suspicious_processes:
        suspicious_lower = [p.lower() for p in result.suspicious_processes]
        if any('mimikatz' in p for p in suspicious_lower):
            narratives.append(
                "• Se detectó ejecución de *Mimikatz*, herramienta de extracción de credenciales."
            )
        if any('powershell' in p and ('-enc' in p or 'encodedcommand' in p) for p in suspicious_lower):
            narratives.append(
                "• Se detectó uso de *PowerShell ofuscado* (-enc), técnica común en ataques avanzados."
            )

    # Posible exfiltración: muchas IPs externas + eventos de red
    if len(result.external_ips) > 3:
        if result.scan_events > 5 or len(result.external_ips) > 5:
            narratives.append(
                f"• Se observó comunicación con {_es_num(len(result.external_ips))} IPs externas distintas, "
                f"posible reconocimiento o exfiltración."
            )

    # CVEs conocidos
    if result.cves:
        if len(result.cves) >= 2:
            cve_list = ", ".join([f"*{c}*" for c in result.cves[:3]])
            more = " y más" if len(result.cves) > 3 else ""
            narratives.append(
                f"• Se identificaron {_es_num(len(result.cves))} CVEs distintos, incluyendo {cve_list}{more}."
            )
        elif len(result.cves) == 1:
            narratives.append(
                f"• Se detectó explotación de {result.cves[0]}, vulnerabilidad conocida."
            )

    # Si no hay narrativas específicas, dar una general
    if not narratives:
        if result.critical_count > 0:
            narratives.append(
                f"• Se detectaron {_es_num(result.critical_count)} eventos críticos que requieren atención inmediata."
            )
        elif result.high_count > 0:
            narratives.append(
                f"• Se registraron {_es_num(result.high_count)} eventos de alta severidad."
            )
        else:
            narratives.append(
                f"• Se analizaron {_es_num(result.total_events)} eventos sin hallazgos de seguridad significativos."
            )

    # Limitar a 3 narrativas máximas para mantener concisión ejecutiva
    return narratives[:3]


# ---------------------------------------------------------------------------
# Prioridad / recomendaciones automáticas
# ---------------------------------------------------------------------------
def _priority_lines(result: AnalysisResult) -> list[str]:
    if result.critical_count:
        yield f"• Revisión inmediata de los *{_es_num(result.critical_count)}* eventos críticos."
    if result.cves:
        yield "• Priorizar la actualización/corrección de los CVEs identificados en los agentes afectados."
    if result.scan_events:
        yield "• Investigar el origen de los escaneos (ver IPs relevantes) a nivel de firewall/proxy."
    if result.suspicious_events:
        yield "• Validar los procesos/comandos sospechosos y aislar los hosts comprometidos si fuera necesario."
    if result.service_events:
        yield "• Revisar los servicios de Windows recién creados."
    if result.auth_events:
        yield "• Revisar intentos de autenticación/credenciales y forzar el cambio de contraseñas si aplica."
    if not result.critical_count and not result.cves and not result.scan_events \
            and not result.suspicious_events and not result.service_events \
            and not result.auth_events:
        yield "• Mantener el monitoreo habitual sobre los eventos detectados."


# ---------------------------------------------------------------------------
# Plantillas de reporte (ejecutivo, técnico, auditoría)
# ---------------------------------------------------------------------------
REPORT_TEMPLATES = {
    "ejecutivo": {
        "name": "Ejecutivo",
        "description": "Resumen de alto nivel para dirección (1-2 páginas)",
        "sections": [
            "header", "resumen_ejecutivo", "riesgo_tendencias", 
            "hallazgos_ejecutivos", "agentes", "prioridad", "footer"
        ]
    },
    "tecnico": {
        "name": "Técnico",
        "description": "Detalle completo para analistas SOC (incluye MITRE, IOCs, secuencias)",
        "sections": [
            "header", "resumen_ejecutivo", "riesgo_tendencias",
            "hallazgos_ejecutivos", "agentes", "hallazgos_destacados",
            "ips", "iocs", "attack_sequences", "mitre", "prioridad", "footer"
        ]
    },
    "auditoria": {
        "name": "Auditoría",
        "description": "Formato estructurado para compliance/auditoría (trazabilidad completa)",
        "sections": [
            "header", "resumen_ejecutivo", "riesgo_tendencias",
            "hallazgos_ejecutivos", "agentes", "hallazgos_destacados",
            "ips", "iocs", "attack_sequences", "mitre", "prioridad", 
            "trazabilidad", "footer"
        ]
    }
}


def build_report(
    analyst: str,
    period: str,
    entity: str,
    result: AnalysisResult,
    mitre_summary: dict[str, dict],
    geo: dict[str, dict[str, str]] | None = None,
    today: date | None = None,
    enriched=None,
    template: str = "ejecutivo"
) -> str:
    """Genera el reporte completo según plantilla seleccionada.

    `template`: "ejecutivo" | "tecnico" | "auditoria"
    `geo` mapea IP pública -> {"cc": código, "pais": nombre} para banderas.
    `enriched` es el DataFrame enriquecido (opcional) para narrativas.
    """
    template_config = REPORT_TEMPLATES.get(template, REPORT_TEMPLATES["ejecutivo"])
    sections_to_include = template_config["sections"]
    
    today = today or date.today()
    geo = geo or {}
    agents = result.agents
    lines: list[str] = []
    
    # HEADER (siempre incluido)
    if "header" in sections_to_include:
        lines.append("🛡️ *REPORTE SOC 24x7*")
        lines.append("")
        lines.append("Hola, compartimos el *reporte SOC 24x7* correspondiente al turno indicado:")
        lines.append("")
        lines.append(f"👨‍💻 *Analista:* {analyst}")
        lines.append(f"📅 *Fecha:* {today:%d/%m/%Y}")
        lines.append(f"🕒 *Periodo:* {_period_label(period)}")
        lines.append(f"🏢 *Entidad:* {entity or 'No especificada'}")
        lines.append(f"📄 *Plantilla:* {template_config['name']}")
        lines.append("")
    
    # RESUMEN EJECUTIVO
    if "resumen_ejecutivo" in sections_to_include:
        lines.append("*🔍 Resumen Ejecutivo*")
        lines.append(f"• 🔴 Eventos Críticos: *{_es_num(result.critical_count)}*")
        lines.append(f"• 🟠 Eventos Alta Severidad: *{_es_num(result.high_count)}*")
        lines.append(f"• 🟢 Total de eventos: *{_es_num(result.total_events)}*")
        lines.append(f"• 💻 Agentes afectados: *{_es_num(len(agents))}*")
        lines.append("")
    
    # RIESGO Y TENDENCIAS
    if "riesgo_tendencias" in sections_to_include:
        lines.append("*📊 Análisis de Riesgo y Tendencias*")
        lines.append(f"• 🎯 Score de Riesgo General: *{_es_num(int(result.overall_risk_score))}/100*")
        
        if result.trend_data:
            trend = result.trend_data
            def get_trend_indicator(change: float) -> str:
                if change > 5: return "🔴▲"
                elif change < -5: return "🟢▼"
                else: return "🟡→"
            
            lines.append("• 📈 Tendencia vs últimos 3 días:")
            lines.append(f"  - Eventos Críticos: {get_trend_indicator(trend['critical_change'])} *{_es_num(int(abs(trend['critical_change'])))}%*")
            lines.append(f"  - Eventos Alta Severidad: {get_trend_indicator(trend['high_change'])} *{_es_num(int(abs(trend['high_change'])))}%*")
            lines.append(f"  - Total de Eventos: {get_trend_indicator(trend['total_change'])} *{_es_num(int(abs(trend['total_change'])))}%*")
            lines.append(f"  - Agentes Afectados: {get_trend_indicator(trend['agents_change'])} *{_es_num(int(abs(trend['agents_change'])))}%*")
        else:
            lines.append("• 📊 Datos de tendencia no disponibles (se requieren histórico de al menos 1 día)")
        lines.append("")
    
    # HALLAZGOS EJECUTIVOS
    if "hallazgos_ejecutivos" in sections_to_include:
        executive_narratives = _generate_executive_narratives(result, geo)
        if executive_narratives:
            lines.append("*📋 Hallazgos Ejecutivos*")
            lines.extend(executive_narratives)
            lines.append("")
    
    # AGENTES AFECTADOS
    if "agentes" in sections_to_include:
        lines.append(f"*💻 Agentes afectados ({_es_num(len(agents))}):*")
        lines.extend(_agents_lines(agents))
        lines.append("")
    
    # HALLAZGOS DESTACADOS (narrativas por tipo)
    if "hallazgos_destacados" in sections_to_include:
        lines.append("*📋 Hallazgos destacados*")
        lines.extend(_narrative_lines(result, geo, enriched))
        lines.append("")
    
    # IPs RELEVANTES
    if "ips" in sections_to_include:
        ip_title, ip_lines = _ips_block(result, geo)
        if ip_lines:
            lines.append(ip_title)
            lines.extend(ip_lines)
            lines.append("")
    
    # IOCs
    if "iocs" in sections_to_include:
        iocs_title, iocs_lines = _iocs_block(result)
        if iocs_lines:
            lines.append(iocs_title)
            lines.extend(iocs_lines)
            lines.append("")
    
    # SECUENCIAS DE ATAQUE
    if "attack_sequences" in sections_to_include:
        attack_title, attack_lines = _attack_sequences_block(result)
        if attack_lines:
            lines.append(attack_title)
            lines.extend(attack_lines)
            lines.append("")
    
    # MITRE ATT&CK
    if "mitre" in sections_to_include:
        lines.append("*🧩 Clasificación MITRE ATT&CK*")
        lines.extend(_mitre_lines(mitre_summary))
        lines.append("")
    
    # PRIORIDAD
    if "prioridad" in sections_to_include:
        lines.append("*🚨 Prioridad*")
        lines.extend(_priority_lines(result) or ["• Mantener el monitoreo habitual."])
        lines.append("")
    
    # TRAZABILIDAD (solo auditoría)
    if "trazabilidad" in sections_to_include:
        lines.append("*🔗 Trazabilidad y Evidencias*")
        lines.append(f"• Hash del reporte: *SHA256 generado en generación*")
        lines.append(f"• Fuente de datos: CSV analizado ({_es_num(result.total_events)} eventos)")
        lines.append(f"• Método de análisis: Motor SOC 24x7 v3 (reglas + ML + MITRE)")
        lines.append(f"• Retención mínima: *3 días* (configurable)")
        lines.append(f"• Firmado por: {analyst}")
        lines.append("")
    
    # FOOTER
    if "footer" in sections_to_include:
        lines.append("*✅ Estado:* Notificado para revisión")
        lines.append("")
        lines.append(f"Atendido por {analyst} · Equipo SOC 24x7")
    
    return "\n".join(lines)