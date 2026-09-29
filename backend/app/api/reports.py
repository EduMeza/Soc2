from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from ..core.database import get_db
from ..api.auth import get_current_user
from ..services.reporting import ReportData, generate_report_files
from ..services.history import add_report_record, get_history, get_report_by_id
from ..services.analysis import analyze
from ..services.correlation import find_correlations
from ..services.mitre import classify_mitre
from ..services.risk import calculate_risk_score
from ..services.geoip import get_geoip_for_events
from ..models.event import Event
from datetime import datetime
from pathlib import Path
from collections import Counter
import pandas as pd

router = APIRouter(tags=["reports"])


class GenerateReportRequest(BaseModel):
    format: str = "pdf"
    report_type: str = "ejecutivo"
    include_timeline: bool = True
    include_mitre: bool = True
    include_iocs: bool = True
    entity: str = "No especificada"
    analyst: str = ""


class GenerateResponse(BaseModel):
    status: str
    message: str
    report_id: str
    files: dict


def _build_report_data(db: Session, report_type: str) -> tuple[ReportData, list]:
    """Construye ReportData y lista de eventos desde la BD."""
    events = db.query(Event).all()
    events_list = [
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "severity": e.severity,
            "agent": e.agent,
            "host": e.hostname or e.agent,
            "source_ip": e.source_ip,
            "dst_ip": e.destination_ip,
            "rule": e.rule_id,
            "description": e.rule_description,
            "cve": e.cve,
            "process": e.process,
            "mitre_tactic": e.mitre_tactic,
            "mitre_technique": e.mitre_technique,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "username": e.username,
        }
        for e in events
    ]

    if not events_list:
        events_list = [{"timestamp": "", "severity": "Unknown", "agent": "", "host": "", "source_ip": "", "dst_ip": "", "rule": "", "description": "", "cve": "", "process": "", "mitre_tactic": "", "mitre_technique": "", "source_ip": "", "destination_ip": "", "username": ""}]

    df = pd.DataFrame(events_list)
    analysis_result = analyze(df)

    # Correlaciones
    correlations = find_correlations([
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "src_ip": e.source_ip,
            "host": e.hostname or e.agent,
            "agent": e.agent,
            "rule": e.rule_id,
            "process": e.process,
            "user": e.username,
            "timestamp_raw": e.timestamp.isoformat() if e.timestamp else "",
        }
        for e in events
    ])

    # MITRE
    mitre_data = classify_mitre(events_list)

    # Risk
    risk = calculate_risk_score(events_list)

    # IOCs
    iocs = analysis_result.extract_iocs() if hasattr(analysis_result, 'extract_iocs') else {}

    # Severity counts
    severity_counts = {
        "Critical": sum(1 for e in events if e.severity == "Critical"),
        "High": sum(1 for e in events if e.severity == "High"),
        "Medium": sum(1 for e in events if e.severity == "Medium"),
        "Low": sum(1 for e in events if e.severity == "Low"),
    }

    # Agents and hosts
    agents_affected = len(set(e.agent for e in events if e.agent))
    hosts_affected = len(set(e.hostname or e.agent for e in events if e.hostname or e.agent))

    # Build findings
    findings = []
    if analysis_result.critical_count > 0:
        findings.append(f"{analysis_result.critical_count} eventos críticos detectados - Revisión inmediata requerida")
    if analysis_result.high_count > 0:
        findings.append(f"{analysis_result.high_count} eventos de alta severidad - Prioridad alta")
    if analysis_result.suspicious_processes:
        findings.append(f"Procesos/comandos sospechosos: {', '.join(analysis_result.suspicious_processes[:10])}")
    if analysis_result.cves:
        findings.append(f"CVEs identificados: {', '.join(analysis_result.cves[:10])}")
    if analysis_result.scan_ips:
        findings.append(f"IPs de escaneo detectadas: {len(analysis_result.scan_ips)}")

    # Recommendations
    recommendations = []
    if severity_counts['Critical']:
        recommendations.append(f"Inmediata: validar los {severity_counts['Critical']} eventos críticos y evaluar contención si se confirma actividad no autorizada.")
    if severity_counts['High']:
        recommendations.append(f"Prioritaria: revisar legitimidad y alcance de los {severity_counts['High']} eventos de alta severidad.")
    if analysis_result.cves:
        recommendations.append("Corto plazo: verificar versiones afectadas por los CVEs registrados y priorizar las correcciones aplicables.")
    if analysis_result.suspicious_processes:
        recommendations.append("Validar los procesos observados con los responsables de los equipos y revisar su origen.")
    recommendations.append("Seguimiento: documentar la validación y ajustar las detecciones si se confirman falsos positivos.")

    # Timeline
    timeline = [
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "host": e.hostname or e.agent,
            "severity": e.severity,
            "description": e.rule_description or "",
        }
        for e in events[-50:]
    ]

    timestamps = sorted(e.timestamp for e in events if e.timestamp)
    agent_counts = Counter(e.agent for e in events if e.agent)
    report_data = ReportData(
        header="Reporte SOC 24x7",
        entity="No especificada",
        analyst="SOC Analyst",
        period=f"{timestamps[0].isoformat()} a {timestamps[-1].isoformat()} (horario de origen)" if timestamps else "No disponible",
        report_type=report_type,
        risk_score=round(risk, 1),
        top_agents=[{'agent': agent, 'count': count} for agent, count in agent_counts.most_common()],
        observed_ips=sorted({ip for e in events for ip in (e.source_ip, e.destination_ip) if ip}),
        total_events=len(events),
        critical=severity_counts.get("Critical", 0),
        high=severity_counts.get("High", 0),
        medium=severity_counts.get("Medium", 0),
        low=severity_counts.get("Low", 0),
        agents_affected=agents_affected,
        hosts_affected=hosts_affected,
        events=events_list if events else [],
        severity_counts=severity_counts,
        mitre_tactics=mitre_data.get("tactics", {}),
        correlations=correlations,
        iocs=iocs,
        timeline=timeline,
        findings=findings,
        recommendations=recommendations,
        iocs_data=iocs,
    )
    return report_data, events


@router.post("/generate")
def generate_report(
    request: GenerateReportRequest,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user)
):
    report_data, events = _build_report_data(db, request.report_type)
    report_data.entity = request.entity.strip() or "No especificada"
    report_data.analyst = request.analyst.strip() or current_user.username
    if not request.include_timeline:
        report_data.timeline = []
    if not request.include_mitre:
        report_data.mitre_tactics = {}
    if not request.include_iocs:
        report_data.iocs_data = {}
        report_data.observed_ips = []

    # Generar archivos
    files = generate_report_files(report_data, Path("output"))
    report_id = files["report_id"]
    file_paths = files["files"]

    # Guardar en historial
    record = {
        "id": report_id,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "analyst": report_data.analyst,
        "entity": report_data.entity,
        "period": report_data.period,
        "total_events": len(events),
        "critical": report_data.critical,
        "high": report_data.high,
        "medium": report_data.medium,
        "low": report_data.low,
        "risk_score": round(calculate_risk_score([{"severity": e.severity} for e in events]), 1),
        "file_paths": file_paths,
        "summary": f"Eventos críticos: {report_data.critical} · Alta severidad: {report_data.high} · Total: {len(events)} · Agentes: {report_data.agents_affected}",
    }
    add_report_record(record)

    return {
        "status": "success",
        "message": "Reporte generado correctamente",
        "report_id": report_id,
        "files": file_paths,
    }


@router.get("/download/{format}/{report_id}")
def download_report(format: str, report_id: str):
    from fastapi.responses import FileResponse
    import re
    if format not in {"pdf", "txt", "json"}:
        raise HTTPException(status_code=400, detail="Formato no compatible")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", report_id):
        raise HTTPException(status_code=400, detail="Identificador no válido")
    base = report_id[11:] if report_id.startswith("soc_report_") and len(report_id) > 11 else report_id
    candidates = [
        Path("output") / f"soc_report_{base}.{format}",
        Path("output") / f"{report_id}.{format}",
        Path(__file__).resolve().parents[2] / "output" / f"soc_report_{base}.{format}",
        Path(__file__).resolve().parents[2] / "output" / f"{report_id}.{format}",
    ]
    record = get_report_by_id(report_id)
    stored_path = (record or {}).get("file_paths", {}).get(format)
    if stored_path:
        filename = Path(stored_path.replace("\\", "/")).name
        candidates.insert(0, Path(__file__).resolve().parents[2] / "output" / filename)
    file_path = next((c for c in candidates if c.exists()), None)
    if not file_path:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    media_type = {
        "pdf": "application/pdf",
        "txt": "text/plain",
        "json": "application/json",
    }.get(format, "application/octet-stream")
    return FileResponse(path=file_path, media_type=media_type, filename=file_path.name)


@router.get("/")
def list_reports(limit: int = 50):
    return get_history(limit)


@router.get("/{report_id}")
def get_report(report_id: str):
    report = get_report_by_id(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    return report
