from pathlib import Path
from collections import Counter
from fastapi import HTTPException
from sqlalchemy import func
from app.core.config import OUTPUT_DIR
from app.models.event import Event
from app.models.persistence import Report, Correlation, CorrelationEvent, as_utc
from app.services.reporting import ReportData, generate_report_files
from app.services.audit import audit

def safe_path(path):
    root = OUTPUT_DIR.resolve()
    target = Path(path).resolve()
    if not target.is_relative_to(root):
        raise HTTPException(400, 'Ruta de reporte fuera de output')
    return target

def generate(db, username, entity='', analyst='', report_type='ejecutivo', start=None, end=None):
    query = db.query(Event)
    if start is not None:
        query = query.filter(Event.timestamp >= start)
    if end is not None:
        query = query.filter(Event.timestamp < end)
    events = query.order_by(Event.timestamp).all()
    counts = {s: sum(e.severity == s for e in events) for s in ['Critical','High','Medium','Low']}
    timestamps = [e.timestamp for e in events if e.timestamp]
    period = f'{start or min(timestamps)} - {end or max(timestamps)} UTC' if timestamps else 'Sin eventos en el período'
    risk = round(sum(e.risk_score or 0 for e in events)/len(events), 1) if events else 0
    data = ReportData(header='Reporte SOC', analyst=analyst or username, entity=entity or 'No especificada',
        period=period, report_type=report_type, total_events=len(events), critical=counts['Critical'],
        high=counts['High'], medium=counts['Medium'], low=counts['Low'], risk_score=risk,
            severity_counts=counts, events=[{c.name: (getattr(e,c.name).isoformat() if hasattr(getattr(e,c.name), 'isoformat') else getattr(e,c.name)) for c in Event.__table__.columns} for e in events])
    data.agents_affected = len({e.agent for e in events if e.agent})
    data.hosts_affected = len({e.hostname for e in events if e.hostname})
    data.top_agents = [{'agent':k,'count':v} for k,v in Counter(e.agent for e in events if e.agent).most_common()]
    data.observed_ips = sorted({ip for e in events for ip in [e.source_ip,e.destination_ip] if ip})
    data.mitre_tactics = dict(Counter(e.mitre_tactic for e in events if e.mitre_tactic))
    data.timeline = [{'timestamp':e.timestamp.isoformat(),'severity':e.severity,'host':e.hostname,'description':e.rule_description} for e in events[-200:] if e.timestamp]
    correlations = db.query(Correlation).join(CorrelationEvent, CorrelationEvent.correlation_id == Correlation.id).join(Event, Event.id == CorrelationEvent.event_id)
    if start is not None:
        correlations = correlations.filter(Event.timestamp >= start)
    if end is not None:
        correlations = correlations.filter(Event.timestamp < end)
    data.correlations = [{'id':c.id,'title':c.title,'risk':c.risk,'evidence':c.evidence} for c in correlations.distinct()]
    data.findings = [f'{data.critical} eventos críticos', f'{data.high} eventos de alta severidad', f'{len(data.correlations)} correlaciones con evidencia persistida']
    data.recommendations = ['Validar las detecciones y su contexto con los responsables de los activos.', 'Documentar la evidencia y las acciones de investigación.']
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    result = generate_report_files(data, OUTPUT_DIR)
    files = result['files']
    record = Report(report_id=result['report_id'], analyst=data.analyst, entity=data.entity,
        period=period, total_events=len(events), critical=data.critical, high=data.high, medium=data.medium,
        low=data.low, risk_score=risk, status='ready', created_by=username,
        **{fmt+'_path': str(safe_path(files[fmt])) for fmt in ['pdf','txt','json']})
    db.add(record)
    audit(db, username, 'REPORT_GENERATE', report_id=record.report_id)
    db.flush()
    return record

def serialize_report(record):
    data = {c.name: as_utc(getattr(record,c.name)) for c in Report.__table__.columns}
    data.update(id=record.report_id, timestamp=as_utc(record.created_at), file_paths={fmt: f'/api/reports/download/{fmt}/{record.report_id}'
        for fmt in ['pdf','txt','json'] if getattr(record,fmt+'_path') and safe_path(getattr(record,fmt+'_path')).is_file()})
    return data
