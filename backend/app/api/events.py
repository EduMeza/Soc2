from datetime import datetime, timezone
from typing import Literal
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.config import settings
from app.models.event import Event
from app.models.persistence import ImportBatch, Correlation, CorrelationEvent, now
from app.api.auth import require_soc_user
from app.services.csv_parser import parse_csv
from app.services.risk import calculate_event_risk
from app.services.correlation import persist_correlations
from app.services.audit import audit
from app.services.mitre import classify_with_evidence

router = APIRouter()

def serialize(event):
    return {c.name: (getattr(event,c.name).replace(tzinfo=timezone.utc).isoformat() if isinstance(getattr(event,c.name),datetime)
                    else getattr(event,c.name)) for c in Event.__table__.columns}

@router.post('/import')
async def import_csv(file: UploadFile = File(...), db: Session = Depends(get_db), user=Depends(require_soc_user)):
    if not file.filename or not file.filename.lower().endswith('.csv'):
        raise HTTPException(400, 'El archivo debe ser CSV')
    content = await file.read(settings.MAX_UPLOAD_MB * 1024 * 1024 + 1)
    try:
        normalized, columns, warnings, rejected, total = parse_csv(content, settings.MAX_UPLOAD_MB, settings.MAX_ROWS)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    batch = ImportBatch(filename=file.filename, file_size=len(content), total_rows=total,
        warnings=warnings, rejected=rejected, detected_columns=columns, username=user.username,
        inserted=0, duplicates=0)
    db.add(batch)
    db.flush()
    fingerprints = [e.event_fingerprint for e in normalized]
    known = set()
    for start in range(0, len(fingerprints), 500):
        known.update(x[0] for x in db.query(Event.event_fingerprint).filter(Event.event_fingerprint.in_(fingerprints[start:start+500])))
    inserted_events = []
    for item in normalized:
        if item.event_fingerprint in known:
            batch.duplicates += 1
            continue
        known.add(item.event_fingerprint)
        values = item.model_dump()
        evidence = classify_with_evidence(values)
        values['mitre_evidence'] = evidence
        risk, factors = calculate_event_risk(values)
        event = Event(**values, import_batch_id=batch.id, risk_score=risk, risk_factors=factors,
                      mitre_tactic='; '.join(dict.fromkeys(e['tactic'] for e in evidence)),
                      mitre_technique='; '.join(dict.fromkeys(e['technique'] for e in evidence)), correlation_id='')
        db.add(event)
        inserted_events.append(event)
        batch.inserted += 1
    db.flush()
    persist_correlations(db, inserted_events)
    batch.status = 'completed'
    batch.completed_at = now()
    audit(db, user.username, 'CSV_IMPORT', filename=file.filename, batch_id=batch.id)
    db.commit()
    return {'message': 'Importación completa', 'batch_id': batch.id, 'inserted': batch.inserted,
            'duplicates': batch.duplicates, 'rejected': rejected, 'total_rows': total,
            'warnings': warnings, 'detected_columns': columns}

SORT_FIELDS = {'id', 'timestamp', 'severity', 'hostname', 'agent', 'rule_id', 'risk_score', 'source_ip', 'destination_ip'}

@router.get('')
@router.get('/')
def list_events(page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=200),
                search: str = '', severity: str = '', host: str = '', agent: str = '',
                source_ip: str = '', rule: str = '', mitre: str = '', min_risk: float = Query(0,ge=0,le=100),
                start_date: str = '', end_date: str = '', sort_by: str = 'id',
                sort_order: Literal['asc','desc'] = 'desc', db: Session = Depends(get_db)):
    if sort_by not in SORT_FIELDS:
        raise HTTPException(422, 'sort_by inválido')
    query = db.query(Event)
    if search:
        query = query.filter(or_(*(getattr(Event, k).ilike('%' + search + '%') for k in
            ['rule_description','rule_id','hostname','agent','source_ip','destination_ip','process','cve'])))
    for column, value in [(Event.hostname, host), (Event.agent, agent), (Event.source_ip, source_ip), (Event.rule_id, rule)]:
        if value:
            query = query.filter(column.ilike('%' + value + '%'))
    if severity:
        query = query.filter(Event.severity == severity)
    if mitre:
        query = query.filter(or_(Event.mitre_tactic.ilike('%'+mitre+'%'), Event.mitre_technique.ilike('%'+mitre+'%')))
    query = query.filter(Event.risk_score >= min_risk)
    try:
        if start_date:
            query = query.filter(Event.timestamp >= datetime.fromisoformat(start_date.replace('Z','+00:00')))
        if end_date:
            query = query.filter(Event.timestamp <= datetime.fromisoformat(end_date.replace('Z','+00:00')))
    except ValueError:
        raise HTTPException(422, 'Fecha inválida')
    total = query.count()
    column = getattr(Event, sort_by)
    query = query.order_by(column.asc() if sort_order == 'asc' else column.desc(), Event.id)
    return {'items': [serialize(e) for e in query.offset((page-1)*limit).limit(limit)], 'total':total, 'page':page, 'limit':limit}

@router.get('/{event_id}')
def event_detail(event_id: int, db: Session = Depends(get_db)):
    event = db.get(Event, event_id)
    if not event:
        raise HTTPException(404, 'Evento no encontrado')
    result = serialize(event)
    result['correlations'] = [{'id':c.id,'title':c.title,'evidence':c.evidence} for c in db.query(Correlation)
        .join(CorrelationEvent,CorrelationEvent.correlation_id == Correlation.id).filter(CorrelationEvent.event_id == event.id)]
    return result
