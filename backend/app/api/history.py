from typing import Literal
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.persistence import ImportBatch, Report, SchedulerRun, AuditLog, as_utc
from app.services.report_store import serialize_report

router = APIRouter()
@router.get('')
@router.get('/')
def history(type: Literal['import','report','scheduler','audit'] = 'import',
            page: int = Query(1,ge=1), limit: int = Query(50,ge=1,le=200), db: Session = Depends(get_db)):
    model, date = {'import':(ImportBatch,ImportBatch.started_at),'report':(Report,Report.created_at),
                   'scheduler':(SchedulerRun,SchedulerRun.started_at),'audit':(AuditLog,AuditLog.timestamp)}[type]
    query = db.query(model)
    items = []
    for record in query.order_by(date.desc()).offset((page-1)*limit).limit(limit):
        item = serialize_report(record) if type == 'report' else {c.name:as_utc(getattr(record,c.name)) for c in model.__table__.columns}
        item['type'] = type
        items.append(item)
    return {'items':items,'total':query.count(),'page':page,'limit':limit}
