from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.auth import require_soc_user
from app.models.persistence import Report
from app.services.report_store import generate, safe_path, serialize_report
from app.services.audit import audit

router = APIRouter()
class GenerateReportRequest(BaseModel):
    entity: str = ''
    analyst: str = ''
    report_type: str = 'ejecutivo'

@router.post('/generate')
def generate_report(request: GenerateReportRequest, db: Session = Depends(get_db), user=Depends(require_soc_user)):
    record = generate(db, user.username, **request.model_dump())
    db.commit()
    return {'status':'success', 'message':'Reporte generado', 'report_id':record.report_id,
            'files':serialize_report(record)['file_paths']}

@router.get('/download/{format}/{report_id}')
def download_report(format: Literal['pdf','txt','json'], report_id: str, db: Session = Depends(get_db), user=Depends(require_soc_user)):
    record = db.get(Report,report_id)
    if not record or not getattr(record, format+'_path'):
        raise HTTPException(404, 'Reporte no encontrado')
    path = safe_path(getattr(record,format+'_path'))
    if not path.is_file():
        raise HTTPException(404, 'Archivo no encontrado')
    audit(db,user.username,'REPORT_DOWNLOAD',report_id=report_id,format=format)
    db.commit()
    return FileResponse(path, media_type={'pdf':'application/pdf','txt':'text/plain','json':'application/json'}[format], filename=path.name)

@router.get('')
@router.get('/')
def list_reports(limit: int = Query(50,ge=1,le=200), db: Session = Depends(get_db)):
    return [serialize_report(r) for r in db.query(Report).order_by(Report.created_at.desc()).limit(limit)]

@router.get('/{report_id}')
def get_report(report_id: str, db: Session = Depends(get_db)):
    record = db.get(Report,report_id)
    if not record:
        raise HTTPException(404,'Reporte no encontrado')
    return serialize_report(record)
