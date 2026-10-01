from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.api.auth import require_soc_user
from app.models.persistence import AppSetting, as_utc
from app.services.scheduler import configuration, execute

router = APIRouter()
class ScheduleUpdate(BaseModel):
    enabled: bool
    entity: str = ''

@router.get('')
@router.get('/')
def schedules(db: Session = Depends(get_db)):
    return {'schedules':[configuration(db)]}

@router.put('')
def update(request: ScheduleUpdate, db: Session = Depends(get_db)):
    value = {**configuration(db),**request.model_dump()}
    record = db.get(AppSetting,'schedule')
    if record:
        record.value = value
    else:
        db.add(AppSetting(key='schedule',value=value))
    db.commit()
    return value

@router.post('/run')
def run_now(db: Session = Depends(get_db), user=Depends(require_soc_user)):
    run = execute(db,user.username)
    return {'execution_id':run.id,'report_id':run.report_id,'status':run.status,'started_at':as_utc(run.started_at),'completed_at':as_utc(run.completed_at)}
