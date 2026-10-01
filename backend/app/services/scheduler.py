from datetime import datetime, time, timezone
from zoneinfo import ZoneInfo
from threading import Thread, Event as StopEvent
from sqlalchemy.exc import IntegrityError
from app.core.config import settings
from app.models.persistence import AppSetting, SchedulerRun, now, uid
from app.services.report_store import generate
from app.services.audit import audit

SHIFTS = {'07:00':(0,7),'16:00':(7,16),'23:00':(16,23)}

def period_for(day, shift):
    start,end = SHIFTS[shift]
    zone = ZoneInfo(settings.TIMEZONE)
    return tuple(datetime.combine(day,time(hour=h),zone).astimezone(timezone.utc).replace(tzinfo=None) for h in [start,end])

def resolve_shift(moment):
    local = moment.astimezone(ZoneInfo(settings.TIMEZONE))
    return next((shift for shift in SHIFTS if local.hour == int(shift[:2]) and local.minute < 5),None)

def configuration(db):
    record = db.get(AppSetting,'schedule')
    return record.value if record else {'enabled':False,'timezone':settings.TIMEZONE,'times':list(SHIFTS),'entity':''}

def execute(db, username, moment=None, shift=None):
    moment = moment or datetime.now(timezone.utc)
    local = moment.astimezone(ZoneInfo(settings.TIMEZONE))
    manual = shift is None
    if manual:
        shift = max((s for s in SHIFTS if int(s[:2]) <= local.hour),default='07:00')
    logical_shift = 'manual-'+uid() if manual else shift
    run = SchedulerRun(date=local.date().isoformat(),shift=logical_shift,status='running')
    db.add(run)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        return db.query(SchedulerRun).filter_by(date=local.date().isoformat(),shift=logical_shift).one()
    try:
        start,end = period_for(local.date(),shift)
        report = generate(db,username,entity=configuration(db).get('entity',''),start=start,end=end)
        run.report_id = report.report_id
        run.status = 'completed'
    except Exception:
        db.rollback()
        run = db.get(SchedulerRun,run.id)
        run.status = 'failed'
        raise
    finally:
        run.completed_at = now()
        audit(db,username,'SCHEDULER_RUN',run.status,execution_id=run.id)
        db.commit()
    return run

def start_scheduler(factory):
    stop = StopEvent()
    def loop():
        while not stop.is_set():
            with factory() as db:
                config = configuration(db)
                moment = datetime.now(timezone.utc)
                shift = resolve_shift(moment)
                if config.get('enabled') and shift:
                    try:
                        execute(db,'scheduler',moment,shift)
                    except Exception:
                        import logging
                        logging.getLogger(__name__).exception('Scheduler report failed')
            stop.wait(30)
    thread = Thread(target=loop,daemon=True)
    thread.start()
    return stop,thread
