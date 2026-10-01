import secrets
from datetime import datetime, date, timezone
from zoneinfo import ZoneInfo
import pytest
from app.models.user import User
from app.models.persistence import AuditLog, SchedulerRun, Report
from app.api.auth import bootstrap
from app.core.config import settings
from app.services.scheduler import resolve_shift, period_for, execute

def test_bootstrap_password_gate(context,monkeypatch):
    client,factory,_,_ = context
    username,password = 'bootstrap_'+secrets.token_hex(5),secrets.token_urlsafe(18)
    monkeypatch.setattr(settings,'INITIAL_ADMIN_USERNAME',username)
    monkeypatch.setattr(settings,'INITIAL_ADMIN_PASSWORD',password)
    with factory() as db:
        db.query(User).delete()
        db.commit()
        bootstrap(db)
        assert db.query(User).one().force_password_change is True
        bootstrap(db)
        assert db.query(User).count() == 1
    response = client.post('/api/auth/login',json={'username':username,'password':password})
    assert response.json()['force_change'] is True
    client.headers['Authorization'] = 'Bearer '+response.json()['access_token']
    assert client.get('/api/events').status_code == 403
    assert client.post('/api/auth/change-password',json={'current_password':password,'new_password':'short'}).status_code == 422
    new_password = secrets.token_urlsafe(20)
    response = client.post('/api/auth/change-password',json={'current_password':password,'new_password':new_password})
    assert response.status_code == 200
    assert client.get('/api/events').status_code == 401
    client.headers['Authorization'] = 'Bearer '+response.json()['access_token']
    assert client.get('/api/events').status_code == 200
    assert client.get('/api/auth/me').json()['force_change'] is False

def test_rate_limit_and_audit(context):
    client,factory,username,_ = context
    wrong = secrets.token_urlsafe(20)
    for _ in range(5):
        assert client.post('/api/auth/login',json={'username':username,'password':wrong}).status_code == 401
    assert client.post('/api/auth/login',json={'username':username,'password':wrong}).status_code == 429
    with factory() as db:
        assert db.query(AuditLog).filter_by(action='LOGIN_FAILURE').count() == 5
        assert wrong not in str([a.details for a in db.query(AuditLog)])

@pytest.mark.parametrize('shift,start,end',[('07:00',0,7),('16:00',7,16),('23:00',16,23)])
def test_periods(shift,start,end):
    zone = ZoneInfo('America/Asuncion')
    moment = datetime(2026,9,14,int(shift[:2]),2,tzinfo=zone)
    assert resolve_shift(moment.astimezone(timezone.utc)) == shift
    assert resolve_shift(moment.replace(minute=6)) is None
    first,last = period_for(date(2026,9,14),shift)
    assert first.replace(tzinfo=timezone.utc).astimezone(zone).hour == start
    assert last.replace(tzinfo=timezone.utc).astimezone(zone).hour == end

def test_scheduler_real_and_unique(authenticated):
    client,factory = authenticated
    assert client.put('/api/schedules',json={'enabled':True,'entity':'test'}).status_code == 200
    assert client.get('/api/schedules').json()['schedules'][0]['enabled'] is True
    moment = datetime(2026,9,14,7,0,tzinfo=ZoneInfo('America/Asuncion'))
    with factory() as db:
        first = execute(db,'test',moment,'07:00')
        second = execute(db,'test',moment,'07:00')
        assert first.id == second.id
        assert db.query(SchedulerRun).count() == 1
        assert db.query(Report).count() == 1
        assert first.report_id and first.status == 'completed'
    response = client.post('/api/schedules/run')
    assert response.status_code == 200,response.text
    assert response.json()['report_id'] and response.json()['execution_id'] != 'exec-1'

@pytest.mark.parametrize('path',['events','analytics/summary','geoip','history','schedules','reports'])
def test_authorized(authenticated,path):
    client,_ = authenticated
    assert client.get('/api/'+path).status_code == 200

def test_path_traversal(authenticated):
    client,factory = authenticated
    with factory() as db:
        db.add(Report(report_id='escape',pdf_path='../private.pdf'))
        db.commit()
    assert client.get('/api/reports/download/pdf/escape').status_code == 400

@pytest.mark.parametrize('query',['page=0','limit=0','limit=201','sort_by=__table__','sort_order=anything'])
def test_pagination(authenticated,query):
    assert authenticated[0].get('/api/events?'+query).status_code == 422
