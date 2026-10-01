import csv
import io
import json
from pathlib import Path
from datetime import datetime, timezone, timedelta
import pytest
from jose import jwt
from app.core import security
from app.models.event import Event
from app.models.persistence import ImportBatch, Report, Correlation, CorrelationEvent
from app.services.csv_parser import parse_csv

ROOT = Path(__file__).resolve().parents[1]

@pytest.mark.parametrize('encoding',['utf-8','utf-8-sig','latin-1'])
@pytest.mark.parametrize('delimiter',[',',';','\t','|'])
def test_csv_encodings(encoding,delimiter):
    text = io.StringIO()
    writer = csv.writer(text,delimiter=delimiter)
    writer.writerow(['timestamp','Host','Severidad','Descripcion'])
    writer.writerow(['2026-09-14 01:00:00','host','Crítico','Descripción válida'])
    events,_,warnings,rejected,total = parse_csv(text.getvalue().encode(encoding))
    assert total == 1 and rejected == 0 and len(events) == 1
    assert events[0].severity == 'Critical'
    assert events[0].rule_description == 'Descripción válida'

def test_invalid_evidence():
    events,_,warnings,rejected,total = parse_csv(b'timestamp,source_ip\nbad,anything.com\n2026-09-14T00:00:00Z,not.an.ip\n')
    assert total == 2 and rejected == 1 and len(events) == 1
    assert events[0].source_ip == '' and 'not.an.ip' in events[0].raw_event
    assert len(warnings) == 2

@pytest.mark.parametrize('path',['events','analytics/summary','geoip','history','schedules','reports'])
def test_security(context,path):
    client,_,username,_ = context
    assert client.get('/api/'+path).status_code == 401
    assert client.get('/api/'+path,headers={'Authorization':'Bearer invalid'}).status_code == 401
    token = jwt.encode({'sub':username,'version':0,'exp':datetime.now(timezone.utc)-timedelta(seconds=2)},security.SECRET_KEY,algorithm='HS256')
    assert client.get('/api/'+path,headers={'Authorization':'Bearer '+token}).status_code == 401

@pytest.mark.parametrize('filename',['sample_events_1.csv','sample_events_2.csv'])
def test_import_and_duplicates(authenticated,filename):
    client,factory = authenticated
    content = (ROOT/'data'/filename).read_bytes()
    response = client.post('/api/events/import',files={'file':(filename,content,'text/csv')})
    assert response.status_code == 200,response.text
    result = response.json()
    assert result['inserted']+result['duplicates']+result['rejected'] == result['total_rows']
    assert result['inserted'] > 0 and result['rejected'] == 0
    summary = client.get('/api/analytics/summary').json()
    assert summary['total_events'] == result['inserted']
    assert summary['hosts'] > 0 and summary['agents'] > 0 and summary['rules'] > 0
    assert summary['high'] + summary['critical'] > 0
    with factory() as db:
        assert db.query(Event).filter(Event.risk_score > 0).count() > 0
        assert not db.query(Event).filter((Event.risk_score < 0)|(Event.risk_score > 100)).count()
        assert db.query(ImportBatch).count() == 1
        if filename == 'sample_events_2.csv':
            assert db.query(Event).filter(Event.process != '').count() > 0
            assert 'GeoLocation.country_name' in db.query(Event).first().raw_event
    second = client.post('/api/events/import',files={'file':(filename,content)}).json()
    assert second['inserted'] == 0 and second['duplicates'] > 0
    assert client.get('/api/analytics/summary').json()['total_events'] == result['inserted']
    print(filename, result['total_rows'],result['inserted'],result['duplicates'],result['rejected'])

def test_e2e(authenticated):
    client,factory = authenticated
    response = client.post('/api/events/import',files={'file':('events.csv',(ROOT/'data/sample_events_1.csv').read_bytes())})
    assert response.status_code == 200
    total = response.json()['inserted']
    assert client.get('/api/analytics/summary').json()['total_events'] == total
    events = client.get('/api/events').json()
    assert events['total'] == total
    detail = client.get('/api/events/'+str(events['items'][0]['id'])).json()
    assert 'raw_event' in detail and 'risk_factors' in detail
    for endpoint in ['risk','correlations','attack-sequences','mitre','graph','timeline']:
        response = client.get('/api/analytics/'+endpoint)
        assert response.status_code == 200,response.text
    assert client.get('/api/analytics/risk').json()['overall_risk'] > 0
    graph = client.get('/api/analytics/graph').json()
    assert graph['nodes'] and graph['edges']
    ids = {node['id'] for node in graph['nodes']}
    assert all(edge['source'] in ids and edge['target'] in ids for edge in graph['edges'])
    assert client.get('/api/analytics/mitre').json()['techniques']
    assert client.get('/api/geoip').status_code == 200
    assert client.get('/api/history?type=import').json()['total'] == 1
    generated = client.post('/api/reports/generate',json={'entity':'Test entity'})
    assert generated.status_code == 200,generated.text
    report_id = generated.json()['report_id']
    with factory() as db:
        record = db.get(Report,report_id)
        assert record.total_events == total
        assert all(Path(getattr(record,f+'_path')).is_file() for f in ['pdf','txt','json'])
    for fmt in ['pdf','txt','json']:
        download = client.get(f'/api/reports/download/{fmt}/{report_id}')
        assert download.status_code == 200 and len(download.content) > 0
        if fmt == 'pdf': assert download.content.startswith(b'%PDF')
        if fmt == 'json': assert download.json()['total_events'] == total
    assert client.get('/api/history?type=report').json()['items'][0]['report_id'] == report_id
    assert client.post('/api/auth/logout').status_code == 200
    assert client.get('/api/events').status_code == 401

def test_correlation(authenticated):
    client,factory = authenticated
    content = b'timestamp,host,rule_id,source_ip,severity\n2026-09-14T01:00:00Z,host,123,8.8.8.8,High\n2026-09-14T01:01:00Z,host,123,8.8.8.8,High\n'
    assert client.post('/api/events/import',files={'file':('correlation.csv',content)}).status_code == 200
    with factory() as db:
        record = db.query(Correlation).one()
        correlation_id = record.id
        assert db.query(CorrelationEvent).count() == 2
        assert 'same_source_ip: 8.8.8.8' in record.evidence
    assert client.get('/api/analytics/correlations').json()[0]['id'] == correlation_id
    assert client.get('/api/analytics/attack-sequences').json() == {'sequences':[]}

def test_evidence_sequence(authenticated):
    client,factory = authenticated
    text = 'timestamp,host,rule_id,source_ip,severity,username,description\n'
    for minute in range(4):
        description = 'Failed login' if minute < 3 else 'Successful login'
        text += f'2026-09-14T01:0{minute}:00Z,host,{minute},8.8.8.8,High,user,{description}\n'
    result = client.post('/api/events/import',files={'file':('sequence.csv',text.encode())})
    assert result.status_code == 200
    sequences = client.get('/api/analytics/attack-sequences').json()['sequences']
    assert len(sequences) == 1 and len(sequences[0]['events']) == 4
    with factory() as db:
        assert db.get(Correlation,sequences[0]['correlation_id']) is not None

def test_ips_and_search(authenticated):
    client,_ = authenticated
    text = b'timestamp,host,rule_id,source_ip,destination_ip,description\n2026-09-14T00:00:00Z,server,rule,8.8.8.8,1.1.1.1,evidence\n2026-09-14T00:01:00Z,server,rule,1.1.1.1,8.8.8.8,evidence\n'
    assert client.post('/api/events/import',files={'file':('ip.csv',text)}).status_code == 200
    ips = client.get('/api/analytics/ips').json()
    assert len(ips) == 2
    assert all(r['source_count'] == 1 and r['destination_count'] == 1 and r['total_count'] == 2 for r in ips)
    assert client.get('/api/events?search=evidence').json()['total'] == 2
    assert client.get('/api/events?search=missing').json()['total'] == 0

def test_mitre_evidence():
    from app.services.mitre import classify_with_evidence
    assert classify_with_evidence({'rule_description':'normal service started'}) == []
    result = classify_with_evidence({'command':'powershell.exe -enc AAAA'})
    assert result[0]['technique'] == 'T1059.001' and result[0]['evidence']

@pytest.mark.parametrize('ip',['127.0.0.1','10.0.0.1','169.254.1.1','224.0.0.1','::1','fc00::1','203.0.113.1','not.an.ip'])
def test_geo_exclusions(ip):
    from app.services.geoip import is_public, resolve_geoip
    assert not is_public(ip)
    assert resolve_geoip(ip)['latitude'] is None
