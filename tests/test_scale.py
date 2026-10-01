"""Aggregation correctness at the requested 200,000-event scale."""
from datetime import datetime
from time import perf_counter
from sqlalchemy import insert
from app.models.event import Event

def test_aggregations_200000(authenticated):
    client,factory = authenticated
    with factory() as db:
        for start in range(0,200000,5000):
            db.execute(insert(Event),[{
                'timestamp':datetime(2026,9,14,12), 'event_fingerprint':str(i),
                'hostname':f'host-{i%100}', 'agent':f'agent-{i%100}', 'rule_id':str(i%20),
                'severity':['Critical','High','Medium','Low'][i%4], 'risk_score':50,
                'source_ip':'8.8.8.8' if i%2 else '10.0.0.1', 'destination_ip':'1.1.1.1',
                'rule_description':'Scale fixture', 'cve':''
            } for i in range(start,start+5000)])
        db.commit()
    started = perf_counter()
    response = client.get('/api/analytics/summary')
    assert response.status_code == 200
    summary = response.json()
    assert summary['total_events'] == 200000
    assert [summary[k] for k in ['critical','high','medium','low']] == [50000]*4
    assert summary['hosts'] == summary['agents'] == 100
    assert summary['rules'] == 20 and summary['overall_risk'] == 50
    assert sum(client.get('/api/analytics/severity').json().values()) == 200000
    for endpoint in ['agents','hosts','rules']:
        rows = client.get('/api/analytics/'+endpoint+'?limit=200').json()
        assert sum(r['count'] for r in rows) == 200000
    ips = client.get('/api/analytics/ips').json()
    assert sum(r['source_count'] for r in ips) == 200000
    assert sum(r['destination_count'] for r in ips) == 200000
    print(f'200000 events: summary/severity/agents/hosts/rules/ips {perf_counter()-started:.3f}s')
