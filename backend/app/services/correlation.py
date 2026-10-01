"""Evidence-bearing correlations, created once during ingestion."""
import re
from collections import defaultdict
from app.models.persistence import Correlation, CorrelationEvent

def windows(members, seconds=3600):
    result = []
    for event in sorted(members,key=lambda e:e.timestamp):
        if not result or (event.timestamp-result[-1][0].timestamp).total_seconds() > seconds:
            result.append([])
        result[-1].append(event)
    return result

def store(db, members, title, evidence, repeated=False):
    strongest = max(members,key=lambda e:e.risk_score)
    record = Correlation(title=title,severity=strongest.severity,risk=strongest.risk_score,support_score=1,
        first_seen=members[0].timestamp,last_seen=members[-1].timestamp,evidence=evidence)
    db.add(record)
    db.flush()
    for event in members:
        db.add(CorrelationEvent(correlation_id=record.id,event_id=event.id))
        event.correlation_id = record.id
        factors = dict(event.risk_factors or {})
        factors['correlation'] = 5
        if repeated:
            factors['frequency'] = min(10,len(members)-1)
        event.risk_factors = factors
        event.risk_score = min(100,sum(factors.values()))
    record.risk = max(e.risk_score for e in members)

def persist_correlations(db, events):
    groups, auth = defaultdict(list), defaultdict(list)
    for event in events:
        host = event.hostname or event.agent
        if event.source_ip and host:
            if event.rule_id:
                groups[(event.source_ip,host,event.rule_id)].append(event)
            if event.username:
                auth[(event.source_ip,host,event.username)].append(event)
    for (ip,host,rule),members in groups.items():
        for window in windows(members):
            if len(window) >= 2:
                store(db,window,f'{rule} / {host} / {ip}',[
                    'same_source_ip: '+ip,'same_host: '+host,'repeated_rule: '+rule,'time_window: 60 minutes'],True)
    for (ip,host,username),members in auth.items():
        for window in windows(members,600):
            failures = []
            for event in window:
                description = event.rule_description or ''
                if re.search(r'failed (?:login|logon)|authentication fail|inicio de sesi[oó]n fallido',description,re.I):
                    failures.append(event)
                elif len(failures) >= 3 and re.search(r'successful (?:login|logon)|authentication success|inicio de sesi[oó]n exitoso',description,re.I):
                    store(db,failures+[event],f'Autenticación repetida seguida de éxito / {host}',[
                        'authentication_sequence: >=3 failures followed by success', 'same_source_ip: '+ip,
                        'same_host: '+host,'same_user: '+username,'time_window: 10 minutes'])
                    failures = []
