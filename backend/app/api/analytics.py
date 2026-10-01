import ipaddress
from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, union_all, literal
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.event import Event
from app.models.persistence import Correlation, CorrelationEvent, as_utc

router = APIRouter()

def counts(db, column):
    return dict(db.query(column,func.count(Event.id)).group_by(column).all())

def ip_rows(db):
    sources = select(Event.source_ip.label('ip'), literal(1).label('src'), literal(0).label('dst'), Event.timestamp.label('ts'))
    destinations = select(Event.destination_ip.label('ip'), literal(0).label('src'), literal(1).label('dst'), Event.timestamp.label('ts'))
    ips = union_all(sources,destinations).subquery()
    rows = db.query(ips.c.ip,func.sum(ips.c.src),func.sum(ips.c.dst),func.min(ips.c.ts),func.max(ips.c.ts)).filter(ips.c.ip != '').group_by(ips.c.ip).all()
    result = []
    for ip, src, dst, first, last in rows:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            continue
        result.append(dict(ip=ip,source_count=src,destination_count=dst,total_count=src+dst,count=src+dst,
                           public=address.is_global,private=address.is_private,first_seen=as_utc(first),last_seen=as_utc(last)))
    return sorted(result,key=lambda r:r['total_count'],reverse=True)

@router.get('/summary')
def summary(db: Session = Depends(get_db)):
    severity = counts(db,Event.severity)
    ips = ip_rows(db)
    distinct = lambda col: db.query(func.count(func.distinct(col))).filter(col != '').scalar()
    return dict(total_events=sum(severity.values()),critical=severity.get('Critical',0),high=severity.get('High',0),
        medium=severity.get('Medium',0),low=severity.get('Low',0),info=severity.get('Info',0)+severity.get('Unknown',0),
        agents=distinct(Event.agent),hosts=distinct(Event.hostname),rules=distinct(Event.rule_id),cves=distinct(Event.cve),
        correlations=db.query(Correlation).count(),external_ips=sum(r['public'] for r in ips),
        internal_ips=sum(r['private'] for r in ips),overall_risk=round(db.query(func.avg(Event.risk_score)).scalar() or 0,1))

@router.get('/severity')
def severity(db: Session = Depends(get_db)):
    return counts(db,Event.severity)

def top(db,column,key,limit):
    return [{key:value,'count':n} for value,n in db.query(column,func.count(Event.id)).filter(column != '').group_by(column).order_by(func.count(Event.id).desc()).limit(limit)]

@router.get('/agents')
def agents(limit: int = Query(10,ge=1,le=200), db: Session = Depends(get_db)):
    return top(db,Event.agent,'agent',limit)

@router.get('/hosts')
def hosts(limit: int = Query(10,ge=1,le=200), db: Session = Depends(get_db)):
    return top(db,func.coalesce(func.nullif(Event.hostname,''),Event.agent),'host',limit)

@router.get('/rules')
def rules(limit: int = Query(10,ge=1,le=200), db: Session = Depends(get_db)):
    return top(db,Event.rule_id,'rule',limit)

@router.get('/ips')
def ips(limit: int = Query(10,ge=1,le=200), db: Session = Depends(get_db)):
    return ip_rows(db)[:limit]

@router.get('/risk')
def risk(db: Session = Depends(get_db)):
    return {'overall_risk':round(db.query(func.avg(Event.risk_score)).scalar() or 0,1),
            'per_agent':dict(db.query(Event.agent,func.avg(Event.risk_score)).group_by(Event.agent).all()),
            'per_host':dict(db.query(Event.hostname,func.avg(Event.risk_score)).group_by(Event.hostname).all()),
            'factors':{'total_events':db.query(Event).count()}}

@router.get('/mitre')
def mitre(db: Session = Depends(get_db)):
    return {'tactics':[{'tactic':k,'count':v} for k,v in counts(db,Event.mitre_tactic).items() if k],
            'techniques':[{'technique':k,'count':v} for k,v in counts(db,Event.mitre_technique).items() if k]}

@router.get('/correlations')
def correlations(db: Session = Depends(get_db)):
    output = []
    for c in db.query(Correlation).order_by(Correlation.last_seen.desc()).limit(200):
        events = db.query(Event).join(CorrelationEvent,CorrelationEvent.event_id == Event.id).filter(CorrelationEvent.correlation_id == c.id).all()
        output.append(dict(id=c.id,title=c.title,severity=c.severity,risk=c.risk,support_score=c.support_score,
            confidence=c.support_score,first_seen=as_utc(c.first_seen),last_seen=as_utc(c.last_seen),evidence=c.evidence,
            events=len(events),event_ids=[e.id for e in events],hosts=sorted({e.hostname for e in events if e.hostname}),
            agents=sorted({e.agent for e in events if e.agent}),ips=sorted({e.source_ip for e in events if e.source_ip})))
    return output

@router.get('/attack-sequences')
def attack_sequences(db: Session = Depends(get_db)):
    # Shared IP/host/rule alone does not prove an ordered attack sequence.
    sequences = []
    for c in db.query(Correlation).all():
        if not any(e.startswith(('authentication_sequence','suspicious_process_sequence')) for e in c.evidence):
            continue
        events = db.query(Event).join(CorrelationEvent,CorrelationEvent.event_id == Event.id).filter(CorrelationEvent.correlation_id == c.id).order_by(Event.timestamp).all()
        sequences.append({'correlation_id':c.id,'evidence':c.evidence,'events':[{'id':e.id,'timestamp':as_utc(e.timestamp),'description':e.rule_description} for e in events]})
    return {'sequences':sequences}

@router.get('/timeline')
def timeline(limit: int = Query(100,ge=1,le=200), db: Session = Depends(get_db)):
    return [dict(id=e.id,timestamp=as_utc(e.timestamp),severity=e.severity,host=e.hostname,agent=e.agent,
        source_ip=e.source_ip,rule=e.rule_id,description=e.rule_description,mitre_tactic=e.mitre_tactic,
        mitre_technique=e.mitre_technique,correlation_id=e.correlation_id) for e in
        reversed(db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all())]

@router.get('/iocs')
def iocs(db: Session = Depends(get_db)):
    return {'ips':[r['ip'] for r in ip_rows(db)]}

@router.get('/graph')
def graph(db: Session = Depends(get_db)):
    nodes, edges = {}, {}
    for e in db.query(Event).order_by(Event.timestamp.desc()).limit(200):
        entities = [('event',str(e.id),e.rule_description or str(e.id)),('host',e.hostname or e.agent,e.hostname or e.agent),
                    ('ip',e.source_ip,e.source_ip),('ip',e.destination_ip,e.destination_ip),('rule',e.rule_id,e.rule_id),
                    ('mitre',e.mitre_tactic,e.mitre_tactic),('cve',e.cve,e.cve)]
        for kind,key,label in entities:
            if not key:
                continue
            node_id = kind+'-'+key
            nodes[node_id] = {'id':node_id,'type':kind,'position':{'x':0,'y':0},'data':{'label':label,'type':kind,'severity':e.severity}}
            if kind != 'event':
                edge_id = f'event-{e.id}-{node_id}'
                edges[edge_id] = {'id':edge_id,'source':f'event-{e.id}','target':node_id,'data':{'relationship':kind}}
    return {'nodes':list(nodes.values()),'edges':list(edges.values())}
