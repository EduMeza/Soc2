from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List, Optional
from ..core.database import get_db
from ..models.event import Event
from ..services.analysis import analyze
from ..services.correlation import find_correlations
from ..services.mitre import classify_mitre
from ..services.risk import calculate_risk_score, calculate_agent_risk_scores
from ..services.geoip import resolve_geoip

router = APIRouter(tags=["analytics"])


@router.get("/summary")
def get_summary(db: Session = Depends(get_db)):
    total = db.query(Event).count()
    if total == 0:
        return {
            "total_events": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "agents": 0,
            "hosts": 0,
            "external_ips": 0,
            "internal_ips": 0,
            "rules": 0,
            "cves": 0,
            "correlations": 0,
            "overall_risk": 0.0
        }

    events = db.query(Event).all()
    events_list = [
        {
            "severity": e.severity,
            "agent": e.agent,
            "host": e.hostname,
            "src_ip": e.source_ip,
            "dst_ip": e.destination_ip,
            "rule_id": e.rule_id,
            "description": e.rule_description,
            "cve": e.cve,
            "process": e.process,
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
        }
        for e in events
    ]

    # Usar el motor de análisis
    import pandas as pd
    df = pd.DataFrame(events_list)
    from app.services.analysis import analyze
    result = analyze(df)

    return {
        "total_events": result.total_events,
        "critical": result.critical_count,
        "high": result.high_count,
        "medium": result.severity_counts.get("Medium", 0),
        "low": result.severity_counts.get("Low", 0),
        "info": result.severity_counts.get("Unknown", 0),
        "agents": result.agents_count,
        "hosts": len({e.hostname or e.agent for e in events if e.hostname or e.agent}),
        "external_ips": len(result.external_ips),
        "internal_ips": len(result.internal_ips),
        "rules": len({e.rule_id for e in events if e.rule_id}),
        "cves": len(result.cves),
        "correlations": len(find_correlations(result.df.to_dict("records") if result.df is not None else [])),
        "overall_risk": calculate_risk_score(events_list),
    }


@router.get("/timeline")
def get_timeline(limit: int = 100, db: Session = Depends(get_db)):
    events = db.query(Event).order_by(Event.timestamp.desc()).limit(limit).all()
    return [
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "severity": e.severity,
            "host": e.hostname or e.agent,
            "agent": e.agent,
            "source_ip": e.source_ip,
            "rule": e.rule_id,
            "description": e.rule_description[:100] if e.rule_description else "",
            "mitre_tactic": e.mitre_tactic,
            "mitre_technique": e.mitre_technique,
            "correlation_id": e.correlation_id,
        }
        for e in reversed(events)
    ]


@router.get("/severity")
def get_severity_distribution(db: Session = Depends(get_db)):
    from sqlalchemy import func
    result = db.query(Event.severity, func.count(Event.id)).group_by(Event.severity).all()
    return {severity: count for severity, count in result}


@router.get("/agents")
def get_top_agents(limit: int = 10, db: Session = Depends(get_db)):
    from sqlalchemy import func
    result = db.query(Event.agent, func.count(Event.id)).group_by(Event.agent).order_by(func.count(Event.id).desc()).limit(limit).all()
    return [{"agent": agent, "count": count} for agent, count in result if agent]


@router.get("/hosts")
def get_top_hosts(limit: int = 10, db: Session = Depends(get_db)):
    from sqlalchemy import func
    host = func.coalesce(func.nullif(Event.hostname, ''), Event.agent)
    result = db.query(host, func.count(Event.id)).filter(host != '').group_by(host).order_by(func.count(Event.id).desc()).limit(limit).all()
    return [{"host": host, "count": count} for host, count in result if host]


@router.get("/rules")
def get_top_rules(limit: int = 10, db: Session = Depends(get_db)):
    from sqlalchemy import func
    result = db.query(Event.rule_id, func.count(Event.id)).group_by(Event.rule_id).order_by(func.count(Event.id).desc()).limit(limit).all()
    return [{"rule": rule, "count": count} for rule, count in result if rule]


@router.get("/ips")
def get_top_ips(limit: int = 10, db: Session = Depends(get_db)):
    from sqlalchemy import func
    # Combinar source_ip y destination_ip
    from sqlalchemy import union_all, select
    from sqlalchemy.orm import Session as S
    from ..models.event import Event
    # Simplificado: solo source_ip
    from sqlalchemy import func
    result = db.query(Event.source_ip, func.count(Event.id)).group_by(Event.source_ip).order_by(func.count(Event.id).desc()).limit(limit).all()
    return [{"ip": ip, "count": count} for ip, count in result if ip]


@router.get("/mitre")
def get_mitre_distribution(db: Session = Depends(get_db)):
    # Obtener eventos con datos MITRE
    events = db.query(Event).filter(Event.mitre_tactic != "").all()
    from collections import Counter
    tactics = Counter(e.mitre_tactic for e in events if e.mitre_tactic)
    techniques = Counter(e.mitre_technique for e in events if e.mitre_technique)
    return {
        "tactics": [{"tactic": k, "count": v} for k, v in tactics.items()],
        "techniques": [{"technique": k, "count": v} for k, v in techniques.most_common(20)]
    }


@router.get("/correlations")
def get_correlations(db: Session = Depends(get_db)):
    from ..services.correlation import find_correlations
    events = db.query(Event).all()
    events_list = [
        {
            "timestamp": e.timestamp.isoformat() if e.timestamp else "",
            "src_ip": e.source_ip,
            "host": e.hostname or e.agent,
            "agent": e.agent,
            "rule": e.rule_id,
            "process": e.process,
            "user": e.username,
            "timestamp_raw": e.timestamp.isoformat() if e.timestamp else "",
            "severity": e.severity,
            "id": e.id,
            "description": e.rule_description,
        }
        for e in events
    ]
    correlations = find_correlations(events_list)
    return correlations


@router.get("/risk")
def get_risk_analysis(db: Session = Depends(get_db)):
    from ..services.risk import calculate_risk_score, calculate_agent_risk_scores
    events = db.query(Event).all()
    events_list = [
        {
            "severity": e.severity,
            "agent": e.agent,
            "host": e.hostname or e.agent,
            "source_ip": e.source_ip,
            "rule_id": e.rule_id,
            "process": e.process,
        }
        for e in events
    ]
    overall = calculate_risk_score(
        [{"severity": e.severity} for e in []]  # Se calculará desde BD
    )
    # Calcular desde BD directamente
    from sqlalchemy import func
    critical = db.query(Event).filter(Event.severity == "Critical").count()
    high = db.query(Event).filter(Event.severity == "High").count()
    total = db.query(Event).count()
    overall = calculate_risk_score(events_list)

    agents = db.query(Event.agent, func.count(Event.id)).group_by(Event.agent).all()
    agent_scores = calculate_agent_risk_scores(events_list)

    return {
        "overall_risk": round(overall, 1),
        "per_agent": agent_scores,
        "factors": {
            "critical_events": db.query(Event).filter(Event.severity == "Critical").count(),
            "high_events": db.query(Event).filter(Event.severity == "High").count(),
            "total_events": db.query(Event).count(),
        }
    }


@router.get("/iocs")
def get_iocs(db: Session = Depends(get_db)):
    from sqlalchemy import func
    # Extraer IPs únicas
    from sqlalchemy import distinct
    ips = db.query(Event.source_ip).filter(Event.source_ip != "").distinct().all()
    return {"ips": [ip[0] for ip in ips if ip[0]]}


@router.get("/agents")
def get_agents_analytics(db: Session = Depends(get_db)):
    from sqlalchemy import func
    result = db.query(Event.agent, func.count(Event.id)).group_by(Event.agent).order_by(func.count(Event.id).desc()).all()
    return [{"agent": a, "events": c} for a, c in result if a]


@router.get("/hosts")
def get_hosts_analytics(db: Session = Depends(get_db)):
    from sqlalchemy import func
    result = db.query(Event.hostname, func.count(Event.id)).group_by(Event.hostname).order_by(func.count(Event.id).desc()).all()
    return [{"host": h, "events": c} for h, c in result if h]


@router.get("/graph")
def get_graph(db: Session = Depends(get_db)):
    """Obtener grafo de relaciones: IPs -> Hosts -> Eventos -> Reglas -> MITRE"""
    from sqlalchemy import func
    
    events = db.query(Event).order_by(Event.timestamp.desc(), Event.id.desc()).limit(200).all()
    
    nodes = []
    edges = []
    node_ids = set()
    edge_ids = set()
    
    def add_node(node_id: str, node_type: str, label: str, **extra):
        if node_id not in node_ids:
            nodes.append({
                "id": node_id,
                "type": node_type,
                "position": {"x": 0, "y": 0},
                "data": {"label": label, "type": node_type, **extra}
            })
            node_ids.add(node_id)
    
    def add_edge(source: str, target: str, relationship: str):
        edge_id = f"{source}-{target}-{relationship}"
        if edge_id not in edge_ids:
            edges.append({
                "id": edge_id,
                "source": source,
                "target": target,
                "type": "relationship",
                "data": {"relationship": relationship}
            })
            edge_ids.add(edge_id)
    
    for e in events:
        # IP nodes
        host = e.hostname or e.agent
        if host:
            add_node(f"host-{host}", "host", host)
        if e.source_ip:
            ip_id = f"ip-{e.source_ip}"
            add_node(ip_id, "ip", e.source_ip, severity=e.severity)
            
            if host:
                host_id = f"host-{host}"
                add_edge(ip_id, host_id, "source")
        
        # Event node
        event_id = f"event-{e.id}"
        event_label = e.rule_description[:50] if e.rule_description else f"Event {e.id}"
        add_node(event_id, "event", event_label, severity=e.severity)
        
        if host:
            host_id = f"host-{host}"
            add_edge(host_id, event_id, "generated")
        
        if e.source_ip:
            ip_id = f"ip-{e.source_ip}"
            add_edge(ip_id, event_id, "source")
        
        # Rule node
        if e.rule_id:
            rule_id = f"rule-{e.rule_id}"
            add_node(rule_id, "rule", e.rule_id)
            add_edge(event_id, rule_id, "triggered")
        
        # MITRE node
        if e.mitre_tactic:
            mitre_id = f"mitre-{e.mitre_tactic}"
            add_node(mitre_id, "mitre", e.mitre_tactic)
            add_edge(event_id, mitre_id, "maps to")
        
        # CVE node
        if e.cve:
            cve_id = f"cve-{e.cve}"
            add_node(cve_id, "cve", e.cve)
            add_edge(event_id, cve_id, "references")
    
    return {"nodes": nodes, "edges": edges}
