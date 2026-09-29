import csv
import io
import re
from fastapi import APIRouter, UploadFile, File, HTTPException, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from ..core.database import get_db
from ..models.event import Event
from ..services.csv_parser import load_csv
from ..services.analysis import analyze
from ..services.risk import calculate_risk_score, calculate_agent_risk_scores
from ..services.mitre import classify_mitre, classify_event_mitre, MITRE_TECHNIQUES
from ..services.correlation import find_correlations
from ..services.geoip import get_geoip_for_events
from datetime import datetime
import uuid

router = APIRouter()


class EventDetail(BaseModel):
    id: int
    timestamp: str
    severity: str
    hostname: str
    source_ip: str
    rule_id: str

    class Config:
        orm_mode = True


def _detect_delimiter(sample: str) -> str:
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample, delimiters=",\t;|")
        return dialect.delimiter
    except Exception:
        comma = sample.count(",")
        semicolon = sample.count(";")
        tab = sample.count("\t")
        pipe = sample.count("|")
        if semicolon > comma and semicolon > tab and semicolon > pipe:
            return ";"
        if tab > comma and tab > semicolon and tab > pipe:
            return "\t"
        if pipe > comma and pipe > semicolon and pipe > tab:
            return "|"
        return ","


@router.post("/import")
async def import_csv(file: UploadFile = File(...), db: Session = Depends(get_db)):
    # Validación básica
    if not file.filename or not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="El archivo debe ser CSV")

    contents = await file.read()
    size_mb = len(contents) / (1024 * 1024)

    from ..core.config import settings
    if size_mb > settings.MAX_UPLOAD_MB:
        raise HTTPException(status_code=400, detail=f"Archivo excede {settings.MAX_UPLOAD_MB} MB")

    # Parsear CSV usando el parser robusto
    try:
        df, detected_columns = load_csv(
            contents,
            max_mb=settings.MAX_UPLOAD_MB,
            max_rows=settings.MAX_ROWS,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if len(df) == 0:
        raise HTTPException(status_code=400, detail="CSV sin datos válidos después del parsing")

    # Ejecutar análisis completo
    analysis_result = analyze(df)

    # Calcular riesgo
    events_for_risk = df.to_dict("records")
    overall_risk = calculate_risk_score(events_for_risk)
    agent_risks = calculate_agent_risk_scores(events_for_risk)

    # Clasificar MITRE
    mitre_classification = classify_mitre(events_for_risk)

    # Correlaciones
    correlations = find_correlations(events_for_risk)

    # GeoIP
    geoip_results = get_geoip_for_events(events_for_risk)

    # Generar batch_id
    batch_id = "batch-" + datetime.utcnow().strftime("%Y%m%d%H%M%S")

    # Insertar eventos en BD
    inserted = 0
    correlation_map = {}
    for i, corr in enumerate(correlations):
        for event_idx in corr.get("event_indices", []):
            correlation_map[event_idx] = corr.get("id", f"corr-{i}")

    print(f"DataFrame shape: {df.shape}")
    print(f"DataFrame columns: {df.columns.tolist()}")

    for idx, row in df.iterrows():
        # Validación básica de fecha
        ts_raw = row.get("timestamp", "").strip()
        if ts_raw:
            try:
                ts_str = ts_raw.replace("Z", "+00:00")
                datetime.fromisoformat(ts_str)
            except Exception:
                try:
                    datetime.strptime(ts_raw.split()[0], "%Y-%m-%d")
                except Exception:
                    ts_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        else:
            ts_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")

        def normalize_ip(val):
            val = (val or "").strip()
            if not val:
                return ""
            import re
            if (re.search(r"[^0-9a-fA-F.:]", val) and "." not in val and ":" not in val) or len(val) > 45:
                return val[:50]
            return val[:45]

        correlation_id = correlation_map.get(idx, "")

        mitre_tactic_name = ""
        mitre_techniques = []
        try:
            text_for_mitre = " ".join(str(row.get(f, "") or "") for f in ("rule_description", "description", "rule", "process", "command", "status"))
            mitre_counts = classify_event_mitre(text_for_mitre)
            try:
                raw_rid = row.get("rule_id", row.get("rule"))
                rid = int(float(str(raw_rid))) if raw_rid not in (None, "", "nan") else None
            except (ValueError, TypeError):
                rid = None
            for tactic, info in MITRE_TECHNIQUES.items():
                rid_match = rid is not None and rid in info.get("rule_ids", [])
                if mitre_counts.get(tactic, 0) > 0 or rid_match:
                    mitre_tactic_name = tactic
                    mitre_techniques = info.get("techniques", [])
                    break
        except Exception:
            pass

        try:
            event = Event(
                event_uid=row.get("id") or row.get("event_uid") or f"evt-{inserted}" or "",
                timestamp=datetime.fromisoformat(ts_str) if ts_raw else datetime.utcnow(),
                agent=row.get("agent", ""),
                hostname=row.get("hostname", row.get("host", "")),
                source=row.get("source", ""),
                event_type=row.get("event_type", row.get("event_type", "")),
                rule_id=row.get("rule_id", row.get("rule", "")),
                rule_description=row.get("rule_description", row.get("description", "")),
                severity=row.get("severity", row.get("original_severity", "INFO")),
                original_severity=row.get("original_severity", row.get("severity", "INFO")),
                source_ip=normalize_ip(row.get("source_ip", row.get("src_ip", row.get("source", "")))),
                destination_ip=row.get("destination_ip", row.get("dest_ip", "")),
                source_port=int(row.get("source_port", 0) or 0),
                destination_port=int(row.get("destination_port", 0) or 0),
                protocol=row.get("protocol", ""),
                username=row.get("username", row.get("user", "")),
                process=row.get("process", ""),
                command=row.get("command", ""),
                file_path=row.get("file_path", ""),
                cve=row.get("cve", ""),
                mitre_tactic=mitre_tactic_name,
                mitre_technique="; ".join(mitre_techniques),
                raw_event=str(row.to_dict()),
                risk_score=float(row.get("risk_score", 0) or 0),
                correlation_id=correlation_id,
                status=row.get("status", "completed"),
                import_batch_id=batch_id,
            )
            db.add(event)
            inserted += 1
        except Exception as e:
            import traceback
            traceback.print_exc()
            print(f"Error inserting row {idx}: {e}")
            continue

    try:
        db.commit()
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"Commit error: {e}")
        db.rollback()

    # Invalidar caché de analytics (forzar recálculo)
    return {
        "message": "Importación completa",
        "inserted": inserted,
        "batch_id": batch_id,
        "detected_columns": detected_columns,
        "analysis": {
            "total_events": analysis_result.total_events,
            "critical": analysis_result.critical_count,
            "high": analysis_result.high_count,
            "agents": analysis_result.agents_count,
            "cves": len(analysis_result.cves),
            "suspicious_processes": len(analysis_result.suspicious_processes),
            "correlations": len(correlations),
            "overall_risk": round(overall_risk, 1),
        },
    }


@router.get("/")
def list_events(
    page: int = 1,
    limit: int = 50,
    severity: Optional[str] = Query(None),
    host: Optional[str] = Query(None),
    agent: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    rule: Optional[str] = Query(None),
    mitre: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    sort_by: str = Query("id"),
    sort_order: str = Query("desc"),
    db: Session = Depends(get_db)
):
    from sqlalchemy import func, or_
    from datetime import datetime as dt

    query = db.query(Event)

    # Filtros
    if severity:
        query = query.filter(Event.severity == severity)
    if host:
        query = query.filter(Event.hostname.ilike(f"%{host}%"))
    if agent:
        query = query.filter(Event.agent.ilike(f"%{agent}%"))
    if source_ip:
        query = query.filter(Event.source_ip.ilike(f"%{source_ip}%"))
    if rule:
        query = query.filter(Event.rule_id.ilike(f"%{rule}%"))
    if mitre:
        query = query.filter(or_(Event.mitre_tactic.ilike(f"%{mitre}%"), Event.mitre_technique.ilike(f"%{mitre}%")))
    if min_risk:
        query = query.filter(Event.risk_score >= min_risk)
    if start_date:
        try:
            query = query.filter(Event.timestamp >= dt.fromisoformat(start_date.replace("Z", "+00:00")))
        except:
            pass
    if end_date:
        try:
            query = query.filter(Event.timestamp <= dt.fromisoformat(end_date.replace("Z", "+00:00")))
        except:
            pass

    # Ordenamiento
    if hasattr(Event, sort_by):
        order_col = getattr(Event, sort_by)
        if sort_order == "desc":
            query = query.order_by(order_col.desc())
        else:
            query = query.order_by(order_col.asc())
    else:
        query = query.order_by(Event.id.desc())

    total = query.count()
    events = query.offset((page - 1) * limit).limit(limit).all()

    def serialize(ev):
        return {k: getattr(ev, k) for k in [
            "id", "event_uid", "timestamp", "agent", "hostname", "source", "event_type",
            "rule_id", "rule_description", "severity", "original_severity", "source_ip",
            "destination_ip", "source_port", "destination_port", "protocol", "username",
            "process", "command", "file_path", "cve", "mitre_tactic", "mitre_technique",
            "raw_event", "risk_score", "correlation_id", "status", "import_batch_id"
        ] if hasattr(ev, k)}

    return {"items": [serialize(e) for e in events], "total": total, "page": page, "limit": limit}