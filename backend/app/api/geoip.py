from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..models.event import Event
from ..services.geoip import get_geoip_for_events, resolve_geoip

router = APIRouter()


@router.get("/")
def geoip_list(db: Session = Depends(get_db)):
    """Obtener geolocalización de IPs públicas en eventos."""
    events = db.query(Event).all()
    events_list = [
        {
            "src_ip": e.source_ip,
            "dst_ip": e.destination_ip,
            "severity": e.severity,
        }
        for e in events
    ]
    results = get_geoip_for_events(events_list)
    return {"results": results}


@router.post("/batch")
def geoip_batch(ips: list[str]):
    """Resuelve geolocalización para lista de IPs."""
    results = {}
    for ip in ips:
        results[ip] = resolve_geoip(ip)
    return results