from fastapi import APIRouter, Depends, Body
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..models.event import Event
from ..services.geoip import get_geoip_for_events, resolve_geoip

router = APIRouter()


@router.get("/")
@router.get("")
def geoip_list(db: Session = Depends(get_db)):
    """Obtener geolocalización de IPs públicas en eventos."""
    from .analytics import ip_rows
    results = []
    for row in ip_rows(db):
        geo = resolve_geoip(row['ip'])
        if geo['latitude'] is not None and geo['longitude'] is not None:
            results.append({**geo,'event_count':row['total_count'],'severity':'Unknown'})
    return {"results": results}


@router.post("/batch")
def geoip_batch(ips: list[str] = Body(max_length=200)):
    """Resuelve geolocalización para lista de IPs."""
    results = {}
    for ip in ips:
        results[ip] = resolve_geoip(ip)
    return results
