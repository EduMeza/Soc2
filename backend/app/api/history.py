from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..core.database import get_db
from ..models.event import Event

router = APIRouter()

@router.get("/")
def history(db: Session = Depends(get_db)):
    events = db.query(Event).limit(20).all()
    return {"history": [{"id": e.id, "batch_id": e.import_batch_id, "timestamp": str(e.created_at)} for e in events]}
