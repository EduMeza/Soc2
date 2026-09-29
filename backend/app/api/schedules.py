from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def schedules():
    return {"schedules": [{"id": 1, "timezone": "America/Asuncion", "times": ["07:00", "16:00", "23:00"], "enabled": False}]}

@router.post("/run")
def run_now():
    return {"message": "Run now executed", "execution_id": "exec-1"}
