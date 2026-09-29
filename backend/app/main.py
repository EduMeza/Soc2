from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .core.database import init_db, get_db
from sqlalchemy.orm import Session

# Importar modelos antes de crear tablas para que se registren en Base
from .models import user, event

# Inicializar DB
init_db()

app = FastAPI(title="SOC Command Center", version="1.0")

# CORS restringido
origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health():
    return {"status": "ok", "message": "SOC backend running"}

@app.get("/")
def root():
    return {"message": "SOC Command Center API", "docs": "/docs"}

# Importar routers después de crear app para evitar ciclos
from .api import auth, events, analytics, reports, geoip, schedules, history

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
app.include_router(events.router, prefix="/api/events", tags=["events"])
app.include_router(analytics.router, prefix="/api/analytics", tags=["analytics"])
app.include_router(reports.router, prefix="/api/reports", tags=["reports"])
app.include_router(geoip.router, prefix="/api/geoip", tags=["geoip"])
app.include_router(schedules.router, prefix="/api/schedules", tags=["schedules"])
app.include_router(history.router, prefix="/api/history", tags=["history"])
