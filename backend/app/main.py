from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .core.database import init_db, get_db
from sqlalchemy.orm import Session

# Importar modelos antes de crear tablas para que se registren en Base
from .models import user, event, persistence
from contextlib import asynccontextmanager

# Inicializar DB
@asynccontextmanager
async def lifespan(app):
    if len(settings.JWT_SECRET) < 32:
        raise RuntimeError('Configure JWT_SECRET con al menos 32 caracteres aleatorios en .env')
    init_db()
    from .api.auth import bootstrap
    from .core.database import SessionLocal
    with SessionLocal() as db:
        bootstrap(db)
    from .services.scheduler import start_scheduler
    stop, thread = start_scheduler(SessionLocal)
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=10)

app = FastAPI(title="SOC Command Center", version="1.0", lifespan=lifespan,
              docs_url='/docs' if settings.APP_ENV == 'development' else None,
              redoc_url=None, openapi_url='/openapi.json' if settings.APP_ENV == 'development' else None)

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

if settings.APP_ENV == 'development':
    @app.get("/")
    def root():
        return {"message": "SOC Command Center API", "docs": "/docs"}

# Importar routers después de crear app para evitar ciclos
from .api import auth, events, analytics, reports, geoip, schedules, history

app.include_router(auth.router, prefix="/api/auth", tags=["auth"])
for router, name in [(events.router, 'events'), (analytics.router, 'analytics'),
                     (reports.router, 'reports'), (geoip.router, 'geoip'),
                     (schedules.router, 'schedules'), (history.router, 'history')]:
    app.include_router(router, prefix='/api/' + name, tags=[name], dependencies=[Depends(auth.require_soc_user)])
