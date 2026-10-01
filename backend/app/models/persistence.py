from datetime import datetime, timezone
from uuid import uuid4
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, ForeignKey, UniqueConstraint
from app.core.database import Base

def now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def uid():
    return uuid4().hex

def as_utc(value):
    return value.replace(tzinfo=timezone.utc) if isinstance(value, datetime) and value.tzinfo is None else value

class ImportBatch(Base):
    __tablename__ = 'import_batches'
    id = Column(String, primary_key=True, default=uid)
    filename = Column(String)
    file_size = Column(Integer)
    total_rows = Column(Integer, default=0)
    inserted = Column(Integer, default=0)
    duplicates = Column(Integer, default=0)
    rejected = Column(Integer, default=0)
    warnings = Column(JSON, default=list)
    detected_columns = Column(JSON, default=dict)
    started_at = Column(DateTime, default=now)
    completed_at = Column(DateTime)
    status = Column(String, default='running')
    username = Column(String)

class Correlation(Base):
    __tablename__ = 'correlations'
    id = Column(String, primary_key=True, default=uid)
    title = Column(String)
    severity = Column(String)
    risk = Column(Float)
    support_score = Column(Float)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    evidence = Column(JSON, default=list)
    created_at = Column(DateTime, default=now)

class CorrelationEvent(Base):
    __tablename__ = 'correlation_events'
    correlation_id = Column(String, ForeignKey('correlations.id'), primary_key=True)
    event_id = Column(Integer, ForeignKey('events.id'), primary_key=True)

class Report(Base):
    __tablename__ = 'reports'
    report_id = Column(String, primary_key=True, default=uid)
    created_at = Column(DateTime, default=now)
    analyst = Column(String)
    entity = Column(String)
    period = Column(String)
    total_events = Column(Integer)
    critical = Column(Integer)
    high = Column(Integer)
    medium = Column(Integer)
    low = Column(Integer)
    risk_score = Column(Float)
    pdf_path = Column(String)
    txt_path = Column(String)
    json_path = Column(String)
    status = Column(String)
    created_by = Column(String)

class SchedulerRun(Base):
    __tablename__ = 'scheduler_runs'
    __table_args__ = (UniqueConstraint('date', 'shift'),)
    id = Column(String, primary_key=True, default=uid)
    date = Column(String)
    shift = Column(String)
    report_id = Column(String, ForeignKey('reports.report_id'))
    status = Column(String)
    started_at = Column(DateTime, default=now)
    completed_at = Column(DateTime)

class AuditLog(Base):
    __tablename__ = 'audit_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now, index=True)
    username = Column(String)
    action = Column(String, index=True)
    status = Column(String)
    details = Column(JSON, default=dict)

class AppSetting(Base):
    __tablename__ = 'app_settings'
    key = Column(String, primary_key=True)
    value = Column(JSON)
