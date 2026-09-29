import requests
import pandas as pd
from app.services.csv_parser import load_csv
from app.services.analysis import analyze
from app.services.correlation import find_correlations
from app.services.mitre import classify_mitre
from app.services.risk import calculate_risk_score
from app.services.geoip import get_geoip_for_events
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.event import Event
from datetime import datetime
import sqlite3

# Load CSV
with open(r'C:\Users\emeza.LEGACY\Documents\Proyectos\Soc2\data\sample_events_1.csv', 'rb') as f:
    contents = f.read()

df, detected = load_csv(contents, max_mb=50, max_rows=200000)
print(f"DataFrame shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")

# Run analysis
analysis_result = analyze(df)
print(f"Analysis: total={analysis_result.total_events}, critical={analysis_result.critical_count}, high={analysis_result.high_count}")

# Get DB session
db_gen = get_db()
db = next(db_gen)

# Check existing events count before
c = conn = sqlite3.connect('data/soc.db')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM events')
print(f"Events before: {c.fetchone()}")

# Test insert
batch_id = "batch-test-" + datetime.utcnow().strftime("%Y%m%d%H%M%S")
inserted = 0
for idx, row in df.iterrows():
    ts_raw = row.get("timestamp", "").strip()
    if ts_raw:
        try:
            ts_str = ts_raw.replace("Z", "+00:00")
            datetime.fromisoformat(ts_str)
        except Exception:
            try:
                datetime.strptime(ts_raw.split()[0], "%Y-%m-%d")
            except Exception:
                pass
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

    event = Event(
        event_uid=row.get("id") or row.get("event_uid") or f"evt-0" or "",
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
        mitre_tactic=row.get("mitre_tactic", ""),
        mitre_technique=row.get("mitre_technique", ""),
        raw_event=str(row.to_dict()),
        risk_score=float(row.get("risk_score", 0) or 0),
        correlation_id="",
        status=row.get("status", "completed"),
        import_batch_id="batch-test",
    )
    db.add(event)

print("Committing...")
db.commit()
print("Committed!")

# Check DB
c = sqlite3.connect('data/soc.db').cursor()
c.execute('SELECT COUNT(*) FROM events')
print(f"Events after: {c.fetchone()}")