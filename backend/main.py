from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
import csv
import os

from database import init_db, get_db
import hashlib
from auth_config import INITIAL_USERNAME, INITIAL_HASH, FORCE_CHANGE

app = FastAPI(title="SOC Command Center API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup():
    init_db()
    # Insert initial user if not present
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (INITIAL_USERNAME,))
    if not c.fetchone():
        c.execute("INSERT INTO users (username, password_hash, force_change) VALUES (?, ?, ?)",
                  (INITIAL_USERNAME, INITIAL_HASH, FORCE_CHANGE))
        conn.commit()
    conn.close()

@app.get("/")
async def root():
    return {"message": "SOC Command Center API running", "version": "1.0.0"}

@app.get("/events")
async def get_events():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM events")
    rows = c.fetchall()
    conn.close()
    return [{"id": row[0], "timestamp": row[1], "source_ip": row[2],
             "event_type": row[3], "severity": row[4], "status": row[5]} for row in rows]

@app.post("/login")
async def login(username: str = Query(default=""), password: str = Query(default="")):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid user")
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    if pw_hash != user[2]:
        raise HTTPException(status_code=401, detail="Invalid password")
    return {
        "username": user[1],
        "force_change": bool(user[3]),
        "message": "First access - change password required" if user[3] else "Login successful"
    }

@app.get("/summary")
async def get_summary():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM events")
    total = c.fetchone()[0]
    conn.close()
    return {"total_events": total}

@app.post("/import")
async def import_csv():
    init_db()
    demo_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "demo", "demo_events.csv")
    conn = get_db()
    c = conn.cursor()
    with open(demo_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            c.execute("INSERT INTO events (timestamp, source_ip, event_type, severity, status) VALUES (?, ?, ?, ?, ?)",
                      (row.get("timestamp"), row.get("source_ip"), row.get("event_type"),
                       row.get("severity"), row.get("status")))
    conn.commit()
    conn.close()
    return {"message": "Demo CSV imported", "file": demo_path}
