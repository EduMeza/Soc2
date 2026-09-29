"""Historial de reportes y análisis."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime
from typing import Any
from dataclasses import dataclass, field
from typing import List


HISTORY_FILE = Path("data/report_history.json")


@dataclass
class ReportRecord:
    id: str
    timestamp: str
    analyst: str
    entity: str
    period: str
    total_events: int
    critical: int
    high: int
    medium: int
    low: int
    risk_score: float
    file_paths: dict[str, str] = field(default_factory=dict)
    summary: str = ""


def load_history() -> list[dict]:
    if Path("data/report_history.json").exists():
        try:
            with open("data/report_history.json", "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_history(history: list[dict]):
    with open("data/report_history.json", "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


def add_report_record(record: dict):
    history = load_history()
    record.setdefault("id", f"rpt_{datetime.utcnow().strftime('%Y%m%d_%H%M%S%f')}")
    record["timestamp"] = datetime.utcnow().isoformat() + "Z"
    history.insert(0, record)
    # Mantener solo últimos 100
    save_history(history[:100])


def get_history(limit: int = 50) -> list[dict]:
    history = load_history()
    return history[:limit]


def get_report_by_id(report_id: str) -> dict | None:
    history = load_history()
    for r in history:
        if r.get("id") == report_id:
            return r
    return None
