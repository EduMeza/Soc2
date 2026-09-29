"""Programador de reportes automáticos."""
from __future__ import annotations
import json
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any
from dataclasses import dataclass, field
from typing import Optional

SCHEDULE_FILE = Path("data/schedule_config.json")
SCHEDULE_LOG = Path("data/schedule_log.json")

SHIFTS = {
    "Mañana (07:00)": "Mañana (07:00)",
    "Tarde (16:00)": "Tarde (16:00)",
    "Noche (23:00)": "Noche (23:00)",
}


@dataclass
class ScheduleConfig:
    enabled: bool = False
    shifts: list[str] = field(default_factory=lambda: ["Mañana (07:00)", "Tarde (16:00)", "Noche (23:00)"])
    template: str = "ejecutivo"
    entity: str = "Organización"
    analyst: str = "Sistema Automatizado"
    timezone: str = "America/Asuncion"


def load_schedule() -> ScheduleConfig:
    if Path("data/schedule_config.json").exists():
        try:
            with open("data/schedule_config.json", "r", encoding="utf-8") as f:
                data = json.load(f)
                return ScheduleConfig(**data)
        except Exception:
            pass
    return ScheduleConfig()


def save_schedule(config: ScheduleConfig):
    with open("data/schedule_config.json", "w", encoding="utf-8") as f:
        json.dump(config.__dict__, f, indent=2)


def log_execution(result: dict):
    log = []
    if Path("data/schedule_log.json").exists():
        try:
            with open("data/schedule_log.json", "r", encoding="utf-8") as f:
                log = json.load(f)
        except Exception:
            pass
    log.insert(0, {"timestamp": datetime.utcnow().isoformat() + "Z", **result})
    with open("data/schedule_log.json", "w", encoding="utf-8") as f:
        json.dump(log[:100], f, indent=2, ensure_ascii=False)


def get_schedule_log(limit: int = 50) -> list:
    if Path("data/schedule_log.json").exists():
        try:
            with open("data/schedule_log.json", "r", encoding="utf-8") as f:
                return json.load(f)[:50]
        except Exception:
            pass
    return []


class SchedulerThread(threading.Thread):
    def __init__(self, generate_report_func):
        super().__init__(daemon=True)
        self.generate_report_func = generate_report_func
        self.running = False

    def run(self):
        self.running = True
        while self.running:
            config = load_schedule()
            if not config.enabled:
                time.sleep(60)
                continue

            now = datetime.utcnow()
            for shift_name in config.shifts:
                shift_time = shift_name.split("(")[1].rstrip(")")
                hour, minute = map(int, shift_time.split(":"))
                shift_dt = datetime(now.year, now.month, now.day, hour, minute)
                if shift_dt <= now < shift_dt + timedelta(minutes=5):
                    # Generar reporte
                    try:
                        self.generate_report_func(config)
                        log_execution({"shift": shift_name, "status": "success", "timestamp": datetime.utcnow().isoformat()})
                    except Exception as e:
                        log_execution({"shift": shift_name, "status": "error", "error": str(e), "timestamp": datetime.utcnow().isoformat()})
            time.sleep(60)

    def stop(self):
        self.running = False


_scheduler_thread: Optional[threading.Thread] = None


def start_scheduler(generate_report_func):
    global _scheduler_thread
    if _scheduler_thread is None or not _scheduler_thread.is_alive():
        _scheduler_thread = SchedulerThread(generate_report_func)
        _scheduler_thread.start()


def stop_scheduler():
    global _scheduler_thread
    if _scheduler_thread:
        _scheduler_thread.stop()
        _scheduler_thread = None