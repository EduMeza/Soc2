"""Programación automática de cortes diarios (07:00, 16:00, 23:00).

Este módulo gestiona la generación automática de reportes en los tres turnos
estándar SOC 24x7. Diseñado para ejecutarse como servicio en segundo plano
o mediante cron/Task Scheduler.
"""
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, date, timedelta
from pathlib import Path
from typing import Callable, Optional

from modules.config import DATA_DIR, PROJECT_ROOT

SCHEDULE_FILE = DATA_DIR / "schedule_config.json"
SCHEDULE_LOG_FILE = DATA_DIR / "schedule_log.json"

# Turnos estándar SOC 24x7
DEFAULT_SHIFTS = {
    "mañana": {"time": "07:00", "label": "Mañana (07:00)", "enabled": True},
    "tarde": {"time": "16:00", "label": "Tarde (16:00)", "enabled": True},
    "noche": {"time": "23:00", "label": "Noche (23:00)", "enabled": True},
}


@dataclass
class ScheduleConfig:
    """Configuración del programador automático."""
    shifts: dict = field(default_factory=lambda: DEFAULT_SHIFTS.copy())
    auto_enabled: bool = False
    last_run: dict = field(default_factory=dict)
    analyst_default: str = "SOC Automático"
    entity_default: str = ""
    template_default: str = "ejecutivo"
    output_formats: list = field(default_factory=lambda: ["pdf", "json"])


def _load_config() -> ScheduleConfig:
    """Carga la configuración desde disco."""
    if not SCHEDULE_FILE.exists():
        return ScheduleConfig()
    try:
        data = json.loads(SCHEDULE_FILE.read_text("utf-8"))
        return ScheduleConfig(**data)
    except (json.JSONDecodeError, TypeError):
        return ScheduleConfig()


def _save_config(config: ScheduleConfig) -> None:
    """Guarda la configuración en disco."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "shifts": config.shifts,
        "auto_enabled": config.auto_enabled,
        "last_run": config.last_run,
        "analyst_default": config.analyst_default,
        "entity_default": config.entity_default,
        "template_default": config.template_default,
        "output_formats": config.output_formats
    }
    SCHEDULE_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _load_log() -> list[dict]:
    """Carga el log de ejecuciones."""
    if not SCHEDULE_LOG_FILE.exists():
        return []
    try:
        return json.loads(SCHEDULE_LOG_FILE.read_text("utf-8"))
    except json.JSONDecodeError:
        return []


def _save_log(log: list[dict]) -> None:
    """Guarda el log de ejecuciones."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SCHEDULE_LOG_FILE.write_text(json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")


def get_schedule_config() -> ScheduleConfig:
    """Obtiene la configuración actual del programador."""
    return _load_config()


def update_schedule_config(
    shifts: dict | None = None,
    auto_enabled: bool | None = None,
    analyst_default: str | None = None,
    entity_default: str | None = None,
    template_default: str | None = None,
    output_formats: list | None = None
) -> ScheduleConfig:
    """Actualiza la configuración del programador."""
    config = _load_config()
    if shifts is not None:
        config.shifts = shifts
    if auto_enabled is not None:
        config.auto_enabled = auto_enabled
    if analyst_default is not None:
        config.analyst_default = analyst_default
    if entity_default is not None:
        config.entity_default = entity_default
    if template_default is not None:
        config.template_default = template_default
    if output_formats is not None:
        config.output_formats = output_formats
    _save_config(config)
    return config


def is_shift_due(shift_key: str, config: ScheduleConfig | None = None) -> bool:
    """Verifica si un turno debe ejecutarse ahora (basado en hora planificada).

    Lógica:
        - Solo si no se ejecutó hoy (checa historial)
        - Y la hora actual ya supera la hora programada del turno.

    Para la lógica de catch-up (turnos pasados no ejecutados), usar
    `get_pending_shifts()` que devuelve los turnos restantes.
    """
    config = config or _load_config()
    shift = config.shifts.get(shift_key)
    if not shift or not shift.get("enabled", False):
        return False

    # Comprobar si ya hay un registro de 'success' para hoy
    # (la función shift_done_today usa el historial)
    from modules.history import load_reports
    today_str = date.today().isoformat()

    last_run = config.last_run.get(shift_key, "")
    if last_run == today_str:
        return False

    # Solo se ejecuta si ya pasó la hora programada del turno
    now = datetime.now()
    shift_time = shift["time"]
    shift_hour, shift_minute = map(int, shift_time.split(":"))
    target = now.replace(hour=shift_hour, minute=shift_minute, second=0, microsecond=0)
    return now >= target


def mark_shift_run(shift_key: str, status: str = "success") -> None:
    """Marca un turno como ejecutado hoy con el estado indicado ('success'/'error')."""
    config = _load_config()
    config.last_run[shift_key] = date.today().isoformat()
    _save_config(config)

    # Log de ejecución
    log = _load_log()
    log.append({
        "timestamp": datetime.now().isoformat(),
        "shift": shift_key,
        "status": status
    })
    _save_log(log)


# ---------------------------------------------------------------------------
# Verificación basada en estado (historial) — permite recuperación ante apagado
# ---------------------------------------------------------------------------

def _report_is_success(report: dict) -> bool:
    """True si el registro historial indica éxito.

    - Si el registro tiene clave 'status', la usamos.
    - Si no, se infiere que el análisis se completó exitosamente.
    """
    status = report.get("status") or report.get("traceability", {}).get("status")
    if status:
        return str(status).lower() in ("success", "ok", "completed")
    # Registros viejos no tiene campo 'status'; por compatibilidad se asumen OK.
    return True


def shift_done_today(shift_key: str, config: ScheduleConfig | None = None) -> bool:
    """Devuelve True si el historial contiene un reporte success del turno de hoy.

    Matchea por `shift_key` (los nuevos reportes) o, como fallback,
    por el `period`/label del turno (reportes viejos que no guardaban el key).
    """
    config = config or _load_config()
    today_str = date.today().isoformat()
    label = config.shifts.get(shift_key, {}).get("label", "")

    try:
        from modules.history import load_reports
        reports = load_reports()
    except Exception:
        return False

    for report in reports:
        if not report.get("created_at", "").startswith(today_str):
            continue
        matches_key = report.get("shift_key") == shift_key
        matches_label = report.get("period") == label
        if (matches_key or matches_label) and _report_is_success(report):
            return True
    return False


def get_pending_shifts(config: ScheduleConfig | None = None) -> list[str]:
    """Devuelve la lista de turnos que ya deberían haberse generado hoy
    pero no tienen un reporte success en el historial.

    Esto permite que un servidor recién reiniciado haga catch-up de turnos
    pasados (dosifying), útil si la máquina estuvo apagada.
    """
    config = config or _load_config()
    pending = []

    for shift_key, shift in config.shifts.items():
        if not shift.get("enabled", False):
            continue
        if shift_done_today(shift_key, config):
            continue

        now = datetime.now()
        shift_hour, shift_minute = map(int, shift["time"].split(":"))
        target = now.replace(hour=shift_hour, minute=shift_minute, second=0, microsecond=0)

        # Pasa el turno planeado, pero no se ha hecho todavía
        if now >= target or now.date() > target.date():
            pending.append(shift_key)

    return pending


def get_next_shifts(config: ScheduleConfig | None = None, hours_ahead: int = 24) -> list[dict]:
    """Obtiene los próximos turnos programados."""
    config = config or _load_config()
    now = datetime.now()
    results = []
    
    for i in range(hours_ahead * 2):  # Cada 30 min
        check_time = now + timedelta(minutes=i * 30)
        for shift_key, shift in config.shifts.items():
            if not shift.get("enabled", False):
                continue
            shift_hour, shift_minute = map(int, shift["time"].split(":"))
            target = check_time.replace(hour=shift_hour, minute=shift_minute, second=0, microsecond=0)
            if abs((target - check_time).total_seconds()) < 1800:  # 30 min
                results.append({
                    "shift": shift_key,
                    "label": shift["label"],
                    "time": target.isoformat(),
                    "due": is_shift_due(shift_key, config)
                })
                break
    
    return results[:6]  # Próximos 6


def run_scheduled_reports(
    generate_report_fn: Callable | None = None,
    config: ScheduleConfig | None = None,
    force: bool = False,  # NUEVO: si True, ignora si ya fue procesado hoy
) -> list[dict]:
    """Ejecuta los reportes programados pendientes.

    Lógica basada en estado (historial), no ventana rígida:
    - Para cada turno enabled: si no está en historial (o force=True), lo ejecuta.

    Args:
        generate_report_fn: Función que genera el reporte.
            Si None, usa `modules.scheduled_reports.generate_shift_report`.
        config: Configuración opcional.
        force: Si True, ignora verificación de historial (util para reintentos).

    Returns:
        Lista de dict con resultados por turno procesado.
    """
    config = config or _load_config()
    results = []

    # Si no se proporcionó la función, usar la integración automatizada
    if generate_report_fn is None:
        from modules.scheduled_reports import generate_shift_report
        generate_report_fn = generate_shift_report

    for shift_key, shift in config.shifts.items():
        if not shift.get("enabled", False):
            continue

        # Si no es forzada y ya está en historial con éxito, saltar
        if not force and shift_done_today(shift_key, config):
            continue

        # Verificar que la hora actual ya pasó la del turno (a menos que sea force)
        if not force and not is_shift_due(shift_key, config):
            continue

        try:
            for_date = date.today()
            outcome = generate_report_fn(shift_key, for_date, config)
            mark_shift_run(shift_key, status="success")
            results.append(outcome)

        except Exception as e:
            results.append({
                "shift": shift_key,
                "status": "error",
                "error": str(e),
                "date": date.today().isoformat(),
            })
            mark_shift_run(shift_key, status="error")

    return results


class SchedulerDaemon:
    """Demonio para ejecución continua de reportes programados.
    
    Uso:
        daemon = SchedulerDaemon(generate_report_fn)
        daemon.start()  # En hilo separado
        # ... aplicación principal ...
        daemon.stop()
    """
    
    def __init__(self, generate_report_fn: Callable[[str, str, str, str], tuple[bytes, bytes, bytes]],
                 check_interval: int = 60):
        self.generate_report_fn = generate_report_fn
        self.check_interval = check_interval  # segundos
        self._running = False
        self._thread: Optional[threading.Thread] = None
    
    def start(self) -> None:
        """Inicia el demonio en hilo separado."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
    
    def stop(self) -> None:
        """Detiene el demonio."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
    
    def _run_loop(self) -> None:
        """Bucle principal del demonio."""
        while self._running:
            try:
                run_scheduled_reports(self.generate_report_fn)
            except Exception:
                pass  # Log interno si se desea
            time.sleep(self.check_interval)
    
    def is_running(self) -> bool:
        return self._running