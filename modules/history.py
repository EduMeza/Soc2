"""Historial de reportes generados (trazabilidad del analista).

Los reportes se guardan en data/report_history.json con una retención mínima
configurable (por defecto 3 días). Cada entrada incluye el momento exacto de
generación, analista, periodo, entidad/empresa, resumen de métricas y el texto
completo del reporte para su vista previa posterior.
"""
from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta

from modules.config import DATA_DIR, HISTORY_FILE, HISTORY_RETENTION_DAYS


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def load_reports() -> list[dict]:
    """Carga el historial desde disco y lo recorta a la ventana de retención."""
    if not HISTORY_FILE.exists():
        return []
    try:
        data = json.loads(HISTORY_FILE.read_text("utf-8"))
        reports = data if isinstance(data, list) else data.get("reports", [])
    except (OSError, json.JSONDecodeError):
        return []
    return prune_reports([r for r in reports if isinstance(r, dict)])


def prune_reports(reports: list[dict], days: int = HISTORY_RETENTION_DAYS,
                  now: datetime | None = None) -> list[dict]:
    """Elimina reportes más antiguos que `days` días (mantiene al menos 3)."""
    now = now or datetime.now()
    cutoff = now - timedelta(days=max(days, 3))  # Mínimo 3 días
    kept = []
    for report in reports:
        try:
            created = datetime.fromisoformat(report.get("created_at", ""))
        except (TypeError, ValueError):
            continue
        if created >= cutoff:
            kept.append(report)
    return kept


def _write(reports: list[dict]) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    temp = HISTORY_FILE.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as fh:
        json.dump({"reports": reports}, fh, ensure_ascii=False, indent=2)
    temp.replace(HISTORY_FILE)


def save_report(report: dict) -> tuple[list[dict], bool]:
    """Guarda un reporte en el historial evitando duplicados.

    Si ya existe una entrada con la misma firma (analista+periodo+entidad+
    datos+destino), se reemplaza por la más reciente (evita duplicados al
    re-ejecutar la app o editar campos). Devuelve (historial, salvado).
    """
    reports = load_reports()
    signature = report.get("signature", "")
    reports = [r for r in reports if r.get("signature") != signature]
    reports.append(report)
    reports = prune_reports(reports)
    _write(reports)
    return reports, True


def build_report_record(
    signature: str,
    analyst: str,
    period: str,
    entity: str,
    result_count: dict,
    report_text: str,
    template: str = "ejecutivo",
    output_formats: list | None = None,
    file_hashes: dict | None = None
) -> dict:
    """Construye el registro JSON de un reporte para el historial con trazabilidad completa."""
    output_formats = output_formats or ["txt"]
    file_hashes = file_hashes or {}
    
    # Calcular hash del contenido del reporte para integridad
    content_hash = hashlib.sha256(report_text.encode("utf-8")).hexdigest()[:16]
    
    return {
        "id": uuid.uuid4().hex[:10],
        "created_at": _now_iso(),
        "signature": signature,
        "analyst": analyst,
        "period": period,
        "entity": entity,
        "template": template,
        "critical": result_count.get("critical", 0),
        "high": result_count.get("high", 0),
        "total": result_count.get("total", 0),
        "agents": result_count.get("agents", 0),
        "report": report_text,
        "output_formats": output_formats,
        "content_hash": content_hash,
        "file_hashes": file_hashes,
        "traceability": {
            "generated_by": "SOC 24x7 Dashboard v3",
            "retention_days": HISTORY_RETENTION_DAYS,
            "auto_generated": analyst == "SOC Automático"
        }
    }


def clear_history() -> None:
    """Elimina todo el historial guardado."""
    if HISTORY_FILE.exists():
        HISTORY_FILE.unlink()


def get_report_by_id(report_id: str) -> dict | None:
    """Obtiene un reporte específico por ID para vista previa."""
    reports = load_reports()
    for report in reports:
        if report.get("id") == report_id:
            return report
    return None


def filter_reports(
    reports: list[dict],
    analyst: str | None = None,
    period: str | None = None,
    entity: str | None = None,
    template: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    min_critical: int | None = None
) -> list[dict]:
    """Filtra reportes por múltiples criterios."""
    filtered = reports
    
    if analyst:
        filtered = [r for r in filtered if analyst.lower() in r.get("analyst", "").lower()]
    if period:
        filtered = [r for r in filtered if period.lower() in r.get("period", "").lower()]
    if entity:
        filtered = [r for r in filtered if entity.lower() in (r.get("entity") or "").lower()]
    if template:
        filtered = [r for r in filtered if r.get("template", "ejecutivo") == template]
    if date_from:
        filtered = [r for r in filtered if r.get("created_at", "") >= date_from]
    if date_to:
        filtered = [r for r in filtered if r.get("created_at", "") <= date_to]
    if min_critical is not None:
        filtered = [r for r in filtered if r.get("critical", 0) >= min_critical]
    
    return filtered


def get_history_stats(reports: list[dict]) -> dict:
    """Obtiene estadísticas agregadas del historial."""
    if not reports:
        return {
            "total_reports": 0,
            "total_critical": 0,
            "total_high": 0,
            "total_events": 0,
            "by_analyst": {},
            "by_template": {},
            "by_period": {},
            "date_range": None
        }
    
    by_analyst = {}
    by_template = {}
    by_period = {}
    
    for r in reports:
        analyst = r.get("analyst", "Desconocido")
        by_analyst[analyst] = by_analyst.get(analyst, 0) + 1
        
        template = r.get("template", "ejecutivo")
        by_template[template] = by_template.get(template, 0) + 1
        
        period = r.get("period", "Sin periodo")
        by_period[period] = by_period.get(period, 0) + 1
    
    dates = [r.get("created_at", "") for r in reports]
    
    return {
        "total_reports": len(reports),
        "total_critical": sum(r.get("critical", 0) for r in reports),
        "total_high": sum(r.get("high", 0) for r in reports),
        "total_events": sum(r.get("total", 0) for r in reports),
        "total_agents": sum(r.get("agents", 0) for r in reports),
        "by_analyst": by_analyst,
        "by_template": by_template,
        "by_period": by_period,
        "date_range": {
            "from": min(dates) if dates else None,
            "to": max(dates) if dates else None
        }
    }


def _baseline_file():
    return DATA_DIR / "daily_baseline.json"


def save_daily_baseline(date_str: str, metrics: dict) -> None:
    """Guarda las métricas diarias para cálculo de tendencias futuras."""
    baseline = []
    baseline_file = _baseline_file()
    if baseline_file.exists():
        try:
            data = json.loads(baseline_file.read_text("utf-8"))
            baseline = data if isinstance(data, list) else data.get("days", [])
        except (OSError, json.JSONDecodeError):
            baseline = []

    baseline = [d for d in baseline if d.get("date") != date_str]
    baseline.append({"date": date_str, **metrics})
    baseline = baseline[-30:]
    baseline.sort(key=lambda d: d.get("date", ""))

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp = baseline_file.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as fh:
        json.dump({"days": baseline}, fh, ensure_ascii=False, indent=2)
    temp.replace(baseline_file)


def load_daily_baseline(days: int = 3) -> list[dict]:
    """Carga las métricas de los últimos N días para cálculo de tendencias."""
    baseline_file = _baseline_file()
    if not baseline_file.exists():
        return []
    try:
        data = json.loads(baseline_file.read_text("utf-8"))
        baseline = data if isinstance(data, list) else data.get("days", [])
        baseline = [d for d in baseline if isinstance(d, dict)]
        baseline.sort(key=lambda d: d.get("date", ""))
        return baseline[-days:]
    except (OSError, json.JSONDecodeError):
        return []