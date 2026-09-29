"""Orquestador de reportes automáticos por turno (07:00, 16:00, 23:00).

Este módulo actúa como glue entre:
- modules.wazuh_client      → fetch desde el Indexer en la ventana del turno
- modules.parser            → normalización (no cambia)
- modules.analysis / mitre   → análisis (no cambia)
- modules.report.exportar   → generación de texto y multiformato (no cambia)
- modules.history           → guardado del registro (no cambia)

Cada corte define su ventana estrictamente:
- 07:00 → [ayer 23:00:00, hoy 06:59:59]
- 16:00 → [hoy 07:00:00, hoy 15:59:59]
- 23:00 → [hoy 16:00:00, hoy 22:59:59]

Si no hay eventos en la ventana, se genera reporte de "cero" (trazabilidad
del "no pasa nada"), con mismo historial/estado completado.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, date, timezone, timedelta
from pathlib import Path

from modules.analysis import analyze
from modules.mitre import classify
from modules.report import build_report
from modules.exports import (
    report_to_pdf_bytes,
    report_to_json_bytes,
    report_to_stix_bytes,
    report_to_txt_bytes,
)
from modules.history import build_report_record, save_report
from modules.config import PROJECT_ROOT, DATA_DIR
from modules.scheduler import ScheduleConfig, get_schedule_config
from modules.wazuh_client import WazuhIndexerClient, INDEX_FIELDS
from modules.parser import normalize_dataframe

# Cargar .env al importar este módulo (silencioso si no existe)
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

logger = logging.getLogger(__name__)

# Directorio de outputs programados
SCHEDULED_OUTPUT_ROOT = PROJECT_ROOT / "output" / "scheduled"

# Configuración estricta de las 3 ventanas de corte
# (start_hour:min) → (end_hour:min)
SHIFTS = {
    "mañana": {
        "label": "Mañana (07:00)",
        "start": ("previous_day", 23, 0, 0),
        "end":   ("same_day",     6, 59, 59),
    },
    "tarde": {
        "label": "Tarde (16:00)",
        "start": ("same_day", 7, 0, 0),
        "end":   ("same_day", 15, 59, 59),
    },
    "noche": {
        "label": "Noche (23:00)",
        "start": ("same_day", 16, 0, 0),
        "end":   ("same_day", 22, 59, 59),
    },
}


def _get_shift_window(shift_key: str, for_date: date):
    """Devuelve (start_dt, end_dt) en hora local para la fecha dada.

    Excepción: mañana empieza la *madrugada del día anterior* (23:00) y termina
    en la mañana del `for_date` (06:59).
    """
    if shift_key not in SHIFTS:
        raise ValueError(f"shift_key inválido: {shift_key!r}")

    cfg = SHIFTS[shift_key]
    start_ref, sh, sm, ss = cfg["start"]
    end_ref, eh, em, es = cfg["end"]

    if start_ref == "previous_day":
        start_date = for_date - timedelta(days=1)
    else:
        start_date = for_date

    end_date = for_date

    start_dt = datetime(start_date.year, start_date.month, start_date.day,
                        sh, sm, ss)
    end_dt = datetime(end_date.year, end_date.month, end_date.day,
                      eh, em, es)
    return start_dt, end_dt


def _make_dirs(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def generate_shift_report(
    shift_key: str,
    for_date: date,
    config: ScheduleConfig | None = None,
) -> dict:
    """Genera el reporte completo para un turno en una fecha concreta.

    Devuelve un dict con el estado final:
        {
            "status": "success" | "error",
            "shift": shift_key,
            "label": str,
            "date": for_date.isoformat(),
            "period_start": iso, "period_end": iso,
            "events_received": int,
            "events_processed": int,
            "report_file": path (str) si hubo PDF,
            "history_saved": bool,
            "error": str | None,
        }
    """
    outcome = {
        "status": "error",
        "shift": shift_key,
        "date": for_date.isoformat(),
        "label": SHIFTS.get(shift_key, {}).get("label", shift_key),
        "period_start": None,
        "period_end": None,
        "events_received": 0,
        "events_processed": 0,
        "report_file": None,
        "history_saved": False,
        "error": None,
    }

    config = config or get_schedule_config()
    started_at = datetime.now()

    try:
        start_dt, end_dt = _get_shift_window(shift_key, for_date)
        outcome["period_start"] = start_dt.isoformat()
        outcome["period_end"] = end_dt.isoformat()

        logger.info(
            "Generando reporte turno=%s fecha=%s ventana=[%s..%s]",
            shift_key, for_date, start_dt, end_dt)

        # 1) Fetch desde Wazuh Indexer (lee todo desde .env si no hay parámetros)
        client = WazuhIndexerClient()  # lee automáticamente de variables de entorno
        df = client.search_range(start_dt, end_dt)

        outcome["events_received"] = len(df)

        # 2) Normalizar a canónica (si viene de CSV ya estaría; aquí vienen desde Indexer)
        from modules.parser import CANONICAL_FIELDS
        detected = {c: c for c in CANONICAL_FIELDS if c in df.columns}
        try:
            df_norm = normalize_dataframe(df, detected)
        except Exception:
            # Si algo falla en la normalización, continuamos con el DF crudo
            df_norm = df

        # 3) Análisis y clasificación
        result = analyze(df_norm)
        mitre_summary, enriched = classify(df_norm)
        result.overall_risk_score = getattr(result, "overall_risk_score", None) or 0
        outcome["events_processed"] = len(result.df)

        # 4) Reporte textual (TXT)
        analyst = config.analyst_default
        entity = config.entity_default or ""
        period_label = outcome["label"]
        report_text = build_report(
            analyst or "SOC Automático",
            period_label,
            entity or "N/A",
            result,
            mitre_summary,
            enriched=enriched,
        )

        # 5) Exportaciones múltiples
        today_str = for_date.isoformat()
        base_dir = SCHEDULED_OUTPUT_ROOT / today_str
        base_dir.mkdir(parents=True, exist_ok=True)
        out_base = f"soc_report_{shift_key}_{today_str}"

        pdf_bytes = report_to_pdf_bytes(
            report_text,
            analyst=analyst, period=period_label, entity=entity,
            severity_counts=result.severity_counts,
            top_agents=result.top_agents,
            mitre_summary=mitre_summary,
            overall_risk_score=result.overall_risk_score,
            total_events=result.total_events,
            agents_count=result.agents_count,
        )
        json_bytes = report_to_json_bytes(report_text, result, mitre_summary, analyst, period_label, entity)
        stix_bytes = report_to_stix_bytes(report_text, result, mitre_summary, analyst, period_label, entity)
        txt_bytes = report_to_txt_bytes(report_text)

        # Definir formatos activos
        formats = config.output_formats or ["pdf", "json", "stix"]
        if "txt" not in formats:
            formats.append("txt")
        # siempre, para registro/debug
        if "json" not in formats:
            formats.append("json")
        if "stix" not in formats:
            formats.append("stix")
        if "pdf" not in formats:
            formats.append("pdf")

        (base_dir / f"{out_base}.pdf").write_bytes(pdf_bytes)
        (base_dir / f"{out_base}.json").write_bytes(json_bytes)
        (base_dir / f"{out_base}.stix.json").write_bytes(stix_bytes)
        (base_dir / f"{out_base}.txt").write_bytes(txt_bytes)

        outcome["report_file"] = str(base_dir / f"{out_base}.pdf")

        # 6) Persistir en el historial (evita duplicados por signature)
        signature = hashlib.sha256(
            f"{analyst}|{period_label}|{entity}|{today_str}|{shift_key}".encode()
        ).hexdigest()

        result_count = {
            "critical": result.critical_count,
            "high": result.high_count,
            "total": result.total_events,
            "agents": result.agents_count,
        }
        report_record = build_report_record(
            signature=signature,
            analyst=analyst,
            period=period_label,
            entity=entity,
            result_count=result_count,
            report_text=report_text,
            template=config.template_default,
            output_formats=formats,
        )
        # Enriquecer con metadatos operativos del corte (para scheduler y auditoria)
        report_record["shift_key"] = shift_key
        report_record["status"] = "success"
        report_record["period_start"] = outcome["period_start"]
        report_record["period_end"] = outcome["period_end"]
        report_record["events_received"] = outcome["events_received"]
        report_record["events_processed"] = outcome["events_processed"]
        report_record["report_file"] = outcome["report_file"]
        report_record["error"] = None
        save_report(report_record)
        outcome["history_saved"] = True

        outcome["status"] = "success"
        outcome["error"] = None

        logger.info(
            "Turno %s OK: %d eventos procesados, reporte %s",
            shift_key, outcome["events_processed"], outcome["report_file"]
        )

    except Exception as exc:
        logger.exception("Error generando turno %s", shift_key)
        outcome["status"] = "error"
        outcome["error"] = str(exc)

    outcome["finished_at"] = datetime.now().isoformat()
    return outcome


def generate_all_pending(for_date: date | None = None) -> list[dict]:
    """Genera todos los turnos pendientes de la fecha. (Útil para catch-up).

    Nota: este helper **no decide** si debe ejecutarse; el scheduler decide.
    """
    for_date = for_date or date.today()
    config = get_schedule_config()
    results: list[dict] = []
    for shift_key, _shift_cfg in config.shifts.items():
        results.append(generate_shift_report(shift_key, for_date, config))
    return results
