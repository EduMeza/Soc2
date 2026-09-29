"""Motor de cálculo de riesgo SOC."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class RiskScore:
    overall: float = 0.0
    per_agent: dict[str, float] = field(default_factory=dict)
    factors: dict[str, float] = field(default_factory=dict)


def calculate_risk_score(events: list[dict]) -> float:
    """Calcula score de riesgo 0-100 basado en severidad y tipos de amenaza."""
    if not events:
        return 0.0

    weights = {
        "Critical": 10.0, "High": 6.0, "Medium": 3.0, "Low": 1.0,
        "suspicious_process": 8.0, "service_event": 7.0,
        "auth_event": 5.0, "scan_event": 4.0, "cve": 9.0
    }

    critical = sum(1 for e in events if e.get("severity") == "Critical")
    high = sum(1 for e in events if e.get("severity") == "High")
    medium = sum(1 for e in events if e.get("severity") == "Medium")
    low = sum(1 for e in events if e.get("severity") == "Low")

    total = len(events)
    if total == 0:
        return 0.0

    # Pesos por severidad y tipo
    score = (
        critical * 10.0 +
        high * 6.0 +
        medium * 3.0 +
        low * 1.0
    )

    # Normalizar a 0-100
    max_possible = len(events) * 10.0  # máximo si todos son Critical
    if max_possible == 0:
        return 0.0
    score = min(100.0, (score / max_possible) * 100.0)
    return round(score, 1)


def calculate_agent_risk_scores(events: list[dict]) -> dict[str, float]:
    """Calcula score de riesgo por agente/activo."""
    from collections import defaultdict
    agent_events = {}
    for e in events:
        agent = e.get("agent") or e.get("src_ip") or "unknown"
        agent_events.setdefault(agent, []).append(e)

    scores = {}
    for agent, events in agent_events.items():
        score = calculate_risk_score(events)
        # Ajustar por criticidad del activo
        name = agent.lower()
        if any(k in name for k in ["dc", "domain", "adfs", "certsrv"]):
            factor = 1.0
        elif any(k in name for k in ["srv", "sql", "db", "exchange", "mail"]):
            factor = 0.85
        elif any(k in name for k in ["ws", "workstation", "work"]):
            factor = 0.6
        else:
            factor = 0.7
        scores[agent] = round(min(100.0, calculate_risk_score(events) * factor), 1)
    return scores