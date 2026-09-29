"""Motor de correlación de eventos SOC."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime, timedelta
from collections import Counter


@dataclass
class Correlation:
    id: str
    title: str
    severity: str
    risk: float
    first_seen: str
    last_seen: str
    hosts: list[str]
    agents: list[str]
    ips: list[str]
    events: list[str]
    evidence: list[str]
    confidence: float
    event_ids: list[int] = field(default_factory=list)


def find_correlations(events: list[dict], time_window_minutes: int = 60) -> list[dict]:
    """Encuentra correlaciones entre eventos basándose en IP, host, agente, regla, proceso, usuario."""
    if not events:
        return []

    # Normalize events to (index, event) tuples
    events_with_idx = [(i, e) if isinstance(e, dict) else e for i, e in enumerate(events)]
    
    # Agrupar por claves de correlación
    groups = defaultdict(list)
    for i, e in events_with_idx:
        keys = [
            ("ip", e.get("src_ip") or e.get("dst_ip") or ""),
            ("host", e.get("host") or e.get("hostname") or e.get("agent") or ""),
            ("agent", e.get("agent") or ""),
            ("rule", e.get("rule_id") or e.get("rule") or ""),
            ("process", e.get("process") or ""),
            ("user", e.get("user") or e.get("username") or ""),
        ]
        for key_type, value in keys:
            if value:
                groups[(key_type, value)].append((i, e))

    correlations = []
    seen_event_sets = {}
    for (key_type, value), events_list in groups.items():
        if len(events_list) < 2:
            continue

        value_str = str(value)

        events_sorted = sorted(events_list, key=lambda x: x[1].get("timestamp", ""))
        first_seen = events_sorted[0][1].get("timestamp", "")
        last_seen = events_sorted[-1][1].get("timestamp", "")

        # Verificar ventana temporal
        try:
            first_dt = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
            last_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            if (last_dt - first_dt).total_seconds() > time_window_minutes * 60:
                continue
        except Exception:
            pass

        hosts = list(set(e.get("host") or e.get("hostname") or e.get("agent") or "" for _, e in events_list))
        agents = list(set(e.get("agent", "") for _, e in events_list))
        ips = list(set((e.get("src_ip") or e.get("dst_ip") or "") for _, e in events_list))
        event_ids = [e.get('id', i) for i, e in events_list]
        signature = tuple(sorted(event_ids))
        if signature in seen_event_sets:
            seen_event_sets[signature]['title'] += f' / {key_type}: {value_str[:50]}'
            continue

        severities = [e.get("severity", "Low") for _, e in events_list]
        severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}
        max_severity = max(severities, key=lambda s: {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Unknown": 0}.get(s, 0))

        import hashlib
        from .risk import calculate_risk_score
        correlation = {
            "id": 'corr_' + hashlib.sha256(str(signature).encode()).hexdigest()[:16],
            "title": f"{key_type}: {value_str[:50]}",
            "severity": max_severity,
            "risk": calculate_risk_score([e for _, e in events_list]),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "hosts": [h for h in hosts if h],
            "agents": [a for a in agents if a],
            "ips": [ip for ip in ips if ip],
            "events": len(events_list),
            "evidence": [f"Evento {eid}" for eid in event_ids[:5]],
            "confidence": min(1.0, len(events_list) / 10.0),
            "event_ids": event_ids,
        }
        correlations.append(correlation)
        seen_event_sets[signature] = correlation

    return sorted(correlations, key=lambda c: c["risk"], reverse=True)[:50]
