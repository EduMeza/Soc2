"""Generación de gráficos estáticos para PDF con Plotly + Kaleido."""
from __future__ import annotations

import io
from typing import Any

import plotly.graph_objects as go
from plotly.io import to_image


# Paleta consistente con el frontend (Tailwind slate/emerald/amber/red)
PALETTE = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "primary": "#1873be",
    "background": "#0f172a",
    "card": "#1e293b",
    "grid": "#334155",
    "text": "#f1f5f9",
    "muted": "#94a3b8",
}

TACTIC_COLORS = {
    "Reconocimiento": "#fbbf24",
    "Ejecución": "#ef4444",
    "Persistencia": "#a855f7",
    "Evasión de defensas": "#ec4899",
    "Exfiltración": "#06b6d4",
    "Comando y Control": "#8b5cf6",
    "Initial Access": "#f97316",
    "Execution": "#ef4444",
    "Persistence": "#a855f7",
    "Privilege Escalation": "#ec4899",
    "Defense Evasion": "#ec4899",
    "Credential Access": "#f43f5e",
    "Discovery": "#fbbf24",
    "Lateral Movement": "#8b5cf6",
    "Collection": "#06b6d4",
    "Command and Control": "#8b5cf6",
    "Exfiltration": "#06b6d4",
    "Impact": "#ef4444",
}


def _layout_common(title: str, height: int = 280) -> dict:
    return dict(
        title=dict(text=title, font=dict(size=14, color=PALETTE["text"], family="Inter")),
        paper_bgcolor=PALETTE["background"],
        plot_bgcolor=PALETTE["card"],
        font=dict(color=PALETTE["text"], family="Inter"),
        margin=dict(l=60, r=30, t=50, b=50),
        height=height,
        xaxis=dict(gridcolor=PALETTE["grid"], zerolinecolor=PALETTE["grid"]),
        yaxis=dict(gridcolor=PALETTE["grid"], zerolinecolor=PALETTE["grid"]),
    )


def _to_png(fig: go.Figure) -> bytes:
    return to_image(fig, format="png", scale=2)


def severity_donut_image(severity_counts: dict[str, int]) -> bytes:
    if not severity_counts:
        return b""
    labels = list(severity_counts.keys())
    values = list(severity_counts.values())
    colors = [PALETTE.get(k.lower(), PALETTE["muted"]) for k in labels]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.62,
        marker=dict(colors=colors, line=dict(color=PALETTE["background"], width=3)),
        textinfo="label+percent", textfont=dict(size=11, color=PALETTE["text"]),
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>",
    ))
    fig.update_layout(_layout_common("Distribución de severidades"))
    fig.add_annotation(text=f"{sum(values):,}", x=0.5, y=0.5, font_size=22, showarrow=False, font_color=PALETTE["text"])
    return _to_png(fig)


def top_agents_bar_image(top_agents: list[dict], top_n: int = 10) -> bytes:
    if not top_agents:
        return b""
    data = sorted(top_agents, key=lambda x: x["count"], reverse=True)[:top_n]
    agents = [d["agent"] for d in data]
    counts = [d["count"] for d in data]
    fig = go.Figure(go.Bar(
        y=agents[::-1], x=counts[::-1], orientation="h",
        marker_color=PALETTE["primary"],
        hovertemplate="%{y}: %{x} eventos<extra></extra>",
    ))
    fig.update_layout(_layout_common("Agentes con mayor actividad"), xaxis_title="Eventos")
    return _to_png(fig)


def risk_gauge_image(risk_score: float) -> bytes:
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=risk_score,
        number=dict(suffix="/100", font=dict(size=28, color=PALETTE["text"])),
        gauge=dict(
            axis=dict(range=[0, 100], tickcolor=PALETTE["muted"]),
            bar=dict(color=PALETTE["primary"]),
            bgcolor=PALETTE["card"],
            borderwidth=1,
            bordercolor=PALETTE["grid"],
            steps=[
                dict(range=[0, 20], color="#22c55e33"),
                dict(range=[20, 40], color="#eab30833"),
                dict(range=[40, 70], color="#f9731633"),
                dict(range=[70, 100], color="#ef444433"),
            ],
        ),
    ))
    fig.update_layout(_layout_common("Índice de riesgo global", height=260))
    return _to_png(fig)


def mitre_tactics_bar_image(mitre_tactics: dict[str, int]) -> bytes:
    if not mitre_tactics:
        return b""
    tactics = list(mitre_tactics.keys())
    counts = list(mitre_tactics.values())
    colors = [TACTIC_COLORS.get(t, PALETTE["muted"]) for t in tactics]
    fig = go.Figure(go.Bar(
        y=tactics[::-1], x=counts[::-1], orientation="h",
        marker_color=colors[::-1],
        hovertemplate="%{y}: %{x} eventos<extra></extra>",
    ))
    fig.update_layout(_layout_common("Tácticas MITRE ATT&CK"), xaxis_title="Eventos asociados")
    return _to_png(fig)


def timeline_chart_image(timeline: list[dict]) -> bytes:
    if not timeline:
        return b""
    from collections import Counter
    from datetime import datetime

    by_day_sev = Counter()
    for e in timeline[:200]:
        ts = e.get("timestamp", "")
        sev = e.get("severity", "Low")
        try:
            day = datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%d/%m")
        except Exception:
            day = "?"
        by_day_sev[(day, sev)] += 1

    days = sorted({d for d, _ in by_day_sev.keys()})
    fig = go.Figure()
    for sev, color in [("Critical", PALETTE["critical"]), ("High", PALETTE["high"]),
                        ("Medium", PALETTE["medium"]), ("Low", PALETTE["low"])]:
        vals = [by_day_sev.get((d, sev), 0) for d in days]
        if any(vals):
            fig.add_trace(go.Bar(name=sev, x=days, y=vals, marker_color=color))
    fig.update_layout(_layout_common("Evolución temporal por severidad", height=280), barmode="stack")
    return _to_png(fig)