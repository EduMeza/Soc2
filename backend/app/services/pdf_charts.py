"""Headless PDF charts: no browser or external service required."""
import io
from collections import Counter
from matplotlib.figure import Figure
from matplotlib.backends.backend_agg import FigureCanvasAgg

def chart(title, labels, values, pie=False):
    if not values or not sum(values):
        return b''
    fig = Figure(figsize=(8,3.5),layout='constrained')
    FigureCanvasAgg(fig)
    ax = fig.subplots()
    ax.set_title(title)
    if pie:
        ax.pie(values,labels=labels,autopct='%1.0f%%',wedgeprops={'width':0.45})
    else:
        ax.barh(labels,values,color='#1873be')
    output = io.BytesIO()
    fig.savefig(output,format='png',dpi=140)
    return output.getvalue()

def severity_donut_image(counts):
    return chart('Distribución de severidades',list(counts),list(counts.values()),True)

def top_agents_bar_image(agents,top_n=10):
    rows = sorted(agents,key=lambda r:r['count'],reverse=True)[:top_n]
    return chart('Agentes con mayor actividad',[r['agent'] for r in rows],[r['count'] for r in rows])

def risk_gauge_image(score):
    fig = Figure(figsize=(6,1.5),layout='constrained')
    FigureCanvasAgg(fig)
    ax = fig.subplots()
    ax.barh(['Riesgo'],[score],color='#1873be')
    ax.set_xlim(0,100)
    ax.set_title(f'Índice de riesgo {score:.1f}/100')
    output = io.BytesIO()
    fig.savefig(output,format='png',dpi=140)
    return output.getvalue()

def mitre_tactics_bar_image(tactics):
    return chart('MITRE ATT&CK',list(tactics),list(tactics.values()))

def timeline_chart_image(events):
    counts = Counter(e['timestamp'][:10] for e in events if e.get('timestamp'))
    return chart('Eventos por fecha',list(counts),list(counts.values()))
