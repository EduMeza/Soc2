import React, { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';
import { api } from '../services/api';
import { SummaryData } from '../types';
import { SeverityDonut } from '../charts/SeverityDonut';
import { TopAgentsChart, TopHostsChart } from '../charts/TopCharts';
import { RiskChart } from '../charts/RiskChart';

export const Dashboard: React.FC = () => {
  const [summary, setSummary] = useState<SummaryData | null>(null);
  const [severity, setSeverity] = useState<Record<string, number>>({});
  const [agents, setAgents] = useState<Array<{agent: string; count: number}>>([]);
  const [hosts, setHosts] = useState<Array<{host: string; count: number}>>([]);
  const [rules, setRules] = useState<Array<{rule: string; count: number}>>([]);
  const [ips, setIps] = useState<Array<{ip: string; count: number}>>([]);
  const [risk, setRisk] = useState<Awaited<ReturnType<typeof api.getRiskAnalysis>> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [updated, setUpdated] = useState('');
  const load = async () => {
    setLoading(true); setError('');
    try {
      const [s, d, a, h, r, i, k] = await Promise.all([api.getSummary(), api.getSeverityDistribution(), api.getTopAgents(10), api.getTopHosts(10), api.getTopRules(10), api.getTopIps(10), api.getRiskAnalysis()]);
      setSummary(s); setSeverity(d); setAgents(a); setHosts(h); setRules(r); setIps(i); setRisk(k);
      setUpdated(new Date().toLocaleTimeString());
    } catch (e) { setError(e instanceof Error ? e.message : 'No se pudieron cargar los indicadores'); }
    finally { setLoading(false); }
  };
  useEffect(() => { void load(); }, []);
  const ranking = (rows: Array<{label: string; count: number}>, color: string) => rows.length ? <div className="space-y-4">{rows.map((row, index) => <div key={row.label}>
    <div className="flex justify-between gap-4 mb-2 text-sm"><span className="truncate" title={row.label}><span className="text-slate-500 mr-3">{String(index + 1).padStart(2, '0')}</span>{row.label}</span><strong className="tabular-nums">{row.count.toLocaleString()}</strong></div>
    <div className="h-1.5 rounded-full bg-slate-800"><div className={`h-full rounded-full ${color}`} style={{width: `${row.count / Math.max(...rows.map(r => r.count), 1) * 100}%`}} /></div>
  </div>)}</div> : <p className="empty-state">No hay datos disponibles.</p>;
  return <div className="space-y-6 animate-fade-in">
    <header className="dashboard-heading">
      <div><p className="eyebrow">MONITOREO DE SEGURIDAD</p><h1 className="text-3xl font-semibold tracking-tight">Resumen de operaciones</h1><p className="text-slate-400 mt-2 text-sm">Visibilidad de los eventos registrados y prioridades de revisión.</p></div>
      <div className="flex items-center gap-3"><span className="text-xs text-slate-500">{updated && `Actualizado ${updated}`}</span><button onClick={load} disabled={loading} className="btn-secondary">{loading ? 'Cargando…' : '↻ Actualizar'}</button></div>
    </header>
    <nav className="module-links" aria-label="Módulos de análisis">{[['/events','Eventos'],['/correlations','Correlaciones'],['/timeline','Línea temporal'],['/mitre','MITRE ATT&CK'],['/geoip','Mapa GeoIP'],['/graph','Relaciones'],['/reports','Reportes']].map(([path,label]) => <NavLink key={path} to={path}>{label}<span aria-hidden="true">↗</span></NavLink>)}</nav>
    {error && <div role="alert" className="error-panel">{error} <button onClick={load} className="underline ml-3">Reintentar</button></div>}
    {loading && !summary ? <div className="grid grid-cols-2 xl:grid-cols-4 gap-4" aria-label="Cargando indicadores">{[1,2,3,4].map(n => <div key={n} className="h-36 rounded-2xl bg-slate-800/60 animate-pulse" />)}</div> : summary && <>
      <section className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">{[
        ['Total de eventos',summary.total_events,'Registros disponibles','text-cyan-300'],['Eventos críticos',summary.critical,'Prioridad de revisión inmediata','text-red-400'],['Alta severidad',summary.high,'Validar legitimidad y alcance','text-orange-400'],['Agentes afectados',summary.agents,`${summary.hosts} hosts identificados`,'text-violet-400']
      ].map(([label,value,detail,color]) => <article key={String(label)} className="metric-card"><p className="text-sm text-slate-400">{label}</p><p className={`text-4xl font-semibold tabular-nums my-3 ${color}`}>{Number(value).toLocaleString()}</p><p className="text-xs text-slate-500">{detail}</p></article>)}</section>
      <section className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        <article className="chart-card"><h2>Distribución de severidades</h2><p className="chart-caption">Todos los registros · conteo por nivel</p><SeverityDonut data={severity} /></article>
        <article className="chart-card"><h2>Agentes con mayor actividad</h2><p className="chart-caption">Hasta 10 agentes · número de eventos</p><TopAgentsChart data={agents} /></article>
        <article className="chart-card"><h2>Hosts con mayor actividad</h2><p className="chart-caption">Hostname o agente cuando no hay hostname</p><TopHostsChart data={hosts} /></article>
        <article className="chart-card"><h2>Índice de riesgo</h2><p className="chart-caption">Escala de 0 a 100 · no representa probabilidad de compromiso</p><RiskChart data={risk} /></article>
        <article className="chart-card"><h2>Reglas más frecuentes</h2><p className="chart-caption">Concentración de actividad por regla</p>{ranking(rules.map(r => ({label:r.rule,count:r.count})), 'bg-violet-400')}</article>
        <article className="chart-card"><h2>IPs de origen observadas</h2><p className="chart-caption">Incluye direcciones privadas y públicas</p>{ranking(ips.map(i => ({label:i.ip,count:i.count})), 'bg-cyan-400')}</article>
      </section>
    </>}
  </div>;
};
export default Dashboard;
