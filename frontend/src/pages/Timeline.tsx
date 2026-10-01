import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useDataRevision } from '../hooks/useDataRevision';

interface TimelineEvent {
  timestamp: string;
  severity: string;
  host: string;
  agent: string;
  source_ip: string;
  rule: string;
  description: string;
  mitre_tactic: string;
  mitre_technique: string;
  correlation_id: string;
}

export const Timeline: React.FC = () => {
  const revision = useDataRevision();
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(0);
  const [sequences, setSequences] = useState<any[]>([]);

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const data = await api.getTimeline(200);
        setTimeline(data);
        const attackData = await api.request<{sequences: any[]}>('/analytics/attack-sequences');
        setSequences(attackData.sequences);
      } catch (error) {
        setError('No se pudo cargar la línea temporal. Recargue para reintentar.');
        console.error('Error fetching timeline:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchTimeline();
  }, [revision]);

  const severityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-900 text-red-300';
      case 'High': return 'bg-orange-900 text-orange-300';
      case 'Medium': return 'bg-yellow-900 text-yellow-300';
      default: return 'bg-slate-700 text-slate-300';
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-emerald-500 border-t-transparent"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-extrabold text-white">Línea temporal</h2>
          <p className="text-slate-400 text-sm">Últimos 200 registros · orden cronológico · no implica una secuencia de ataque confirmada</p>
        </div>
      </div>

      {error && <div role="alert" className="error-panel">{error}</div>}
      {!error && sequences.length === 0 && <p>No se identificó una secuencia de ataque con evidencia suficiente.</p>}
      {sequences.map(s => <section key={s.correlation_id}><h3>Secuencia {s.correlation_id}</h3><pre className="whitespace-pre-wrap">{JSON.stringify(s,null,2)}</pre></section>)}
      <input className="input-field" aria-label="Filtrar línea temporal" placeholder="Buscar host, regla o descripción…" value={query} onChange={e=>{setQuery(e.target.value);setPage(0);}} />
      {timeline.length === 0 ? (
        <div className="bg-slate-900 rounded-2xl p-12 border border-slate-800 shadow-xl text-center">
          <div className="text-6xl mb-4">⏱️</div>
          <h3 className="text-xl font-bold text-slate-300 mb-2">No hay eventos para mostrar</h3>
          <p className="text-slate-500">
            Importe eventos CSV para generar la línea temporal de ataques.
          </p>
        </div>
      ) : (
        <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
          <div className="space-y-4">
            {timeline.filter(e=>`${e.host} ${e.agent} ${e.rule} ${e.description}`.toLowerCase().includes(query.toLowerCase())).slice(page*20,(page+1)*20).map((e, i) => (
              <div key={i} className="flex flex-wrap md:flex-nowrap items-start gap-4 p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-emerald-500/30 transition">
                <div className="flex flex-col items-center w-3 shrink-0 pt-2">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                  <div className="h-full w-0.5 bg-slate-700 flex-1" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-2">
                    <span className="text-xs text-slate-400 font-mono whitespace-nowrap">
                      {e.timestamp ? new Date(e.timestamp).toLocaleString() : 'Fecha no disponible'}
                    </span>
                    <span className={`px-2 py-0.5 text-xs font-bold rounded ${severityColor(e.severity)}`}>
                      {e.severity}
                    </span>
                  </div>
                  <div className="text-sm font-medium text-slate-200 break-words">{e.description || `Regla ${e.rule || 'sin descripción'}`}</div>
                  <div className="text-xs text-purple-400 mt-1">
                    {[e.mitre_tactic, e.mitre_technique].filter(Boolean).join(' / ')}
                    {e.correlation_id && <span className="ml-2 px-1.5 py-0.5 text-xs bg-amber-900/30 text-amber-300 rounded">Corr: {e.correlation_id}</span>}
                  </div>
                </div>
                <div className="text-right w-32 shrink-0 text-xs text-slate-400">
                  <div className="font-semibold">{e.host || e.agent}</div>
                  <div className="text-slate-500">{e.source_ip}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      <div className="flex justify-between items-center text-sm"><button className="btn-secondary" disabled={page===0} onClick={()=>setPage(page-1)}>Anterior</button><span>Página {page+1}</span><button className="btn-secondary" disabled={(page+1)*20>=timeline.filter(e=>`${e.host} ${e.agent} ${e.rule} ${e.description}`.toLowerCase().includes(query.toLowerCase())).length} onClick={()=>setPage(page+1)}>Siguiente</button></div>
    </div>
  );
};

export default Timeline;
