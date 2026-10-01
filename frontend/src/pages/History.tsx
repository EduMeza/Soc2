import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

export const History: React.FC = () => {
  const [type, setType] = useState('import');
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<any[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  useEffect(() => {
    let active = true;
    setLoading(true); setError('');
    api.request<{ items: any[]; total: number }>(`/history?type=${type}&page=${page}&limit=20`)
      .then(data => { if (active) { setItems(data.items); setTotal(data.total); } })
      .catch(e => { if (active) setError(e.message); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [type, page]);
  const download = async (format: 'pdf'|'txt'|'json', id: string) => {
    try {
      const blob = await api.downloadReport(format,id);
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = url; link.download = `${id}.${format}`; link.click();
      requestAnimationFrame(() => URL.revokeObjectURL(url));
    } catch(e: any) { setError(e.message); }
  };
  return <div className="space-y-6">
    <h2 className="text-2xl font-extrabold text-white">Historial</h2>
    <div className="flex gap-3">{Object.entries({import:'Importaciones',report:'Reportes',scheduler:'Scheduler',audit:'Auditoría'}).map(([key,label]) =>
      <button key={key} onClick={() => { setType(key); setPage(1); }} className={`px-4 py-2 rounded ${type === key ? 'bg-emerald-700' : 'bg-slate-800'}`}>{label}</button>)}</div>
    {error && <p role="alert" className="text-red-400">{error}</p>}
    {loading ? <p>Cargando historial…</p> : !items.length ? <p>No hay registros.</p> : items.map(item =>
      <article key={item.id || item.report_id} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2">
        <p>{item.filename || item.entity || item.action || item.shift} · {item.status}</p>
        <p className="text-sm text-slate-400">{new Date(item.started_at || item.created_at || item.timestamp).toLocaleString()} · {item.username || item.created_by}</p>
        {type === 'import' && <p>Filas: {item.total_rows} · Insertadas: {item.inserted} · Duplicadas: {item.duplicates} · Rechazadas: {item.rejected}</p>}
        {type === 'report' && <><p>{item.period} · {item.total_events} eventos · Riesgo {item.risk_score}/100</p><div className="flex gap-3">{(['pdf','txt','json'] as const).filter(f => item.file_paths?.[f]).map(f => <button className="bg-emerald-700 px-3 py-1 rounded" key={f} onClick={() => download(f,item.report_id)}>{f.toUpperCase()}</button>)}</div></>}
        {type === 'audit' && <pre className="text-xs whitespace-pre-wrap">{JSON.stringify(item.details)}</pre>}
        {type === 'scheduler' && <p>Reporte: {item.report_id || 'No generado'}</p>}
      </article>)}
    <div className="flex gap-4"><button disabled={page === 1} onClick={() => setPage(p => p-1)}>Anterior</button><span>Página {page} · {total} registros</span><button disabled={page*20 >= total} onClick={() => setPage(p => p+1)}>Siguiente</button></div>
  </div>;
};
export default History;
