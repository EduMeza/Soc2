import { useEffect, useState } from 'react';
import { api } from '../services/api';

export function ScheduleSettings() {
  const [enabled,setEnabled] = useState(false);
  const [entity,setEntity] = useState('');
  const [timezone,setTimezone] = useState('');
  const [loading,setLoading] = useState(true);
  const [message,setMessage] = useState('');
  useEffect(() => {
    api.request<{schedules: Array<{enabled:boolean; entity:string; timezone:string}>}>('/schedules')
      .then(data => { setEnabled(data.schedules[0].enabled); setEntity(data.schedules[0].entity || ''); setTimezone(data.schedules[0].timezone); })
      .catch(e => setMessage(e.message)).finally(() => setLoading(false));
  }, []);
  const save = async () => {
    setLoading(true); setMessage('');
    try { await api.request('/schedules',{method:'PUT',body:JSON.stringify({enabled,entity})}); setMessage('Programación guardada'); }
    catch(e:any) { setMessage(e.message); }
    finally { setLoading(false); }
  };
  const run = async () => {
    setLoading(true); setMessage('');
    try {
      const result = await api.request<{execution_id:string; report_id:string; status:string}>('/schedules/run',{method:'POST'});
      setMessage(`Ejecución ${result.execution_id}: ${result.status} · Reporte ${result.report_id}`);
    } catch(e:any) { setMessage(e.message); }
    finally { setLoading(false); }
  };
  return <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 space-y-4">
    <h3 className="text-xl font-extrabold text-white">Reportes programados</h3>
    <p>{timezone} · 07:00 (00:00–06:59), 16:00 (07:00–15:59), 23:00 (16:00–22:59)</p>
    <label className="flex gap-3"><input type="checkbox" checked={enabled} disabled={loading} onChange={e => setEnabled(e.target.checked)} />Activar scheduler</label>
    <input aria-label="Entidad de reportes programados" className="input-field" value={entity} onChange={e => setEntity(e.target.value)} />
    <div className="flex gap-4"><button className="btn-primary" disabled={loading} onClick={save}>Guardar programación</button><button className="btn-secondary" disabled={loading} onClick={run}>Ejecutar ahora</button></div>
    {message && <p role="status">{message}</p>}
  </section>;
}
