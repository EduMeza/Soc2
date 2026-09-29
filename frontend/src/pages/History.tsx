import React, { useEffect, useState } from 'react';

export const History: React.FC = () => {
  interface HistoryItem {
    id: string;
    timestamp: string;
    analyst: string;
    entity: string;
    period: string;
    total_events: number;
    critical: number;
    high: number;
    risk_score: number;
    file_paths: Record<string, string>;
    summary: string;
  }
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setTimeout(() => {
      setHistory([
        { id: 'rpt_20260925_230000', timestamp: '2026-09-25T23:00:00Z', analyst: 'Eduardo Meza', entity: 'Medalla Milagrosa', period: 'Turno Noche (23:00)', total_events: 12538, critical: 44, high: 9688, risk_score: 78.5, file_paths: { pdf: '/output/soc_report_20260925_230000.pdf', json: '/output/soc_report_20260925_230000.json' }, summary: 'Reporte turno noche - 44 eventos críticos' },
        { id: 'rpt_20260925_160000', timestamp: '2026-09-25T16:00:00Z', analyst: 'Sistema Automático', entity: 'Medalla Milagrosa', period: 'Turno Tarde (16:00)', total_events: 12400, critical: 42, high: 9500, risk_score: 76.2, file_paths: { pdf: '/output/soc_report_20260925_160000.pdf', json: '/output/soc_report_20260925_160000.json' }, summary: 'Reporte turno tarde - Actividad moderada' },
        { id: 'rpt_20260925_070000', timestamp: '2026-09-25T07:00:00Z', analyst: 'Sistema Automático', entity: 'Medalla Milagrosa', period: 'Turno Mañana (07:00)', total_events: 12200, critical: 38, high: 9200, risk_score: 74.1, file_paths: { pdf: '/output/soc_report_20260925_070000.pdf', json: '/output/soc_report_20260925_070000.json' }, summary: 'Reporte turno mañana - Actividad normal' },
        { id: 'rpt_20260924_230000', timestamp: '2026-09-24T23:00:00Z', analyst: 'Eduardo Meza', entity: 'Medalla Milagrosa', period: 'Turno Noche (23:00)', total_events: 11800, critical: 35, high: 8900, risk_score: 71.5, file_paths: { pdf: '/output/soc_report_20260924_230000.pdf', json: '/output/soc_report_20260924_230000.json' }, summary: 'Reporte día anterior' },
      ]);
      setLoading(false);
    }, 500);
  }, []);

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
          <h2 className="text-2xl font-extrabold text-white">Historial</h2>
          <p className="text-slate-400 text-sm">Historial de reportes generados</p>
        </div>
      </div>

      <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left text-slate-300">
            <thead className="text-xs uppercase bg-slate-700 text-slate-400">
              <tr>
                <th className="p-2 border border-slate-600">ID</th>
                <th className="p-2 border border-slate-600">Fecha</th>
                <th className="p-2 border border-slate-600">Analista</th>
                <th className="p-2 border border-slate-600">Entidad</th>
                <th className="p-2 border border-slate-600">Periodo</th>
                <th className="p-2 border border-slate-600">Total Eventos</th>
                <th className="p-2 border border-slate-600">Críticos</th>
                <th className="p-2 border border-slate-600">Altos</th>
                <th className="p-2 border border-slate-600">Riesgo</th>
                <th className="p-2 border border-slate-600">Resumen</th>
                <th className="p-2 border border-slate-600">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {history.map((r, i) => (
                <tr key={i} className="border-b border-slate-700 hover:bg-slate-800">
                  <td className="p-2 border border-slate-700 text-xs font-mono">{r.id}</td>
                  <td className="p-2 border border-slate-700 text-xs">{new Date(r.timestamp).toLocaleString()}</td>
                  <td className="p-2 border border-slate-700">{r.analyst}</td>
                  <td className="p-2 border border-slate-700">{r.entity}</td>
                  <td className="p-2 border border-slate-700">{r.period}</td>
                  <td className="p-2 border border-slate-700 text-right font-bold">{r.total_events.toLocaleString()}</td>
                  <td className="p-2 border border-slate-700 text-red-400 font-bold">{r.critical}</td>
                  <td className="p-2 border border-slate-700 text-orange-400 font-bold">{r.high}</td>
                  <td className="p-2 border border-slate-700 text-amber-400 font-bold">{r.risk_score}%</td>
                  <td className="p-2 border border-slate-700 max-w-xs truncate">{r.summary}</td>
                  <td className="p-2 border border-slate-700">
                    <div className="flex gap-1">
                      <a href="#" className="px-2 py-1 text-xs bg-red-700 hover:bg-red-800 text-white rounded">PDF</a>
                      <a href="#" className="px-2 py-1 text-xs bg-emerald-700 hover:bg-emerald-800 text-white rounded">JSON</a>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default History;