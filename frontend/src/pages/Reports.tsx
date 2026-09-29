import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

interface ReportRecord {
  id: string;
  timestamp: string;
  analyst: string;
  entity: string;
  period?: string;
  total_events: number;
  critical: number;
  high: number;
  medium?: number;
  low?: number;
  risk_score: number;
  file_paths: Record<string, string>;
  summary?: string;
}

export const Reports: React.FC = () => {
  const [reportFormat, setReportFormat] = useState<'ejecutivo' | 'tecnico' | 'auditoria'>('ejecutivo');
  const [reportOutput, setReportOutput] = useState<'pdf' | 'txt' | 'json'>('pdf');
  const [message, setMessage] = useState('');
  const [reports, setReports] = useState<ReportRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [entity, setEntity] = useState('');
  const [analyst, setAnalyst] = useState('');
  const [downloading, setDownloading] = useState<string | null>(null);

  const loadReports = async () => {
    try {
      const history = await api.getReports();
      setReports(history);
    } catch {
      setMessage('Error al cargar el historial. Intente actualizar la página.');
    }
  };

  useEffect(() => {
    loadReports();
  }, []);

  const handleGenerateReport = async () => {
    setLoading(true);
    setMessage('');
    try {
      const res = await api.generateReport(reportOutput, reportFormat, true, entity, analyst);
      await loadReports();
      if (!res.files[reportOutput] || res.files[`${reportOutput}_error`]) {
        throw new Error(res.files[`${reportOutput}_error`] || 'No se pudo crear el formato seleccionado');
      }
      await handleDownload(reportOutput, res.report_id);
    } catch (error: any) {
      setMessage(`Error al generar reporte: ${error.message || 'desconocido'}`);
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (format: 'pdf' | 'txt' | 'json', reportId: string) => {
    setDownloading(`${reportId}:${format}`);
    setMessage('');
    try {
      const blob = await api.downloadReport(format, reportId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${reportId}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => window.URL.revokeObjectURL(url), 1000);
      setMessage(`Descarga iniciada: ${reportId}.${format}`);
    } catch (error: any) {
      setMessage(`Error descargando ${format}: ${error.message || 'desconocido'}`);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-extrabold text-white">Reportes</h2>
          <p className="text-slate-400 text-sm">Generación y gestión de reportes SOC</p>
        </div>
      </div>

      <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl space-y-6">
        <h3 className="text-xl font-extrabold text-white">Generar Reporte</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label className="text-sm text-slate-300">Cliente / entidad
            <input className="input-field mt-2" value={entity} onChange={e => setEntity(e.target.value)} placeholder="Nombre del cliente" />
          </label>
          <label className="text-sm text-slate-300">Analista responsable
            <input className="input-field mt-2" value={analyst} onChange={e => setAnalyst(e.target.value)} placeholder="Nombre para la firma (por defecto: usuario actual)" />
          </label>
        </div>
        <p className="text-sm text-slate-400">PDF listo para cliente · TXT resumido para copiar en WhatsApp · JSON con datos del análisis. El periodo se obtiene de los registros disponibles.</p>
        <div className="grid grid-cols-1 xl:grid-cols-3 items-end gap-5">
          <div>
            <label className="text-xs font-bold text-slate-400 uppercase block mb-1">Formato del reporte</label>
            <select value={reportFormat} onChange={(e) => setReportFormat(e.target.value as any)} className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm mt-1">
              <option value="ejecutivo">Ejecutivo - Resumen alto nivel</option>
              <option value="tecnico">Técnico - Detalles operativos</option>
              <option value="auditoria">Auditoría - Formato estructura</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-bold text-slate-400 uppercase block mb-1">Formato de salida</label>
            <select value={reportOutput} onChange={(e) => setReportOutput(e.target.value as any)} className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-sm mt-1">
              <option value="pdf">PDF</option>
              <option value="txt">TXT — WhatsApp</option>
              <option value="json">JSON</option>
            </select>
          </div>
          <div>
            <label className="text-xs font-bold text-slate-400 uppercase block mb-1">Acción</label>
            <button onClick={handleGenerateReport} disabled={loading || !!downloading} className="btn-primary w-full min-h-11">
              {loading ? 'Generando...' : 'Generar y descargar'}
            </button>
          </div>
        </div>
        {message && <p role="status" className={`text-sm rounded-lg border p-3 ${message.startsWith('Error') ? 'text-red-300 border-red-900 bg-red-950/30' : 'text-emerald-300 border-emerald-900 bg-emerald-950/30'}`}>{message}</p>}
      </section>

      <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl space-y-6">
        <h3 className="text-xl font-extrabold text-white">Historial de Reportes</h3>
        <div className="overflow-x-auto">
          <table className="w-full text-sm text-left text-slate-300">
            <thead className="text-xs uppercase bg-slate-700 text-slate-400">
              <tr>
                <th className="p-2 border border-slate-600">ID</th>
                <th className="p-2 border border-slate-600">Fecha</th>
                <th className="p-2 border border-slate-600">Analista</th>
                <th className="p-2 border border-slate-600">Entidad</th>
                <th className="p-2 border border-slate-600">Total Eventos</th>
                <th className="p-2 border border-slate-600">Críticos</th>
                <th className="p-2 border border-slate-600">Altos</th>
                <th className="p-2 border border-slate-600">Riesgo</th>
                <th className="p-2 border border-slate-600">Acciones</th>
              </tr>
            </thead>
            <tbody>
              {reports.length === 0 ? (
                <tr>
                  <td colSpan={9} className="p-6 text-center text-slate-500">No hay reportes generados aún. Importe un CSV y genere el primero.</td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr key={r.id} className="border-b border-slate-700 hover:bg-slate-800">
                    <td className="p-2 border border-slate-700 text-xs font-mono">{r.id}</td>
                    <td className="p-2 border border-slate-700 text-xs">{new Date(r.timestamp).toLocaleString()}</td>
                    <td className="p-2 border border-slate-700">{r.analyst}</td>
                    <td className="p-2 border border-slate-700">{r.entity}</td>
                    <td className="p-2 border border-slate-700 text-right font-bold">{r.total_events.toLocaleString()}</td>
                    <td className="p-2 border border-slate-700 text-red-400 font-bold">{r.critical}</td>
                    <td className="p-2 border border-slate-700 text-orange-400 font-bold">{r.high}</td>
                    <td className="p-2 border border-slate-700 text-amber-400 font-bold">{r.risk_score}%</td>
                    <td className="p-2 border border-slate-700">
                      <div className="flex gap-1">
                        {(['pdf', 'txt', 'json'] as const).map((f) => (
                          <button
                            key={f}
                            onClick={() => handleDownload(f, r.id)}
                            disabled={!!downloading || !r.file_paths?.[f] || !!r.file_paths[`${f}_error`]}
                            title={r.file_paths?.[f] ? `Descargar ${f.toUpperCase()}` : 'Formato no generado. Genere un nuevo reporte.'}
                            className="px-3 py-2 text-xs font-semibold border border-slate-600 bg-slate-800 hover:bg-emerald-700 disabled:opacity-40 text-white rounded-lg transition"
                          >
                            {downloading === `${r.id}:${f}` ? '...' : f.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
};

export default Reports;
