import React, { useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';

interface ImportResult {
  message: string;
  inserted: number;
  batch_id: string;
  duplicates: number;
  rejected: number;
  total_rows: number;
  warnings: Array<{row: number; message: string}>;
  analysis?: {
    total_events: number;
    critical: number;
    high: number;
    agents: number;
    cves: number;
    suspicious_processes?: number;
    correlations: number;
    overall_risk: number;
  };
}

export const Import: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [result, setResult] = useState<ImportResult | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const navigate = useNavigate();

  const pickFile = (f: File | null) => {
    if (!f) return;
    if (!f.name.toLowerCase().endsWith('.csv')) {
      setMessage('Solo se admiten archivos CSV.');
      setFile(null);
      return;
    }
    setFile(f);
    setMessage('');
    setResult(null);
  };

  const handleUpload = async () => {
    if (!file) {
      setMessage('Seleccione un archivo CSV primero.');
      return;
    }
    setLoading(true);
    setMessage('');
    setResult(null);
    try {
      const res = await api.importCsv(file);
      setResult(res as ImportResult);
      setMessage('Importación completada correctamente.');
    } catch (error: any) {
      setMessage(error.message || 'Error al importar el CSV.');
    } finally {
      setLoading(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files?.[0];
    if (f) pickFile(f);
  };

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-extrabold text-white">Importar CSV</h2>
        <p className="text-slate-400 text-sm">Cargue un archivo CSV de eventos para analizarlo. El análisis se realiza automáticamente al importar.</p>
      </div>

      <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl space-y-4">
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`cursor-pointer border-2 border-dashed rounded-2xl p-10 text-center transition ${
            dragOver ? 'border-emerald-500 bg-emerald-950/30' : 'border-slate-700 hover:border-slate-500 bg-slate-950'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept=".csv"
            className="hidden"
            onChange={(e) => pickFile(e.target.files?.[0] ?? null)}
          />
          <p className="text-4xl mb-2">📄</p>
          <p className="text-sm text-slate-300 font-semibold">
            {file ? file.name : 'Arrastre el CSV aquí o haga clic para seleccionarlo'}
          </p>
          {file && <p className="text-xs text-slate-500 mt-1">{(file.size / 1024).toFixed(1)} KB</p>}
        </div>

        <div className="flex flex-wrap gap-3">
          <button
            onClick={handleUpload}
            disabled={!file || loading}
            className="px-5 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white text-sm font-bold rounded-lg transition shadow"
          >
            {loading ? 'Importando y analizando...' : 'Importar y analizar'}
          </button>
          <button
            onClick={() => navigate('/reports')}
            className="px-5 py-2 bg-amber-600 hover:bg-amber-700 text-white text-sm font-bold rounded-lg transition shadow"
          >
            Ir a Generar Reporte
          </button>
          <button
            onClick={() => navigate('/dashboard')}
            className="px-5 py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-bold rounded-lg transition shadow"
          >
            Ir al Dashboard
          </button>
        </div>

        {message && (
          <p className={`text-sm ${message.startsWith('Error') || message.startsWith('Solo') ? 'text-red-400' : 'text-emerald-400'}`}>
            {message}
          </p>
        )}
      </section>

      {result && (
        <section className="bg-slate-900 rounded-2xl p-6 border border-emerald-800/50 shadow-xl space-y-4">
          <h3 className="text-lg font-extrabold text-white">Resultado del análisis</h3>
          <p className="text-sm text-slate-400">Lote: <span className="font-mono text-slate-200">{result.batch_id}</span> · Insertados: {result.inserted}</p>
          <p>Filas: {result.total_rows} · Duplicadas: {result.duplicates} · Rechazadas: {result.rejected}</p>
          {!!result.warnings?.length && <details><summary>{result.warnings.length} advertencias</summary><ul>{result.warnings.slice(0,100).map((w,i) => <li key={i}>Fila {w.row}: {w.message}</li>)}</ul></details>}
          {result.analysis && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
                <p className="text-xs text-slate-500 uppercase">Total eventos</p>
                <p className="text-2xl font-extrabold text-emerald-400">{result.analysis.total_events}</p>
              </div>
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
                <p className="text-xs text-slate-500 uppercase">Críticos</p>
                <p className="text-2xl font-extrabold text-red-400">{result.analysis.critical}</p>
              </div>
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
                <p className="text-xs text-slate-500 uppercase">Alta severidad</p>
                <p className="text-2xl font-extrabold text-orange-400">{result.analysis.high}</p>
              </div>
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
                <p className="text-xs text-slate-500 uppercase">Riesgo global</p>
                <p className="text-2xl font-extrabold text-amber-400">{result.analysis.overall_risk}/100</p>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
};

export default Import;
