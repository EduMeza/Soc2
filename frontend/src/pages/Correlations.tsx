import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useDataRevision } from '../hooks/useDataRevision';

interface Correlation {
  id: string;
  title: string;
  severity: string;
  risk: number;
  first_seen: string;
  last_seen: string;
  hosts: string[];
  agents: string[];
  ips: string[];
  events: number;
  evidence: string[];
  confidence: number;
}

export const Correlations: React.FC = () => {
  const revision = useDataRevision();
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchCorrelations = async () => {
      try {
        const data = await api.getCorrelations();
        setCorrelations(data);
      } catch (error) {
        console.error('Error fetching correlations:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchCorrelations();
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
          <h2 className="text-2xl font-extrabold text-white">Correlaciones</h2>
          <p className="text-slate-400 text-sm">Agrupación automática de eventos relacionados</p>
        </div>
      </div>

      {correlations.length === 0 ? (
        <div className="bg-slate-900 rounded-2xl p-12 border border-slate-800 shadow-xl text-center">
          <div className="text-6xl mb-4">🔗</div>
          <h3 className="text-xl font-bold text-slate-300 mb-2">No se detectaron correlaciones</h3>
          <p className="text-slate-500">
            Los eventos actuales no muestran patrones de correlación significativos.
            Importe más eventos o ajuste las reglas de correlación.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          {correlations.map((corr) => (
            <div key={corr.id} className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl hover:border-emerald-500/30 transition">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-extrabold text-white">{corr.title}</h3>
                  <p className="text-xs text-slate-400 mt-1">{corr.events} eventos correlacionados</p>
                </div>
                <span className={`px-2 py-1 text-xs font-bold rounded ${severityColor(corr.severity)}`}>
                  {corr.severity}
                </span>
              </div>
              <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
                <div className="bg-slate-950 rounded-xl p-3 border border-slate-800">
                  <p className="text-xs text-slate-400">Severidad</p>
                  <p className="font-bold text-white">{corr.severity}</p>
                </div>
                <div className="bg-slate-950 rounded-xl p-3 border border-slate-800">
                  <p className="text-xs text-slate-400">Riesgo</p>
                  <p className="font-bold text-amber-400">{corr.risk}/100</p>
                </div>
                <div className="bg-slate-950 rounded-xl p-3 border border-slate-800">
                  <p className="text-xs text-slate-400" title="Coincidencia de IP, host, regla y ventana temporal; no es una probabilidad de compromiso">Soporte de evidencia</p>
                  <p className="font-bold text-emerald-400">{corr.confidence.toFixed(2)}/1</p>
                </div>
                <div className="bg-slate-950 rounded-xl p-3 border border-slate-800">
                  <p className="text-xs text-slate-400">Eventos</p>
                  <p className="font-bold text-white">{corr.events}</p>
                </div>
              </div>
              <div className="mb-4">
                <p className="text-xs text-slate-400 mb-1">Evidencia</p>
                <div className="flex flex-wrap gap-2">
                  {corr.evidence.map((e: string, i: number) => (
                    <span key={i} className="px-2 py-1 text-xs bg-amber-900/30 text-amber-300 rounded border border-amber-900/40">{e}</span>
                  ))}
                </div>
              </div>
              <div className="flex flex-col gap-2 text-xs text-slate-400">
                <span>Primera detección: {corr.first_seen}</span>
                <span>Última: {corr.last_seen}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default Correlations;
