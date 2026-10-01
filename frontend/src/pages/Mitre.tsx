import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { useDataRevision } from '../hooks/useDataRevision';
import { MitreChart } from '../charts/MitreChart';

interface MitreData {
  tactics: Array<{ tactic: string; count: number }>;
  techniques: Array<{ technique: string; count: number }>;
}

export const Mitre: React.FC = () => {
  const revision = useDataRevision();
  const [mitreData, setMitreData] = useState<MitreData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchMitre = async () => {
      try {
        const data = await api.getMitreDistribution();
        setMitreData(data);
      } catch (error) {
        console.error('Error fetching MITRE data:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchMitre();
  }, [revision]);

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
          <h2 className="text-2xl font-extrabold text-white">MITRE ATT&CK</h2>
          <p className="text-slate-400 text-sm">Clasificación de técnicas y tácticas detectadas</p>
        </div>
      </div>

      {mitreData ? (
        <>
          <section className="bg-gradient-to-br from-purple-900/30 to-slate-900 rounded-3xl p-8 border border-purple-900/40 shadow-2xl">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-3 h-3 rounded-full bg-purple-500 animate-pulse" />
              <h3 className="text-2xl font-extrabold text-purple-300">Clasificación MITRE ATT&CK</h3>
            </div>
            <MitreChart data={mitreData} />
          </section>
        </>
      ) : (
        <div className="bg-slate-900 rounded-2xl p-12 border border-slate-800 shadow-xl text-center">
          <div className="text-6xl mb-4">🎯</div>
          <h3 className="text-xl font-bold text-slate-300 mb-2">Sin clasificación MITRE</h3>
          <p className="text-slate-500">
            No se detectaron tácticas o técnicas MITRE en los eventos actuales.
            Importe eventos con campos MITRE (mitre_tactic, mitre_technique) para ver la clasificación.
          </p>
        </div>
      )}
    </div>
  );
};

export default Mitre;
