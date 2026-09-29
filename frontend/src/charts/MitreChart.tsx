import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  Cell,
} from 'recharts';

interface MitreChartProps {
  data: { tactics: Array<{ tactic: string; count: number }>; techniques: Array<{ technique: string; count: number }> } | null;
}

const TACTIC_COLORS: Record<string, string> = {
  'Reconocimiento': '#fbbf24',
  'Ejecución': '#ef4444',
  'Persistencia': '#a855f7',
  'Evasión de defensas': '#ec4899',
  'Exfiltración': '#06b6d4',
  'Comando y Control': '#8b5cf6',
  'Initial Access': '#f97316',
  'Execution': '#ef4444',
  'Persistence': '#a855f7',
  'Privilege Escalation': '#ec4899',
  'Defense Evasion': '#ec4899',
  'Credential Access': '#f43f5e',
  'Discovery': '#fbbf24',
  'Lateral Movement': '#8b5cf6',
  'Collection': '#06b6d4',
  'Command and Control': '#8b5cf6',
  'Exfiltration': '#06b6d4',
  'Impact': '#ef4444',
};

export const MitreChart: React.FC<MitreChartProps> = ({ data }) => {
  if (!data || (!data.tactics.length && !data.techniques.length)) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-slate-500">
        <div className="text-6xl mb-4">🎯</div>
        <p className="text-lg">Sin clasificación MITRE sustentada por los eventos actuales</p>
      </div>
    );
  }

  const tacticData = data.tactics.map((t) => ({
    name: t.tactic,
    count: t.count,
    color: TACTIC_COLORS[t.tactic] || '#64748b',
  }));

  const techniqueData = data.techniques.slice(0, 15).map((t) => ({
    name: t.technique.length > 30 ? t.technique.substring(0, 30) + '...' : t.technique,
    fullName: t.technique,
    count: t.count,
  }));

  return (
    <div className="space-y-8">
      <div>
        <h4 className="text-sm font-bold text-slate-400 mb-4 uppercase tracking-wide">Tácticas detectadas</h4>
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={tacticData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#94a3b8', fontSize: 11 }}
                axisLine={false}
                width={180}
              />
<Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} maxBarSize={30}>
                {tacticData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-bold text-slate-400 mb-4 uppercase tracking-wide">Top 15 Técnicas</h4>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={techniqueData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} />
              <YAxis
                type="category"
                dataKey="name"
                tick={{ fill: '#94a3b8', fontSize: 10 }}
                axisLine={false}
                width={280}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                }}
              />
              <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} maxBarSize={25} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {tacticData.map((tactic) => (
          <span
            key={tactic.name}
            className="px-2 py-1 text-xs font-medium rounded border"
            style={{
              backgroundColor: `${tactic.color}20`,
              borderColor: `${tactic.color}60`,
              color: tactic.color,
            }}
          >
            {tactic.name}: {tactic.count}
          </span>
        ))}
      </div>
    </div>
  );
};

export default MitreChart;