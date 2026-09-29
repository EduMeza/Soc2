import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';

interface RiskChartProps {
  data: { overall_risk: number; per_agent: Record<string, number>; factors: Record<string, number> } | null;
}

export const RiskChart: React.FC<RiskChartProps> = ({ data }) => {
  if (!data || !data.per_agent || Object.keys(data.per_agent).length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500">
        Sin datos de riesgo
      </div>
    );
  }

  const chartData = Object.entries(data.per_agent)
    .map(([agent, score]) => ({ agent, score: Math.round(score) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const overallRisk = data.overall_risk || 0;
  const riskColor = overallRisk >= 70 ? '#ef4444' : overallRisk >= 40 ? '#f97316' : overallRisk >= 20 ? '#eab308' : '#22c55e';

  return (
    <div className="min-w-0 space-y-4">
      <div className="mb-4 text-center">
        <div className="relative inline-block">
          <svg width="80" height="80" className="-rotate-90">
            <circle
              cx="40"
              cy="40"
              r="32"
              fill="none"
              stroke="#334155"
              strokeWidth="8"
            />
            <circle
              cx="40"
              cy="40"
              r="32"
              fill="none"
              stroke={riskColor}
              strokeWidth="8"
              strokeDasharray={`${(overallRisk / 100) * 201} 201`}
              strokeLinecap="round"
              className="transition-all duration-1000"
            />
          </svg>
          <div className="absolute inset-0 flex items-center justify-center">
            <span className="text-lg font-semibold text-white">{overallRisk.toFixed(1)}</span>
          </div>
        </div>
        <p className="text-xs text-slate-400 mt-2">Índice global / 100</p>
      </div>

      <ResponsiveContainer width="100%" height={Math.max(160, chartData.length * 30)}>
        <BarChart data={chartData} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis type="number" domain={[0,100]} tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} />
          <YAxis
            type="category"
            interval={0}
            dataKey="agent"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={false}
            width={100}
          />
          <Tooltip
            cursor={{fill:'#38bdf8',fillOpacity:0.06}}
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
            }}
          />
          <Bar
            dataKey="score"
            name="Índice"
            fill={riskColor}
            radius={[0, 4, 4, 0]}
            maxBarSize={25}
          />
        </BarChart>
      </ResponsiveContainer>

      <div className="mt-4 grid grid-cols-3 gap-4 text-xs text-center">
        {Object.entries(data.factors).map(([key, value]) => (
          <div key={key} className="bg-slate-800/50 rounded-lg p-2">
            <p className="text-slate-500">{key.replace(/_/g, ' ')}</p>
            <p className="font-bold text-white">{value}</p>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RiskChart;
