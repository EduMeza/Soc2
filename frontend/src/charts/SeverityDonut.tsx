import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts';

const SEVERITY_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f97316',
  Medium: '#eab308',
  Low: '#22c55e',
  Unknown: '#64748b',
  Info: '#3b82f6',
};

interface SeverityDonutProps {
  data: Record<string, number>;
}

export const SeverityDonut: React.FC<SeverityDonutProps> = ({ data }) => {
  const chartData = Object.entries(data).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1).toLowerCase(),
    value,
    color: SEVERITY_COLORS[name.charAt(0).toUpperCase() + name.slice(1).toLowerCase()] || '#64748b',
  })).filter(d => d.value > 0);

  if (chartData.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500">
        Sin datos de severidad
      </div>
    );
  }

  const total = chartData.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="min-w-0">
      <ResponsiveContainer width="100%" height={240}>
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={60}
            outerRadius={80}
            fill="#8884d8"
            paddingAngle={2}
            dataKey="value"
            label={false}
            labelLine={false}
          >
            {chartData.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#1e293b',
              border: '1px solid #334155',
              borderRadius: '8px',
            }}
          />
          <text x="50%" y="47%" textAnchor="middle" fill="#f1f5f9" fontSize={26} fontWeight={700}>{total}</text>
          <text x="50%" y="57%" textAnchor="middle" fill="#94a3b8" fontSize={12}>eventos</text>
        </PieChart>
      </ResponsiveContainer>
      <div className="flex flex-wrap justify-center items-center mt-2 gap-4 text-xs">
        {chartData.map((entry, i) => (
          <span key={i} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
            <span className="text-slate-300">{entry.name}: {entry.value} ({Math.round(entry.value / total * 100)}%)</span>
          </span>
        ))}
      </div>
    </div>
  );
};

export default SeverityDonut;
