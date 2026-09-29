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

interface TopAgentChartProps {
  data: Array<{ agent: string; count: number }>;
  color?: string;
}

interface TopHostChartProps {
  data: Array<{ host: string; count: number }>;
  color?: string;
}

export const TopAgentsChart: React.FC<TopAgentChartProps> = ({ data, color = '#10b981' }) => {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500">
        Sin datos de agentes
      </div>
    );
  }

  const chartData = data.map((d, i) => ({
    name: d.agent || 'Unknown',
    value: d.count,
    index: i + 1,
  }));

  return (
    <div style={{height: Math.max(240, chartData.length * 32)}}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} />
          <YAxis
            type="category"
            dataKey="name"
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
            dataKey="value"
            name="Eventos"
            fill={color}
            radius={[0, 4, 4, 0]}
            maxBarSize={30}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export const TopHostsChart: React.FC<TopHostChartProps> = ({ data, color = '#f97316' }) => {
  if (!data || data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-500">
        Sin datos de hosts
      </div>
    );
  }

  const chartData = data.map((d) => ({
    name: d.host || 'Unknown',
    value: d.count,
  }));

  return (
    <div style={{height: Math.max(240, chartData.length * 32)}}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} layout="vertical">
          <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
          <XAxis type="number" tick={{ fill: '#94a3b8', fontSize: 11 }} axisLine={false} />
          <YAxis
            type="category"
            dataKey="name"
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
            dataKey="value"
            name="Eventos"
            fill={color}
            radius={[0, 4, 4, 0]}
            maxBarSize={30}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default { TopAgentsChart, TopHostsChart };
