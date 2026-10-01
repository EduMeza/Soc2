import React, { useEffect, useState, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../services/api';
import { useDataRevision } from '../hooks/useDataRevision';
import { EventDetailDrawer } from '../components/events/EventDetailDrawer';

interface EventItem {
  id: number;
  event_uid: string;
  timestamp: string;
  agent: string;
  hostname: string;
  source: string;
  event_type: string;
  rule_id: string;
  rule_description: string;
  severity: string;
  original_severity: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  protocol: string;
  username: string;
  process: string;
  command: string;
  file_path: string;
  cve: string;
  mitre_tactic: string;
  mitre_technique: string;
  raw_event: string;
  risk_score: number;
  correlation_id: string;
  status: string;
  import_batch_id: string;
}

export const Events: React.FC = () => {
  const navigate = useNavigate();
  const requestSequence = useRef(0);
  const revision = useDataRevision();
  const [error, setError] = useState('');
  const [events, setEvents] = useState<EventItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [limit] = useState(50);
  const [filters, setFilters] = useState({
    search: '',
    severity: '',
    host: '',
    agent: '',
    source_ip: '',
    ip: '',
    rule: '',
    mitre: '',
    min_risk: '',
    start_date: '',
    end_date: '',
    sort_by: 'id',
    sort_order: 'desc',
  });
  const [selectedEvent, setSelectedEvent] = useState<EventItem | null>(null);

  const fetchEvents = async () => {
    const sequence = ++requestSequence.current;
    setLoading(true);
    setError('');
    try {
      const params = new URLSearchParams();
      params.append('page', page.toString());
      params.append('limit', limit.toString());
      
      Object.entries(filters).forEach(([key, value]) => {
        if (value) params.append(key, value);
      });

      const response = await api.getEvents(page, limit, params.toString());
      if (sequence !== requestSequence.current) return;
      if (response.items) {
        setEvents(response.items);
        setTotal(response.total);
      }
    } catch (error) {
      if (sequence !== requestSequence.current) return;
      setError(error instanceof Error ? error.message : 'No se pudieron cargar los eventos');
      console.error('Error fetching events:', error);
    } finally {
      if (sequence === requestSequence.current) setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [page, filters, revision]);

  const handleFilterChange = (key: string, value: string) => {
    setFilters(prev => ({ ...prev, [key]: value }));
    setPage(1);
  };

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
  };

  const clearFilters = () => {
    setFilters({
      search: '', severity: '', host: '', agent: '', source_ip: '', ip: '', rule: '',
      mitre: '', min_risk: '', start_date: '', end_date: '',
      sort_by: 'id', sort_order: 'desc',
    });
    setPage(1);
  };

  const severityColor = (severity: string) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
      case 'crítico':
        return 'bg-red-900 text-red-300';
      case 'high':
      case 'alta':
        return 'bg-orange-900 text-orange-300';
      case 'medium':
      case 'media':
        return 'bg-yellow-900 text-yellow-300';
      default:
        return 'bg-slate-700 text-slate-300';
    }
  };

  const openEventDetail = async (event: EventItem) => {
    try { setSelectedEvent(await api.request<EventItem>(`/events/${event.id}`)); }
    catch(e: any) { setError(e.message); }
  };

  const exportPage = () => {
    const url = URL.createObjectURL(new Blob([JSON.stringify(events,null,2)], {type:'application/json'}));
    const link = document.createElement('a'); link.href = url; link.download = `events-page-${page}.json`; link.click();
    requestAnimationFrame(() => URL.revokeObjectURL(url));
  };

  const closeEventDetail = () => {
    setSelectedEvent(null);
  };

  return (
    <div className="space-y-6">
      {error && <p role="alert" className="text-red-400">{error}</p>}
      <div className="flex flex-col sm:flex-row gap-4 items-start justify-between">
        <div>
          <h2 className="text-2xl font-extrabold text-white">Eventos</h2>
          <p className="text-slate-400 text-sm">Gestión y análisis de eventos de seguridad</p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => navigate('/import')} className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold rounded-lg transition">
            Importar CSV
          </button>
          <button onClick={exportPage} disabled={loading || !events.length} className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition">
            Exportar página JSON
          </button>
        </div>
      </div>

      {/* Filtros */}
      <div className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-extrabold text-white">Filtros</h3>
          <button
            onClick={clearFilters}
            className="px-3 py-1.5 text-xs bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-lg transition"
          >
            Limpiar filtros
          </button>
        </div>
        
        <form onSubmit={handleSearch} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Búsqueda</label>
              <input
                type="text"
                placeholder="Buscar en descripción, regla, CVE..."
                value={filters.search}
                onChange={(e) => handleFilterChange('search', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Severidad</label>
              <select
                value={filters.severity}
                onChange={(e) => handleFilterChange('severity', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              >
                <option value="">Todas</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Host</label>
              <input
                type="text"
                placeholder="Filtrar por host"
                value={filters.host}
                onChange={(e) => handleFilterChange('host', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Agente</label>
              <input
                type="text"
                placeholder="Filtrar por agente"
                value={filters.agent}
                onChange={(e) => handleFilterChange('agent', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">IP Origen</label>
              <input
                type="text"
                placeholder="Filtrar por IP"
                value={filters.source_ip}
                onChange={(e) => handleFilterChange('source_ip', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Regla</label>
              <input
                type="text"
                placeholder="Filtrar por regla"
                value={filters.rule}
                onChange={(e) => handleFilterChange('rule', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">MITRE</label>
              <input
                type="text"
                placeholder="Táctica/Técnica"
                value={filters.mitre}
                onChange={(e) => handleFilterChange('mitre', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Riesgo Mín.</label>
              <input
                type="number"
                placeholder="0-100"
                min="0"
                max="100"
                value={filters.min_risk}
                onChange={(e) => handleFilterChange('min_risk', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Fecha desde</label>
              <input
                type="date"
                value={filters.start_date}
                onChange={(e) => handleFilterChange('start_date', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Fecha hasta</label>
              <input
                type="date"
                value={filters.end_date}
                onChange={(e) => handleFilterChange('end_date', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Ordenar por</label>
              <select
                value={filters.sort_by}
                onChange={(e) => handleFilterChange('sort_by', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              >
                <option value="id">ID</option>
                <option value="timestamp">Timestamp</option>
                <option value="severity">Severidad</option>
                <option value="agent">Agente</option>
                <option value="hostname">Host</option>
                <option value="rule_id">Regla</option>
                <option value="risk_score">Riesgo</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-bold text-slate-400 uppercase mb-1">Orden</label>
              <select
                value={filters.sort_order}
                onChange={(e) => handleFilterChange('sort_order', e.target.value)}
                className="w-full px-4 py-2 rounded-lg bg-slate-950 border border-slate-700 text-slate-100 focus:outline-none focus:ring-2 focus:ring-emerald-500"
              >
                <option value="desc">Descendente</option>
                <option value="asc">Ascendente</option>
              </select>
            </div>
          </div>
        </form>
      </div>

      {/* Tabla de eventos */}
      <div className="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center h-64">
            <div className="animate-spin rounded-full h-12 w-12 border-4 border-emerald-500 border-t-transparent"></div>
          </div>
        ) : events.length === 0 ? (
          <div className="flex items-center justify-center h-64 text-slate-500">
            <p>No se encontraron eventos</p>
          </div>
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left text-slate-300">
                <thead className="text-xs uppercase bg-slate-700 text-slate-400">
                  <tr>
                    <th className="p-2 border border-slate-600 cursor-pointer hover:bg-slate-600" onClick={() => handleFilterChange('sort_by', 'timestamp')}>
                      Timestamp {filters.sort_by === 'timestamp' && (filters.sort_order === 'desc' ? ' ↓' : ' ↑')}
                    </th>
                    <th className="p-2 border border-slate-600 cursor-pointer hover:bg-slate-600" onClick={() => handleFilterChange('sort_by', 'severity')}>
                      Severidad {filters.sort_by === 'severity' && (filters.sort_order === 'desc' ? ' ↓' : ' ↑')}
                    </th>
                    <th className="p-2 border border-slate-600 cursor-pointer hover:bg-slate-600" onClick={() => handleFilterChange('sort_by', 'hostname')}>
                      Host {filters.sort_by === 'hostname' && (filters.sort_order === 'desc' ? ' ↓' : ' ↑')}
                    </th>
                    <th className="p-2 border border-slate-600 cursor-pointer hover:bg-slate-600" onClick={() => handleFilterChange('sort_by', 'rule_id')}>
                      Regla {filters.sort_by === 'rule_id' && (filters.sort_order === 'desc' ? ' ↓' : ' ↑')}
                    </th>
                    <th className="p-2 border border-slate-600">Descripción</th>
                    <th className="p-2 border border-slate-600 cursor-pointer hover:bg-slate-600" onClick={() => handleFilterChange('sort_by', 'source_ip')}>
                      IP Origen {filters.sort_by === 'source_ip' && (filters.sort_order === 'desc' ? ' ↓' : ' ↑')}
                    </th>
                    <th className="p-2 border border-slate-600">CVE</th>
                    <th className="p-2 border border-slate-600 cursor-pointer hover:bg-slate-600" onClick={() => handleFilterChange('sort_by', 'risk_score')}>
                      Riesgo {filters.sort_by === 'risk_score' && (filters.sort_order === 'desc' ? ' ↓' : ' ↑')}
                    </th>
                    <th className="p-2 border border-slate-600">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e: EventItem) => (
                    <tr key={e.id} className="border-b border-slate-700 hover:bg-slate-800 cursor-pointer" onClick={() => openEventDetail(e)}>
                      <td className="p-2 border border-slate-700 text-xs font-mono">{e.timestamp}</td>
                      <td>
                        <span className={`px-2 py-0.5 text-xs font-bold rounded ${severityColor(e.severity)}`}>
                          {e.severity || e.original_severity}
                        </span>
                      </td>
                      <td className="px-4 py-2">{e.hostname || e.agent}</td>
                      <td className="px-4 py-2 text-xs text-purple-300 font-mono">{e.rule_id || '-'}</td>
                      <td className="px-4 py-2 max-w-xs truncate">{e.rule_description || e.raw_event || '-'}</td>
                      <td className="px-4 py-2 font-mono text-xs">{e.source_ip || '-'}</td>
                      <td className="px-4 py-2 text-xs text-amber-300 font-mono">{e.cve || '-'}</td>
                      <td className="px-4 py-2">
                        <span className={`px-2 py-0.5 text-xs font-bold rounded ${e.risk_score >= 70 ? 'bg-red-900 text-red-300' : e.risk_score >= 40 ? 'bg-orange-900 text-orange-300' : e.risk_score >= 20 ? 'bg-yellow-900 text-yellow-300' : 'bg-green-900 text-green-300'}`}>
                          {Math.round(e.risk_score || 0)}/100
                        </span>
                      </td>
                      <td className="px-4 py-2 text-center">
                        <button
                          onClick={(ev) => { ev.stopPropagation(); openEventDetail(e); }}
                          className="px-3 py-1 text-xs bg-emerald-600 hover:bg-emerald-700 text-white rounded transition"
                        >
                          Ver
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Paginación */}
            <div className="flex items-center justify-between p-4 border-t border-slate-700">
              <p className="text-sm text-slate-400">
                Mostrando {((page - 1) * limit) + 1}-{Math.min(page * limit, total)} de {total} eventos
              </p>
              <div className="flex gap-2">
                <button
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page <= 1}
                  className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Anterior
                </button>
                <button
                  onClick={() => setPage(p => Math.min(Math.ceil(total / limit), p + 1))}
                  disabled={page * limit >= total}
                  className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Siguiente
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      {/* Event Detail Drawer */}
      <EventDetailDrawer
        event={selectedEvent}
        isOpen={!!selectedEvent}
        onClose={closeEventDetail}
      />
    </div>
  );
};

export default Events;
