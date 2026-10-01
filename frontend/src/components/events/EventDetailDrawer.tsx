import React from 'react';

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
  risk_factors?: Record<string, number>;
  mitre_evidence?: Array<Record<string, string>>;
  correlation_id: string;
  status: string;
  import_batch_id: string;
}

interface EventDetailDrawerProps {
  event: EventItem | null;
  isOpen: boolean;
  onClose: () => void;
}

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({
  event,
  isOpen,
  onClose,
}) => {
  if (!isOpen || !event) return null;

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

  const formatValue = (value: any) => {
    if (value === undefined || value === null || value === '') return '-';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
      <div className="bg-slate-900 rounded-2xl shadow-2xl w-full max-w-4xl h-[90vh] flex flex-col animate-slide-in">
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b border-slate-800">
          <div className="flex items-center gap-4">
            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition"
            >
              ✕
            </button>
            <div>
              <h3 className="text-xl font-extrabold text-white">Detalle del Evento</h3>
              <p className="text-sm text-slate-400 font-mono">ID: {event.id} | UID: {event.event_uid}</p>
            </div>
            <span className={`ml-auto px-3 py-1 text-sm font-bold rounded ${severityColor(event.severity)}`}>
              {event.severity || event.original_severity}
            </span>
          </div>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Basic Info Grid */}
          <section className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Timestamp</p>
              <p className="font-mono text-sm text-slate-200">{event.timestamp}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Host</p>
              <p className="font-semibold text-white">{event.hostname || event.agent}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Agente</p>
              <p className="font-semibold text-white">{event.agent}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">IP Origen</p>
              <p className="font-mono text-sm text-slate-200">{event.source_ip || '-'}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">IP Destino</p>
              <p className="font-mono text-sm text-slate-200">{event.destination_ip || '-'}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Puertos</p>
              <p className="font-mono text-sm text-slate-200">
                {event.source_port} → {event.destination_port} ({event.protocol || '-'})
              </p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Regla</p>
              <p className="font-mono text-sm text-purple-300">{event.rule_id || '-'}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">CVE</p>
              <p className="font-mono text-sm text-amber-300">{event.cve || '-'}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">MITRE</p>
              <p className="font-mono text-sm text-pink-300">
                {event.mitre_tactic} / {event.mitre_technique}
              </p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Usuario</p>
              <p className="font-mono text-sm text-slate-200">{event.username || '-'}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Proceso</p>
              <p className="font-mono text-sm text-slate-200 truncate">{event.process || '-'}</p>
            </div>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Riesgo</p>
              <p className="font-bold text-lg text-emerald-400">{Math.round(event.risk_score || 0)}/100</p>
            </div>
          </section>

          <section><h4>Factores de riesgo y evidencia MITRE</h4><pre className="whitespace-pre-wrap text-sm">{JSON.stringify({risk_factors:event.risk_factors,mitre_evidence:event.mitre_evidence},null,2)}</pre></section>

          {/* Description */}
          <section>
            <h4 className="text-lg font-extrabold text-white mb-3">Descripción</h4>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
              <p className="text-slate-300 whitespace-pre-wrap">{event.rule_description || event.raw_event || 'Sin descripción'}</p>
            </div>
          </section>

          {/* Command / Process Details */}
          {(event.command || event.process) && (
            <section>
              <h4 className="text-lg font-extrabold text-white mb-3">Comando / Proceso</h4>
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 overflow-x-auto">
                <pre className="text-sm text-slate-300 font-mono whitespace-pre-wrap">
                  {event.command || event.process}
                </pre>
              </div>
            </section>
          )}

          {/* File Path */}
          {(event.file_path) && (
            <section>
              <h4 className="text-lg font-extrabold text-white mb-3">Ruta del Archivo</h4>
              <div className="bg-slate-950 rounded-xl p-4 border border-slate-800">
                <p className="font-mono text-sm text-slate-200 truncate">{event.file_path}</p>
              </div>
            </section>
          )}

          {/* Raw Event */}
          <section>
            <h4 className="text-lg font-extrabold text-white mb-3">Evento Raw (JSON)</h4>
            <div className="bg-slate-950 rounded-xl p-4 border border-slate-800 overflow-x-auto max-h-96">
              <pre className="text-xs text-slate-400 font-mono whitespace-pre-wrap">
                {JSON.stringify({
                  id: event.id,
                  event_uid: event.event_uid,
                  timestamp: event.timestamp,
                  agent: event.agent,
                  hostname: event.hostname,
                  source: event.source,
                  event_type: event.event_type,
                  rule_id: event.rule_id,
                  rule_description: event.rule_description,
                  severity: event.severity,
                  original_severity: event.original_severity,
                  source_ip: event.source_ip,
                  destination_ip: event.destination_ip,
                  source_port: event.source_port,
                  destination_port: event.destination_port,
                  protocol: event.protocol,
                  username: event.username,
                  process: event.process,
                  command: event.command,
                  file_path: event.file_path,
                  cve: event.cve,
                  mitre_tactic: event.mitre_tactic,
                  mitre_technique: event.mitre_technique,
                  risk_score: event.risk_score,
                  correlation_id: event.correlation_id,
                  status: event.status,
                  import_batch_id: event.import_batch_id,
                }, null, 2)}
              </pre>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="p-6 border-t border-slate-800 flex justify-end gap-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition"
          >
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
};

export default EventDetailDrawer;
