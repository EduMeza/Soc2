import React, { useEffect, useState } from 'react';
import { api } from '../services/api';
import { RelationshipGraph, GraphNodeData } from '../graphs/RelationshipGraph';

interface GraphNode {
  id: string;
  type: 'ip' | 'host' | 'event' | 'rule' | 'mitre' | 'cve';
  position: { x: number; y: number };
  data: GraphNodeData;
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type?: string;
  data: {
    relationship: string;
  };
}

export const Graph: React.FC = () => {
  const [graphData, setGraphData] = useState<{ nodes: GraphNode[]; edges: GraphEdge[] } | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  useEffect(() => {
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const data = await api.getGraph();
        setGraphData({
          nodes: data.nodes as GraphNode[],
          edges: data.edges as GraphEdge[],
        });
      } catch (err) {
        console.error('Error fetching graph:', err);
        setError('Error al cargar el grafo de relaciones');
      } finally {
        setLoading(false);
      }
    };
    fetchGraph();
  }, []);

  const handleNodeClick = (node: import('../graphs/RelationshipGraph').GraphNode) => {
    setSelectedNode(node);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-emerald-500 border-t-transparent"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64 text-red-400">
        <p>{error}</p>
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-96 text-slate-500">
        <div className="text-6xl mb-4">🕸️</div>
        <h3 className="text-xl font-bold text-slate-300 mb-2">Sin datos para el grafo</h3>
        <p className="text-slate-500">Importe eventos CSV para generar el grafo de relaciones</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-extrabold text-white">Grafo de Relaciones</h2>
          <p className="text-slate-400 text-sm">
            Relaciones entre IPs, hosts, eventos, reglas, MITRE y CVEs · muestra de los últimos 200 eventos
            <span className="ml-3 text-sm font-mono bg-slate-800 px-2 py-0.5 rounded">
              {graphData.nodes.length} nodos · {graphData.edges.length} aristas
            </span>
          </p>
        </div>
      </div>

      <section className="bg-slate-900 rounded-2xl border border-slate-800 shadow-xl overflow-hidden">
        <RelationshipGraph
          nodes={graphData.nodes}
          edges={graphData.edges}
          height="650px"
          onNodeClick={handleNodeClick}
        />
      </section>

      {selectedNode && (
        <section className="bg-slate-900 rounded-2xl p-6 border border-slate-800 shadow-xl animate-slide-in">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-xl font-extrabold text-white">Detalle del Nodo</h3>
            <button
              onClick={() => setSelectedNode(null)}
              className="text-slate-400 hover:text-white transition"
            >
              ✕ Cerrar
            </button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Tipo</p>
              <p className="font-bold text-white capitalize">{selectedNode.data.type}</p>
            </div>
            <div>
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Etiqueta</p>
              <p className="font-mono text-sm text-slate-200">{selectedNode.data.label}</p>
            </div>
            {selectedNode.data.severity && (
              <div>
                <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Severidad</p>
                <span className={`px-2 py-0.5 text-xs font-bold rounded ${
                  selectedNode.data.severity === 'Critical' ? 'bg-red-900 text-red-300' :
                  selectedNode.data.severity === 'High' ? 'bg-orange-900 text-orange-300' :
                  selectedNode.data.severity === 'Medium' ? 'bg-yellow-900 text-yellow-300' :
                  'bg-green-900 text-green-300'
                }`}>
                  {selectedNode.data.severity}
                </span>
              </div>
            )}
            <div className="md:col-span-2">
              <p className="text-xs text-slate-400 uppercase tracking-wide mb-1">Detalles adicionales</p>
              <pre className="bg-slate-950 p-3 rounded-lg text-xs text-slate-300 overflow-auto max-h-48">
                {JSON.stringify(selectedNode.data.details || {}, null, 2)}
              </pre>
            </div>
          </div>
        </section>
      )}
    </div>
  );
};

export default Graph;
