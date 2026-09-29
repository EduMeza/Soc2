import React, { useEffect, useMemo } from 'react';
import { ReactFlow, Background, Controls, MiniMap, Panel, Handle, Position, useNodesState } from '@xyflow/react';
import '@xyflow/react/dist/style.css';

export interface GraphNodeData extends Record<string, unknown> {
  label: string; type: 'ip' | 'host' | 'event' | 'rule' | 'mitre' | 'cve'; severity?: string; details?: Record<string, any>;
}
export interface GraphNode { id: string; type: GraphNodeData['type']; position: {x:number; y:number}; data: GraphNodeData; }
export interface GraphEdge { id: string; source: string; target: string; type?: string; data: {relationship:string}; }
const colors: Record<string,string> = {ip:'#38bdf8',host:'#fb923c',event:'#a78bfa',rule:'#60a5fa',mitre:'#f472b6',cve:'#facc15'};
const labels: Record<string,string> = {ip:'IP',host:'Host',event:'Evento',rule:'Regla',mitre:'MITRE',cve:'CVE'};
const EntityNode = ({data}: {data:GraphNodeData}) => <div className="graph-entity" style={{borderColor: colors[data.type]}}>
  <Handle type="target" position={Position.Left} />
  <p className="text-xs font-semibold uppercase mb-2" style={{color:colors[data.type]}}>{labels[data.type]}</p>
  <p className="text-sm text-slate-100 truncate" title={data.label}>{data.label}</p>
  <Handle type="source" position={Position.Right} />
</div>;
const nodeTypes = Object.fromEntries(Object.keys(colors).map(type => [type, EntityNode]));

export const RelationshipGraph: React.FC<{nodes:GraphNode[]; edges:GraphEdge[]; height?:string; onNodeClick?:(node:GraphNode)=>void}> = ({nodes,edges,height='650px',onNodeClick}) => {
  const layout = useMemo(() => {
    const counters:Record<string,number> = {};
    const types = ['ip','host','event','rule','mitre','cve'];
    // Wrap each type into columns of 12, reserving space for the next group.
    const offsets:Record<string,number> = {}; let offset = 0;
    types.forEach(type => { offsets[type] = offset; offset += Math.max(1, Math.ceil(nodes.filter(n=>n.type===type).length/12)) * 260; });
    return nodes.map(node => { const index = counters[node.type] || 0; counters[node.type] = index+1;
      return {...node, position:{x: offsets[node.type] + Math.floor(index/12)*260, y:(index%12)*112}};
    });
  },[nodes]);
  const [displayNodes,setNodes,onNodesChange] = useNodesState<any>(layout);
  useEffect(()=>setNodes(layout),[layout,setNodes]);
  const displayEdges = useMemo(()=>edges.map(edge=>({...edge,type:'default',style:{stroke:'#526783',strokeWidth:1.3},animated:false})),[edges]);
  return <div style={{height}} className="relative">
    <ReactFlow nodes={displayNodes} edges={displayEdges} nodeTypes={nodeTypes} onNodesChange={onNodesChange} colorMode="dark" fitView minZoom={0.03} maxZoom={2} fitViewOptions={{padding:0.15}} onNodeClick={(_,node)=>onNodeClick?.(node as GraphNode)}>
      <Background color="#25344b" gap={24} /><Controls /><MiniMap pannable zoomable nodeColor={node=>colors[String(node.data.type)] || '#64748b'} />
      <Panel position="top-left"><div className="graph-legend">{Object.entries(labels).map(([type,label])=><span key={type}><i style={{background:colors[type]}} />{label}</span>)}<small>Zoom para explorar · clic para detalle · arrastrar para reorganizar</small></div></Panel>
    </ReactFlow>
  </div>;
};
export default RelationshipGraph;
