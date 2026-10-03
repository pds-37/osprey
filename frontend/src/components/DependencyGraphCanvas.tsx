import React, { useState } from 'react';
import { GraphData, GraphNode } from '../types';
import { Network, Info, ZoomIn, ZoomOut, RefreshCw } from 'lucide-react';

interface DependencyGraphCanvasProps {
  graphData: GraphData | null;
  onRefresh: () => void;
}

export const DependencyGraphCanvas: React.FC<DependencyGraphCanvasProps> = ({ graphData, onRefresh }) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState(1);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="border border-slate-800 rounded-2xl bg-slate-900/40 p-16 text-center text-slate-500">
        <Network className="w-12 h-12 mx-auto mb-3 opacity-40 text-blue-500" />
        <p className="text-sm font-semibold text-slate-300">Knowledge Graph is Empty</p>
        <p className="text-xs text-slate-500 mt-1">Upload an SBOM to generate the dependency and asset knowledge graph.</p>
      </div>
    );
  }

  // Simple automated circular/grid layout coordinates for nodes
  const nodes = graphData.nodes;
  const radius = Math.max(160, nodes.length * 28);
  const centerX = 400;
  const centerY = 300;

  const nodePositions = new Map<string, { x: number; y: number }>();
  nodes.forEach((node, i) => {
    // If root/container, place closer to center
    if (node.type === 'Container' || node.type === 'Application') {
      nodePositions.set(node.id, { x: centerX + (i % 2 === 0 ? -60 : 60), y: centerY + (i % 2 === 0 ? -40 : 40) });
    } else {
      const angle = (i / Math.max(1, nodes.length)) * 2 * Math.PI;
      const x = centerX + radius * Math.cos(angle);
      const y = centerY + radius * Math.sin(angle);
      nodePositions.set(node.id, { x, y });
    }
  });

  return (
    <div className="relative border border-slate-800 rounded-2xl bg-slate-950/60 backdrop-blur overflow-hidden shadow-2xl h-[650px] flex">
      {/* Canvas Controls */}
      <div className="absolute top-4 left-4 z-10 flex items-center space-x-2 bg-slate-900/90 border border-slate-800 p-1.5 rounded-xl backdrop-blur">
        <button
          onClick={() => setZoom((z) => Math.min(2, z + 0.15))}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4" />
        </button>
        <button
          onClick={onRefresh}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800"
          title="Refresh Graph"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
        <span className="text-[11px] font-mono text-slate-400 px-2">
          {nodes.length} nodes · {graphData.edges.length} edges
        </span>
      </div>

      {/* SVG Canvas */}
      <div className="flex-1 overflow-auto cursor-grab active:cursor-grabbing flex items-center justify-center p-8">
        <svg
          viewBox="0 0 800 600"
          className="w-full h-full"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center' }}
        >
          <defs>
            <marker
              id="arrowhead"
              markerWidth="10"
              markerHeight="7"
              refX="16"
              refY="3.5"
              orient="auto"
            >
              <polygon points="0 0, 10 3.5, 0 7" fill="#64748b" />
            </marker>
          </defs>

          {/* Edges */}
          {graphData.edges.map((edge, i) => {
            const srcPos = nodePositions.get(edge.source);
            const tgtPos = nodePositions.get(edge.target);
            if (!srcPos || !tgtPos) return null;

            return (
              <g key={`edge-${i}`}>
                <line
                  x1={srcPos.x}
                  y1={srcPos.y}
                  x2={tgtPos.x}
                  y2={tgtPos.y}
                  stroke="#334155"
                  strokeWidth="1.5"
                  strokeDasharray={edge.label === 'CONTAINS' ? '4 2' : undefined}
                  markerEnd="url(#arrowhead)"
                />
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const pos = nodePositions.get(node.id) || { x: centerX, y: centerY };
            const isSelected = selectedNode?.id === node.id;

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                <circle
                  r={isSelected ? 22 : 16}
                  fill={node.color || '#3b82f6'}
                  fillOpacity="0.25"
                  stroke={node.color || '#3b82f6'}
                  strokeWidth={isSelected ? 3 : 2}
                  className="transition-all duration-200 group-hover:scale-125"
                />
                <circle
                  r="6"
                  fill={node.color || '#3b82f6'}
                />
                <text
                  y="28"
                  textAnchor="middle"
                  fill="#cbd5e1"
                  fontSize="10"
                  fontFamily="Plus Jakarta Sans"
                  fontWeight="600"
                  className="pointer-events-none drop-shadow"
                >
                  {node.label.length > 18 ? node.label.substring(0, 16) + '...' : node.label}
                </text>
                <text
                  y="38"
                  textAnchor="middle"
                  fill="#64748b"
                  fontSize="8"
                  fontFamily="JetBrains Mono"
                  className="pointer-events-none"
                >
                  {node.version || node.type}
                </text>
              </g>
            );
          })}
        </svg>
      </div>

      {/* Node Inspector Drawer */}
      {selectedNode && (
        <div className="w-80 border-l border-slate-800 bg-[#0f172a]/95 backdrop-blur p-5 flex flex-col justify-between overflow-y-auto">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-4">
              <div className="flex items-center space-x-2">
                <Info className="w-4 h-4 text-blue-400" />
                <h3 className="text-xs font-bold text-white uppercase tracking-wider">Node Details</h3>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white text-xs font-bold"
              >
                ✕
              </button>
            </div>

            <div className="space-y-4">
              <div>
                <span className="text-[11px] font-semibold text-slate-500 uppercase">Label</span>
                <p className="text-sm font-bold text-white mt-0.5">{selectedNode.label}</p>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-slate-500 uppercase">Entity Type</span>
                <p className="text-xs text-blue-400 font-semibold mt-0.5">{selectedNode.type}</p>
              </div>

              {selectedNode.version && (
                <div>
                  <span className="text-[11px] font-semibold text-slate-500 uppercase">Version</span>
                  <p className="text-xs font-mono text-slate-200 mt-0.5">{selectedNode.version}</p>
                </div>
              )}

              <div>
                <span className="text-[11px] font-semibold text-slate-500 uppercase">Canonical PURL</span>
                <p className="text-[11px] font-mono text-slate-400 mt-0.5 break-all bg-slate-900 p-2 rounded-lg border border-slate-800">
                  {selectedNode.id}
                </p>
              </div>

              {selectedNode.state && (
                <div>
                  <span className="text-[11px] font-semibold text-slate-500 uppercase">Observed State</span>
                  <p className="text-xs font-semibold text-emerald-400 mt-0.5">{selectedNode.state}</p>
                </div>
              )}
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 text-[11px] text-slate-500">
            Node synchronized with Neo4j Knowledge Graph
          </div>
        </div>
      )}
    </div>
  );
};
