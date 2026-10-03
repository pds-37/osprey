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
      <div className="border border-neutral-900 rounded-xl bg-neutral-950 p-16 text-center text-neutral-500">
        <Network className="w-10 h-10 mx-auto mb-3 opacity-30 text-neutral-400" />
        <p className="text-xs font-semibold text-neutral-300">Knowledge Graph is Empty</p>
        <p className="text-[11px] text-neutral-400 mt-1">Upload an SBOM to generate the dependency and asset knowledge graph.</p>
      </div>
    );
  }

  const nodes = graphData.nodes;
  const radius = Math.max(160, nodes.length * 28);
  const centerX = 400;
  const centerY = 300;

  const nodePositions = new Map<string, { x: number; y: number }>();
  nodes.forEach((node, i) => {
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
    <div className="relative border border-neutral-900 rounded-xl bg-black overflow-hidden h-[620px] flex">
      {/* Canvas Controls */}
      <div className="absolute top-3 left-3 z-10 flex items-center space-x-1.5 bg-neutral-950 border border-neutral-900 p-1 rounded-lg">
        <button
          onClick={() => setZoom((z) => Math.min(2, z + 0.15))}
          className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-900"
          title="Zoom In"
        >
          <ZoomIn className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}
          className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-900"
          title="Zoom Out"
        >
          <ZoomOut className="w-3.5 h-3.5" />
        </button>
        <button
          onClick={onRefresh}
          className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-900"
          title="Refresh Graph"
        >
          <RefreshCw className="w-3.5 h-3.5" />
        </button>
        <span className="text-[10px] font-mono text-neutral-400 px-1.5 border-l border-neutral-800">
          {nodes.length} nodes · {graphData.edges.length} edges
        </span>
      </div>

      {/* SVG Canvas */}
      <div className="flex-1 overflow-auto cursor-grab active:cursor-grabbing flex items-center justify-center p-8 bg-black">
        <svg
          viewBox="0 0 800 600"
          className="w-full h-full"
          style={{ transform: `scale(${zoom})`, transformOrigin: 'center' }}
        >
          <defs>
            <marker
              id="arrowhead"
              markerWidth="8"
              markerHeight="6"
              refX="14"
              refY="3"
              orient="auto"
            >
              <polygon points="0 0, 8 3, 0 6" fill="#404040" />
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
                  stroke="#262626"
                  strokeWidth="1.2"
                  strokeDasharray={edge.label === 'CONTAINS' ? '3 2' : undefined}
                  markerEnd="url(#arrowhead)"
                />
              </g>
            );
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const pos = nodePositions.get(node.id) || { x: centerX, y: centerY };
            const isSelected = selectedNode?.id === node.id;
            const accentColor = node.type === 'Application' ? '#ffffff' : node.color || '#a3a3a3';

            return (
              <g
                key={node.id}
                transform={`translate(${pos.x}, ${pos.y})`}
                onClick={() => setSelectedNode(node)}
                className="cursor-pointer group"
              >
                <circle
                  r={isSelected ? 18 : 14}
                  fill="#121212"
                  stroke={isSelected ? '#ffffff' : '#333333'}
                  strokeWidth={isSelected ? 2 : 1}
                  className="transition-all duration-150"
                />
                <circle
                  r="4"
                  fill={accentColor}
                />
                <text
                  y="24"
                  textAnchor="middle"
                  fill="#ededed"
                  fontSize="9"
                  fontFamily="sans-serif"
                  fontWeight="500"
                  className="pointer-events-none"
                >
                  {node.label.length > 18 ? node.label.substring(0, 16) + '...' : node.label}
                </text>
                <text
                  y="34"
                  textAnchor="middle"
                  fill="#737373"
                  fontSize="8"
                  fontFamily="monospace"
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
        <div className="w-72 border-l border-neutral-900 bg-neutral-950 p-4 flex flex-col justify-between overflow-y-auto">
          <div>
            <div className="flex items-center justify-between pb-2.5 border-b border-neutral-900 mb-3">
              <div className="flex items-center space-x-1.5">
                <Info className="w-3.5 h-3.5 text-neutral-400" />
                <h3 className="text-xs font-semibold text-white uppercase font-mono">Node Inspector</h3>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-neutral-500 hover:text-white text-xs"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-[10px] font-mono uppercase text-neutral-400">Label</span>
                <p className="text-xs font-semibold text-white mt-0.5">{selectedNode.label}</p>
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase text-neutral-400">Entity Type</span>
                <p className="text-xs text-neutral-300 font-mono mt-0.5">{selectedNode.type}</p>
              </div>

              {selectedNode.version && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400">Version</span>
                  <p className="text-xs font-mono text-neutral-300 mt-0.5">{selectedNode.version}</p>
                </div>
              )}

              <div>
                <span className="text-[10px] font-mono uppercase text-neutral-400">Canonical PURL</span>
                <p className="text-[10px] font-mono text-neutral-300 mt-0.5 break-all bg-black p-2 rounded border border-neutral-900">
                  {selectedNode.id}
                </p>
              </div>

              {selectedNode.state && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-400">Observed State</span>
                  <p className="text-xs font-mono font-medium text-emerald-400 mt-0.5">{selectedNode.state}</p>
                </div>
              )}
            </div>
          </div>

          <div className="pt-3 border-t border-neutral-900 text-[10px] font-mono text-neutral-400">
            Synchronized with Knowledge Graph
          </div>
        </div>
      )}
    </div>
  );
};
