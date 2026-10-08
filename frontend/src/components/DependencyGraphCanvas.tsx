import React, { useState, useMemo, useEffect } from 'react';
import { GraphData, GraphNode } from '../types';
import { Network, Info, ZoomIn, ZoomOut, RefreshCw, Folder, Search, Sparkles, Maximize2, Minimize2 } from 'lucide-react';

interface DependencyGraphCanvasProps {
  graphData: GraphData | null;
  onRefresh: () => void;
  onOpenCopilot?: (componentName: string) => void;
}

export const DependencyGraphCanvas: React.FC<DependencyGraphCanvasProps> = ({
  graphData,
  onRefresh,
  onOpenCopilot,
}) => {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState(1);
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedFolder, setSelectedFolder] = useState<string>('ALL');
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Close fullscreen on Escape key
  useEffect(() => {
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isFullscreen) setIsFullscreen(false);
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [isFullscreen]);

  // Helper to extract folder/section from node
  const getNodeFolder = (node: GraphNode): string => {
    if (node.properties?.folder && node.properties.folder !== 'root') {
      return node.properties.folder;
    }
    if (node.properties?.source_file) {
      const parts = node.properties.source_file.replace(/\\/g, '/').split('/');
      if (parts.length > 1) return parts[0];
    }
    if (node.type === 'Container' || node.label.toLowerCase().includes('docker')) {
      return 'containers';
    }
    if (node.type === 'Application') {
      return 'root';
    }
    return 'root';
  };

  // Discover all unique folders
  const allFolders = useMemo(() => {
    if (!graphData?.nodes) return [];
    const foldersSet = new Set<string>();
    graphData.nodes.forEach((n) => {
      foldersSet.add(getNodeFolder(n));
    });
    return Array.from(foldersSet).sort();
  }, [graphData]);

  // Filtered nodes
  const filteredNodes = useMemo(() => {
    if (!graphData?.nodes) return [];
    return graphData.nodes.filter((node) => {
      // 1. Folder match
      if (selectedFolder !== 'ALL') {
        const folder = getNodeFolder(node);
        if (folder !== selectedFolder && node.type !== 'Application') {
          return false;
        }
      }
      // 2. Search query match
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchesLabel = node.label.toLowerCase().includes(q);
        const matchesType = node.type.toLowerCase().includes(q);
        const matchesId = node.id.toLowerCase().includes(q);
        return matchesLabel || matchesType || matchesId;
      }
      return true;
    });
  }, [graphData, selectedFolder, searchQuery]);

  // Filtered edges
  const filteredEdges = useMemo(() => {
    if (!graphData?.edges) return [];
    const validNodeIds = new Set(filteredNodes.map((n) => n.id));
    return graphData.edges.filter((e) => validNodeIds.has(e.source) && validNodeIds.has(e.target));
  }, [graphData, filteredNodes]);

  // Connected relations when a node is tapped (parents, children, and edges)
  const connectedInfo = useMemo(() => {
    if (!selectedNode || !graphData?.edges) {
      return {
        selectedId: null,
        outgoingEdgeKeys: new Set<string>(), // edges from selected -> children (dependencies)
        incomingEdgeKeys: new Set<string>(), // edges from parents -> selected (dependents)
        childNodeIds: new Set<string>(),
        parentNodeIds: new Set<string>(),
        allConnectedNodeIds: new Set<string>(),
      };
    }

    const selectedId = selectedNode.id;
    const outgoingEdgeKeys = new Set<string>();
    const incomingEdgeKeys = new Set<string>();
    const childNodeIds = new Set<string>();
    const parentNodeIds = new Set<string>();
    const allConnectedNodeIds = new Set<string>([selectedId]);

    graphData.edges.forEach((edge) => {
      const edgeKey = `${edge.source}->${edge.target}`;
      if (edge.source === selectedId) {
        outgoingEdgeKeys.add(edgeKey);
        childNodeIds.add(edge.target);
        allConnectedNodeIds.add(edge.target);
      }
      if (edge.target === selectedId) {
        incomingEdgeKeys.add(edgeKey);
        parentNodeIds.add(edge.source);
        allConnectedNodeIds.add(edge.source);
      }
    });

    return {
      selectedId,
      outgoingEdgeKeys,
      incomingEdgeKeys,
      childNodeIds,
      parentNodeIds,
      allConnectedNodeIds,
    };
  }, [selectedNode, graphData]);

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <div className="border border-neutral-900 rounded-xl bg-neutral-950 p-16 text-center text-neutral-500">
        <Network className="w-10 h-10 mx-auto mb-3 opacity-30 text-neutral-400" />
        <p className="text-xs font-semibold text-neutral-300">Knowledge Graph is Empty</p>
        <p className="text-[11px] text-neutral-400 mt-1">Scan a workspace to generate the dependency and service graph.</p>
      </div>
    );
  }

  // Hierarchical / Layered layout calculation
  const nodePositions = new Map<string, { x: number; y: number }>();
  const width = 860;
  const height = 580;

  // Group nodes by role / hierarchy level
  const rootNodes = filteredNodes.filter((n) => n.type === 'Application' || n.type === 'Service');
  const serviceNodes = filteredNodes.filter((n) => n.type === 'Container' || n.label.toLowerCase().includes('docker'));
  const libraryNodes = filteredNodes.filter((n) => !rootNodes.includes(n) && !serviceNodes.includes(n));

  // Level 1: Root Application
  rootNodes.forEach((node, idx) => {
    const spacing = width / (rootNodes.length + 1);
    nodePositions.set(node.id, { x: spacing * (idx + 1), y: 70 });
  });

  // Level 2: Containers / Services
  serviceNodes.forEach((node, idx) => {
    const spacing = width / (serviceNodes.length + 1);
    nodePositions.set(node.id, { x: spacing * (idx + 1), y: 190 });
  });

  // Level 3: Packages / Libraries in structured multi-row grid
  const cols = Math.min(6, Math.max(3, Math.ceil(Math.sqrt(libraryNodes.length * 1.5))));
  libraryNodes.forEach((node, idx) => {
    const row = Math.floor(idx / cols);
    const col = idx % cols;
    const itemsInThisRow = Math.min(cols, libraryNodes.length - row * cols);
    const xSpacing = width / (itemsInThisRow + 1);
    const ySpacing = 85;
    const startY = serviceNodes.length > 0 ? 300 : 180;

    nodePositions.set(node.id, {
      x: xSpacing * (col + 1),
      y: startY + row * ySpacing,
    });
  });

  return (
    <div className="relative border border-neutral-900 rounded-xl bg-black overflow-hidden h-[640px] flex flex-col">
      {/* Top Navigation & Filter Bar */}
      <div className="px-3 py-2 bg-neutral-950 border-b border-neutral-900 flex flex-wrap items-center justify-between gap-2 z-10">
        {/* Left: Folder / Section Navigation */}
        <div className="flex items-center space-x-1 overflow-x-auto text-xs py-0.5">
          <div className="flex items-center space-x-1 text-neutral-400 mr-1.5 shrink-0">
            <Folder className="w-3.5 h-3.5 text-neutral-400" />
            <span className="text-[11px] font-semibold uppercase tracking-wider text-neutral-300">Folders:</span>
          </div>

          <button
            onClick={() => setSelectedFolder('ALL')}
            className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 ${
              selectedFolder === 'ALL'
                ? 'bg-white text-black font-semibold'
                : 'bg-neutral-900 text-neutral-400 hover:text-white hover:bg-neutral-800'
            }`}
          >
            All ({graphData.nodes.length})
          </button>

          {allFolders.map((folder) => {
            const count = graphData.nodes.filter((n) => getNodeFolder(n) === folder).length;
            return (
              <button
                key={folder}
                onClick={() => setSelectedFolder(folder)}
                className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors shrink-0 flex items-center space-x-1 ${
                  selectedFolder === folder
                    ? 'bg-white text-black font-semibold'
                    : 'bg-neutral-900 text-neutral-400 hover:text-white hover:bg-neutral-800'
                }`}
              >
                <span>{folder}</span>
                <span className="text-[9px] opacity-75">({count})</span>
              </button>
            );
          })}
        </div>

        {/* Right: Search & Canvas Controls */}
        <div className="flex items-center space-x-2 shrink-0">
          <div className="relative">
            <Search className="w-3 h-3 text-neutral-500 absolute left-2 top-2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search package..."
              className="pl-6 pr-2 py-0.5 text-xs bg-black border border-neutral-800 rounded text-neutral-200 focus:outline-none focus:border-neutral-600 w-32 sm:w-44 font-mono"
            />
          </div>

          <div className="flex items-center space-x-1 bg-neutral-900 p-0.5 rounded border border-neutral-800">
            <button
              onClick={() => setZoom((z) => Math.min(2.5, z + 0.15))}
              className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-800"
              title="Zoom In"
            >
              <ZoomIn className="w-3 h-3" />
            </button>
            <button
              onClick={() => setZoom((z) => Math.max(0.4, z - 0.15))}
              className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-800"
              title="Zoom Out"
            >
              <ZoomOut className="w-3 h-3" />
            </button>
            <button
              onClick={() => setZoom(1)}
              className="px-1 text-[10px] font-mono text-neutral-400 hover:text-white"
              title="Reset Zoom"
            >
              100%
            </button>
            <button
              onClick={onRefresh}
              className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-800"
              title="Refresh"
            >
              <RefreshCw className="w-3 h-3" />
            </button>
            <div className="w-px h-4 bg-neutral-700 mx-0.5" />
            <button
              onClick={() => { setIsFullscreen(true); setZoom(1); }}
              className="p-1 rounded text-neutral-400 hover:text-white hover:bg-neutral-800"
              title="Open fullscreen graph view (Esc to close)"
            >
              <Maximize2 className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas Body */}
      <div className="flex-1 flex overflow-hidden relative">
        {/* Floating Focus Badge Strip */}
        {selectedNode && (
          <div className="absolute top-3 left-3 z-20 flex items-center space-x-2 bg-neutral-950/90 border border-neutral-800 backdrop-blur-md px-3 py-1.5 rounded-lg text-[11px] font-mono shadow-xl animate-in fade-in duration-150">
            <span className="text-white font-semibold flex items-center space-x-1.5">
              <span className="w-2 h-2 rounded-full bg-sky-400 inline-block" />
              <span>{selectedNode.label}</span>
            </span>
            <span className="text-neutral-700">|</span>
            <span className="text-purple-400 flex items-center space-x-1" title="Packages that depend on this">
              <span className="w-1.5 h-1.5 rounded-full bg-purple-400 inline-block" />
              <span>{connectedInfo.parentNodeIds.size} Upstream</span>
            </span>
            <span className="text-neutral-700">|</span>
            <span className="text-cyan-400 flex items-center space-x-1" title="Sub-dependencies used by this">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block" />
              <span>{connectedInfo.childNodeIds.size} Dependencies</span>
            </span>
            <button
              onClick={(e) => {
                e.stopPropagation();
                setSelectedNode(null);
              }}
              className="text-neutral-400 hover:text-white ml-2 text-[10px] px-1.5 py-0.5 rounded bg-neutral-900 hover:bg-neutral-800 border border-neutral-700"
              title="Clear selection"
            >
              ✕ Clear Focus
            </button>
          </div>
        )}

        <div
          className="flex-1 overflow-auto cursor-grab active:cursor-grabbing p-4 bg-black flex items-center justify-center"
          onClick={() => setSelectedNode(null)}
        >
          <svg
            viewBox={`0 0 ${width} ${Math.max(height, (libraryNodes.length / cols) * 90 + 350)}`}
            className="w-full h-full min-w-[700px] min-h-[500px]"
            style={{ transform: `scale(${zoom})`, transformOrigin: 'top center' }}
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
                <polygon points="0 0, 8 3, 0 6" fill="#333333" />
              </marker>
              <marker
                id="arrowhead-outgoing"
                markerWidth="8"
                markerHeight="6"
                refX="14"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#06b6d4" />
              </marker>
              <marker
                id="arrowhead-incoming"
                markerWidth="8"
                markerHeight="6"
                refX="14"
                refY="3"
                orient="auto"
              >
                <polygon points="0 0, 8 3, 0 6" fill="#c084fc" />
              </marker>
              <filter id="glow-selected" x="-30%" y="-30%" width="160%" height="160%">
                <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#38bdf8" floodOpacity="0.8" />
              </filter>
              <filter id="glow-outgoing" x="-30%" y="-30%" width="160%" height="160%">
                <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#06b6d4" floodOpacity="0.6" />
              </filter>
              <filter id="glow-incoming" x="-30%" y="-30%" width="160%" height="160%">
                <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#c084fc" floodOpacity="0.6" />
              </filter>
            </defs>

            {/* Edges with colored connection highlighting */}
            {filteredEdges.map((edge, i) => {
              const srcPos = nodePositions.get(edge.source);
              const tgtPos = nodePositions.get(edge.target);
              if (!srcPos || !tgtPos) return null;

              const edgeKey = `${edge.source}->${edge.target}`;
              const isOutgoing = connectedInfo.outgoingEdgeKeys.has(edgeKey);
              const isIncoming = connectedInfo.incomingEdgeKeys.has(edgeKey);
              const hasSelection = !!selectedNode;

              let strokeColor = "#262626";
              let strokeWidth = 1.2;
              let strokeOpacity = 1;
              let marker = "url(#arrowhead)";

              if (hasSelection) {
                if (isOutgoing) {
                  strokeColor = "#06b6d4"; // Vibrant Cyan for dependencies
                  strokeWidth = 2.5;
                  strokeOpacity = 1;
                  marker = "url(#arrowhead-outgoing)";
                } else if (isIncoming) {
                  strokeColor = "#c084fc"; // Vibrant Purple for upstream dependents
                  strokeWidth = 2.5;
                  strokeOpacity = 1;
                  marker = "url(#arrowhead-incoming)";
                } else {
                  strokeColor = "#1f1f1f";
                  strokeOpacity = 0.12;
                }
              }

              return (
                <g key={`edge-${i}`} opacity={strokeOpacity} className="transition-all duration-200">
                  <path
                    d={`M ${srcPos.x} ${srcPos.y + 16} C ${srcPos.x} ${(srcPos.y + tgtPos.y) / 2}, ${tgtPos.x} ${(srcPos.y + tgtPos.y) / 2}, ${tgtPos.x} ${tgtPos.y - 16}`}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    markerEnd={marker}
                  />
                </g>
              );
            })}

            {/* Nodes with vertex color highlighting */}
            {filteredNodes.map((node) => {
              const pos = nodePositions.get(node.id) || { x: width / 2, y: height / 2 };
              const isSelected = selectedNode?.id === node.id;
              const isChild = connectedInfo.childNodeIds.has(node.id);
              const isParent = connectedInfo.parentNodeIds.has(node.id);
              const isConnected = isSelected || isChild || isParent;
              const hasSelection = !!selectedNode;

              const isApp = node.type === 'Application';
              const isContainer = node.type === 'Container';

              let cardFill = isSelected ? '#0f172a' : isChild ? '#082f49' : isParent ? '#2e1065' : '#0a0a0a';
              let cardStroke = isSelected ? '#38bdf8' : isChild ? '#06b6d4' : isParent ? '#c084fc' : '#262626';
              let cardStrokeWidth = isSelected ? 2.5 : isConnected ? 1.8 : 1;
              let filter = isSelected ? 'url(#glow-selected)' : isChild ? 'url(#glow-outgoing)' : isParent ? 'url(#glow-incoming)' : undefined;
              let opacity = hasSelection ? (isConnected ? 1 : 0.2) : 1;

              let accentColor = isSelected ? '#38bdf8' : isChild ? '#06b6d4' : isParent ? '#c084fc' : (isApp ? '#ffffff' : isContainer ? '#38bdf8' : '#a3a3a3');
              let roleBadge = isSelected ? 'FOCUSED' : isChild ? 'DEPENDENCY' : isParent ? 'UPSTREAM' : (node.version ? `v${node.version}` : getNodeFolder(node));

              return (
                <g
                  key={node.id}
                  transform={`translate(${pos.x}, ${pos.y})`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode((prev) => (prev?.id === node.id ? null : node));
                  }}
                  opacity={opacity}
                  filter={filter}
                  className="cursor-pointer group transition-all duration-200"
                >
                  {/* Card Background */}
                  <rect
                    x="-65"
                    y="-16"
                    width="130"
                    height="32"
                    rx="6"
                    fill={cardFill}
                    stroke={cardStroke}
                    strokeWidth={cardStrokeWidth}
                  />

                  {/* Indicator Dot */}
                  <circle cx="-52" cy="0" r={isSelected ? 5 : 4} fill={accentColor} />

                  {/* Label */}
                  <text
                    x="-42"
                    y="-2"
                    fill={isSelected ? '#ffffff' : isChild ? '#e0f2fe' : isParent ? '#f3e8ff' : '#ededed'}
                    fontSize="9.5"
                    fontFamily="sans-serif"
                    fontWeight={isConnected ? '700' : '600'}
                    className="pointer-events-none"
                  >
                    {node.label.length > 13 ? node.label.substring(0, 12) + '…' : node.label}
                  </text>

                  {/* Subtitle / Role indicator */}
                  <text
                    x="-42"
                    y="9"
                    fill={isSelected ? '#7dd3fc' : isChild ? '#38bdf8' : isParent ? '#d8b4fe' : '#737373'}
                    fontSize="7.5"
                    fontFamily="monospace"
                    fontWeight={isConnected ? '600' : 'normal'}
                    className="pointer-events-none uppercase"
                  >
                    {roleBadge}
                  </text>
                </g>
              );
            })}
          </svg>
        </div>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="w-80 border-l border-neutral-900 bg-neutral-950 p-4 flex flex-col justify-between overflow-y-auto animate-in slide-in-from-right duration-150">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-2.5 border-b border-neutral-900">
                <div className="flex items-center space-x-1.5">
                  <Info className="w-3.5 h-3.5 text-neutral-400" />
                  <h3 className="text-xs font-semibold text-white uppercase font-mono">Component Details</h3>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-neutral-500 hover:text-white text-xs px-1"
                >
                  ✕
                </button>
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase text-neutral-500">Package Name</span>
                <p className="text-sm font-semibold text-white mt-0.5">{selectedNode.label}</p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div className="p-2 rounded bg-black border border-neutral-900">
                  <span className="text-[9px] font-mono uppercase text-neutral-500">Version</span>
                  <p className="text-xs font-mono text-neutral-300 mt-0.5">{selectedNode.version || 'latest'}</p>
                </div>
                <div className="p-2 rounded bg-black border border-neutral-900">
                  <span className="text-[9px] font-mono uppercase text-neutral-500">Section / Folder</span>
                  <p className="text-xs font-mono text-neutral-300 mt-0.5 truncate">{getNodeFolder(selectedNode)}</p>
                </div>
              </div>

              <div>
                <span className="text-[10px] font-mono uppercase text-neutral-500">Canonical Identifier (PURL)</span>
                <p className="text-[10px] font-mono text-neutral-300 mt-1 break-all bg-black p-2 rounded border border-neutral-900">
                  {selectedNode.id}
                </p>
              </div>

              {selectedNode.properties?.source_file && (
                <div>
                  <span className="text-[10px] font-mono uppercase text-neutral-500">Declared In Manifest</span>
                  <p className="text-xs font-mono text-emerald-400 mt-0.5 break-all">
                    {selectedNode.properties.source_file}
                  </p>
                </div>
              )}

              {onOpenCopilot && (
                <button
                  onClick={() => onOpenCopilot(selectedNode.label)}
                  className="w-full mt-2 py-2 px-3 bg-white hover:bg-neutral-200 text-black font-semibold text-xs rounded-md transition-all flex items-center justify-center space-x-1.5 shadow-sm"
                >
                  <Sparkles className="w-3.5 h-3.5 text-black" />
                  <span>Summarize This Package</span>
                </button>
              )}
            </div>

            <div className="pt-3 border-t border-neutral-900 text-[10px] font-mono text-neutral-500">
              Synced with Knowledge Graph
            </div>
          </div>
        )}
      </div>

      {/* Fullscreen Modal Overlay */}
      {isFullscreen && (
        <div className="fixed inset-0 z-[100] bg-black flex flex-col animate-in fade-in duration-150">
          {/* Fullscreen Header */}
          <div className="flex items-center justify-between px-4 py-2.5 bg-neutral-950 border-b border-neutral-900 shrink-0">
            <div className="flex items-center space-x-2 text-xs">
              <Network className="w-4 h-4 text-neutral-400" />
              <span className="font-semibold text-white tracking-tight">Knowledge Graph — Full View</span>
              <span className="text-neutral-500 font-mono">({filteredNodes.length} nodes · {filteredEdges.length} edges)</span>
            </div>
            <div className="flex items-center space-x-2">
              {/* Zoom controls in fullscreen */}
              <div className="flex items-center space-x-1 bg-neutral-900 p-0.5 rounded border border-neutral-800">
                <button
                  onClick={() => setZoom((z) => Math.min(3, z + 0.2))}
                  className="p-1.5 rounded text-neutral-400 hover:text-white hover:bg-neutral-800"
                  title="Zoom In"
                >
                  <ZoomIn className="w-3.5 h-3.5" />
                </button>
                <span className="px-1.5 text-[11px] font-mono text-neutral-400 min-w-[40px] text-center">
                  {Math.round(zoom * 100)}%
                </span>
                <button
                  onClick={() => setZoom((z) => Math.max(0.2, z - 0.2))}
                  className="p-1.5 rounded text-neutral-400 hover:text-white hover:bg-neutral-800"
                  title="Zoom Out"
                >
                  <ZoomOut className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setZoom(1)}
                  className="px-2 py-1 text-[10px] font-mono text-neutral-400 hover:text-white border-l border-neutral-700"
                  title="Reset"
                >
                  Reset
                </button>
              </div>
              <button
                onClick={onRefresh}
                className="p-1.5 rounded text-neutral-400 hover:text-white hover:bg-neutral-900 border border-neutral-800"
                title="Refresh"
              >
                <RefreshCw className="w-3.5 h-3.5" />
              </button>
              <button
                onClick={() => setIsFullscreen(false)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all"
                title="Exit fullscreen (Esc)"
              >
                <Minimize2 className="w-3.5 h-3.5" />
                <span>Exit Full View</span>
              </button>
            </div>
          </div>

          {/* Fullscreen Canvas with connection highlighting */}
          <div
            className="flex-1 overflow-auto p-6 bg-black flex items-start justify-center relative"
            onClick={() => setSelectedNode(null)}
          >
            {/* Fullscreen Floating Focus Badge Strip */}
            {selectedNode && (
              <div className="absolute top-4 left-6 z-20 flex items-center space-x-2 bg-neutral-950/95 border border-neutral-800 backdrop-blur-md px-3.5 py-2 rounded-lg text-xs font-mono shadow-2xl animate-in fade-in duration-150">
                <span className="text-white font-semibold flex items-center space-x-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-sky-400 inline-block" />
                  <span>{selectedNode.label}</span>
                </span>
                <span className="text-neutral-700">|</span>
                <span className="text-purple-400 flex items-center space-x-1" title="Packages that depend on this">
                  <span className="w-2 h-2 rounded-full bg-purple-400 inline-block" />
                  <span>{connectedInfo.parentNodeIds.size} Upstream (Dependents)</span>
                </span>
                <span className="text-neutral-700">|</span>
                <span className="text-cyan-400 flex items-center space-x-1" title="Sub-dependencies used by this">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 inline-block" />
                  <span>{connectedInfo.childNodeIds.size} Dependencies</span>
                </span>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedNode(null);
                  }}
                  className="text-neutral-400 hover:text-white ml-2 text-[10px] px-2 py-0.5 rounded bg-neutral-900 hover:bg-neutral-800 border border-neutral-700"
                  title="Clear selection"
                >
                  ✕ Clear Focus
                </button>
              </div>
            )}

            <svg
              viewBox={`0 0 ${width} ${Math.max(height, (libraryNodes.length / cols) * 90 + 350)}`}
              className="w-full h-full"
              style={{
                minWidth: `${width * zoom}px`,
                minHeight: `${Math.max(height, (libraryNodes.length / cols) * 90 + 350) * zoom}px`,
                transform: `scale(${zoom})`,
                transformOrigin: 'top center',
              }}
            >
              <defs>
                <marker id="arrowhead-fs" markerWidth="8" markerHeight="6" refX="14" refY="3" orient="auto">
                  <polygon points="0 0, 8 3, 0 6" fill="#333333" />
                </marker>
                <marker id="arrowhead-fs-outgoing" markerWidth="8" markerHeight="6" refX="14" refY="3" orient="auto">
                  <polygon points="0 0, 8 3, 0 6" fill="#06b6d4" />
                </marker>
                <marker id="arrowhead-fs-incoming" markerWidth="8" markerHeight="6" refX="14" refY="3" orient="auto">
                  <polygon points="0 0, 8 3, 0 6" fill="#c084fc" />
                </marker>
                <filter id="glow-fs-selected" x="-30%" y="-30%" width="160%" height="160%">
                  <feDropShadow dx="0" dy="0" stdDeviation="5" floodColor="#38bdf8" floodOpacity="0.8" />
                </filter>
                <filter id="glow-fs-outgoing" x="-30%" y="-30%" width="160%" height="160%">
                  <feDropShadow dx="0" dy="0" stdDeviation="3.5" floodColor="#06b6d4" floodOpacity="0.6" />
                </filter>
                <filter id="glow-fs-incoming" x="-30%" y="-30%" width="160%" height="160%">
                  <feDropShadow dx="0" dy="0" stdDeviation="3.5" floodColor="#c084fc" floodOpacity="0.6" />
                </filter>
              </defs>

              {/* Fullscreen Edges with colored highlighting */}
              {filteredEdges.map((edge, i) => {
                const srcPos = nodePositions.get(edge.source);
                const tgtPos = nodePositions.get(edge.target);
                if (!srcPos || !tgtPos) return null;

                const edgeKey = `${edge.source}->${edge.target}`;
                const isOutgoing = connectedInfo.outgoingEdgeKeys.has(edgeKey);
                const isIncoming = connectedInfo.incomingEdgeKeys.has(edgeKey);
                const hasSelection = !!selectedNode;

                let strokeColor = "#333333";
                let strokeWidth = 1.2;
                let strokeOpacity = 1;
                let marker = "url(#arrowhead-fs)";

                if (hasSelection) {
                  if (isOutgoing) {
                    strokeColor = "#06b6d4"; // Vibrant Cyan for dependencies
                    strokeWidth = 2.5;
                    strokeOpacity = 1;
                    marker = "url(#arrowhead-fs-outgoing)";
                  } else if (isIncoming) {
                    strokeColor = "#c084fc"; // Vibrant Purple for upstream dependents
                    strokeWidth = 2.5;
                    strokeOpacity = 1;
                    marker = "url(#arrowhead-fs-incoming)";
                  } else {
                    strokeColor = "#1f1f1f";
                    strokeOpacity = 0.12;
                  }
                }

                return (
                  <path
                    key={`fs-edge-${i}`}
                    d={`M ${srcPos.x} ${srcPos.y + 16} C ${srcPos.x} ${(srcPos.y + tgtPos.y) / 2}, ${tgtPos.x} ${(srcPos.y + tgtPos.y) / 2}, ${tgtPos.x} ${tgtPos.y - 16}`}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={strokeWidth}
                    opacity={strokeOpacity}
                    markerEnd={marker}
                    className="transition-all duration-200"
                  />
                );
              })}

              {/* Fullscreen Nodes with vertex color highlighting */}
              {filteredNodes.map((node) => {
                const pos = nodePositions.get(node.id) || { x: width / 2, y: height / 2 };
                const isSelected = selectedNode?.id === node.id;
                const isChild = connectedInfo.childNodeIds.has(node.id);
                const isParent = connectedInfo.parentNodeIds.has(node.id);
                const isConnected = isSelected || isChild || isParent;
                const hasSelection = !!selectedNode;

                const isApp = node.type === 'Application';
                const isContainer = node.type === 'Container';

                let cardFill = isSelected ? '#0f172a' : isChild ? '#082f49' : isParent ? '#2e1065' : '#0a0a0a';
                let cardStroke = isSelected ? '#38bdf8' : isChild ? '#06b6d4' : isParent ? '#c084fc' : '#2a2a2a';
                let cardStrokeWidth = isSelected ? 2.5 : isConnected ? 2 : 1;
                let filter = isSelected ? 'url(#glow-fs-selected)' : isChild ? 'url(#glow-fs-outgoing)' : isParent ? 'url(#glow-fs-incoming)' : undefined;
                let opacity = hasSelection ? (isConnected ? 1 : 0.2) : 1;

                let accentColor = isSelected ? '#38bdf8' : isChild ? '#06b6d4' : isParent ? '#c084fc' : (isApp ? '#ffffff' : isContainer ? '#38bdf8' : '#a3a3a3');
                let roleBadge = isSelected ? 'FOCUSED' : isChild ? 'DEPENDENCY' : isParent ? 'UPSTREAM' : (node.version ? `v${node.version}` : getNodeFolder(node));

                return (
                  <g
                    key={`fs-${node.id}`}
                    transform={`translate(${pos.x}, ${pos.y})`}
                    onClick={(e) => {
                      e.stopPropagation();
                      setSelectedNode((prev) => (prev?.id === node.id ? null : node));
                    }}
                    opacity={opacity}
                    filter={filter}
                    className="cursor-pointer group transition-all duration-200"
                  >
                    <rect
                      x="-72"
                      y="-20"
                      width="144"
                      height="40"
                      rx="8"
                      fill={cardFill}
                      stroke={cardStroke}
                      strokeWidth={cardStrokeWidth}
                    />
                    <circle cx="-57" cy="0" r={isSelected ? 6 : 5} fill={accentColor} />
                    <text
                      x="-46"
                      y="-4"
                      fill={isSelected ? '#ffffff' : isChild ? '#e0f2fe' : isParent ? '#f3e8ff' : '#ededed'}
                      fontSize="11"
                      fontFamily="sans-serif"
                      fontWeight={isConnected ? '700' : '600'}
                      className="pointer-events-none"
                    >
                      {node.label.length > 14 ? node.label.substring(0, 13) + '…' : node.label}
                    </text>
                    <text
                      x="-46"
                      y="10"
                      fill={isSelected ? '#7dd3fc' : isChild ? '#38bdf8' : isParent ? '#d8b4fe' : '#666666'}
                      fontSize="9"
                      fontFamily="monospace"
                      fontWeight={isConnected ? '600' : 'normal'}
                      className="pointer-events-none uppercase"
                    >
                      {roleBadge}
                    </text>
                    {isApp && (
                      <rect
                        x="-72"
                        y="-20"
                        width="144"
                        height="40"
                        rx="8"
                        fill="none"
                        stroke="#404040"
                        strokeWidth="1"
                        strokeDasharray="4 2"
                      />
                    )}
                  </g>
                );
              })}
            </svg>
          </div>

          {/* Fullscreen bottom hint */}
          <div className="shrink-0 px-4 py-1.5 bg-neutral-950 border-t border-neutral-900 flex items-center justify-between text-[10px] font-mono text-neutral-600">
            <span>Click any node to inspect · Scroll or pinch to navigate · Press <kbd className="px-1 py-0.5 rounded bg-neutral-900 text-neutral-400 border border-neutral-800">Esc</kbd> to exit</span>
            <span>{filteredNodes.length} packages across {allFolders.length} folder(s)</span>
          </div>
        </div>
      )}
    </div>
  );
};
