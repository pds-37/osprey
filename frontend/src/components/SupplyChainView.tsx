import React, { useState } from 'react';
import { ComponentItem, GraphData, SBOMDocument } from '../types';
import { DependencyGraphCanvas } from './DependencyGraphCanvas';
import { Search, GitBranch, Package } from 'lucide-react';

interface SupplyChainViewProps {
  components: ComponentItem[];
  sboms: SBOMDocument[];
  graphData: GraphData | null;
  onRefresh: () => void;
  onOpenLineage: (comp: ComponentItem) => void;
}

export const SupplyChainView: React.FC<SupplyChainViewProps> = ({
  components,
  sboms,
  graphData,
  onRefresh,
  onOpenLineage,
}) => {
  const [search, setSearch] = useState('');
  const [stateFilter, setStateFilter] = useState<'ALL' | 'RUNNING' | 'INSTALLED' | 'DECLARED'>('ALL');
  const [selectedComp, setSelectedComp] = useState<ComponentItem | null>(components[0] || null);

  const filteredComponents = components.filter((c) => {
    const matchesSearch =
      c.name.toLowerCase().includes(search.toLowerCase()) ||
      c.purl.toLowerCase().includes(search.toLowerCase());
    const matchesState = stateFilter === 'ALL' || c.state === stateFilter;
    return matchesSearch && matchesState;
  });

  return (
    <div className="space-y-3">
      {/* Top Filter & Counter Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 bg-neutral-950 border border-neutral-900 rounded-xl">
        <div className="flex items-center space-x-3">
          <div className="relative w-64">
            <Search className="w-3.5 h-3.5 text-neutral-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Filter packages or PURLs..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-black border border-neutral-900 rounded-md text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700 font-mono"
            />
          </div>

          <div className="flex items-center space-x-1">
            {(['ALL', 'RUNNING', 'INSTALLED', 'DECLARED'] as const).map((st) => (
              <button
                key={st}
                onClick={() => setStateFilter(st)}
                className={`px-2 py-1 rounded text-[11px] font-mono transition-all ${
                  stateFilter === st
                    ? 'bg-neutral-100 text-black font-semibold'
                    : 'bg-black text-neutral-400 hover:text-white border border-neutral-900'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        <div className="text-[11px] font-mono text-neutral-400 flex items-center space-x-3">
          <span>{components.length} Components</span>
          <span>•</span>
          <span>{sboms.length} Ingested SBOMs</span>
        </div>
      </div>

      {/* Dual Pane Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 h-[680px]">
        {/* Left Pane: High-Density Component List (5 cols) */}
        <div className="lg:col-span-5 bg-neutral-950 border border-neutral-900 rounded-xl flex flex-col overflow-hidden">
          <div className="px-4 py-2.5 border-b border-neutral-900 bg-black text-[10px] font-mono uppercase text-neutral-400 flex items-center justify-between">
            <span>Packages ({filteredComponents.length})</span>
            <span>Lifecycle State</span>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-neutral-900/60">
            {filteredComponents.length === 0 ? (
              <div className="p-12 text-center text-neutral-600 text-xs">
                <Package className="w-6 h-6 mx-auto mb-2 opacity-30" />
                No matching components.
              </div>
            ) : (
              filteredComponents.map((comp) => {
                const isSelected = selectedComp?.id === comp.id;
                return (
                  <div
                    key={comp.id}
                    onClick={() => setSelectedComp(comp)}
                    className={`p-3 cursor-pointer transition-colors flex items-center justify-between ${
                      isSelected ? 'bg-neutral-900/80' : 'hover:bg-neutral-900/40'
                    }`}
                  >
                    <div className="min-w-0 pr-2">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs font-semibold text-white truncate">{comp.name}</span>
                        <span className="font-mono text-[10px] text-neutral-400">{comp.version}</span>
                      </div>
                      <div className="font-mono text-[10px] text-neutral-400 truncate mt-0.5">{comp.purl}</div>
                    </div>

                    <div className="flex items-center space-x-2 shrink-0">
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-medium border ${
                          comp.state === 'RUNNING'
                            ? 'bg-emerald-950/40 text-emerald-400 border-emerald-900/50'
                            : comp.state === 'INSTALLED'
                            ? 'bg-neutral-900 text-neutral-300 border-neutral-800'
                            : 'bg-black text-neutral-500 border-neutral-900'
                        }`}
                      >
                        {comp.state}
                      </span>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onOpenLineage(comp);
                        }}
                        className="p-1 rounded text-neutral-500 hover:text-white hover:bg-neutral-800"
                        title="View Lineage Ancestry"
                      >
                        <GitBranch className="w-3 h-3" />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Pane: Interactive Knowledge Graph (7 cols) */}
        <div className="lg:col-span-7 bg-neutral-950 border border-neutral-900 rounded-xl overflow-hidden flex flex-col">
          <div className="px-4 py-2.5 border-b border-neutral-900 bg-black text-[10px] font-mono uppercase text-neutral-400 flex items-center justify-between">
            <span>Knowledge Graph Visualization</span>
            <span>{selectedComp ? `Focus: ${selectedComp.name}` : 'Multi-tier Assets'}</span>
          </div>

          <div className="flex-1 relative">
            <DependencyGraphCanvas graphData={graphData} onRefresh={onRefresh} />
          </div>
        </div>
      </div>
    </div>
  );
};
