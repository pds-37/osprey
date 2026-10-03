import React, { useEffect, useState } from 'react';
import { Header } from './components/Header';
import { InventoryTable } from './components/InventoryTable';
import { DependencyGraphCanvas } from './components/DependencyGraphCanvas';
import { SbomUploadModal } from './components/SbomUploadModal';
import { LineageModal } from './components/LineageModal';
import { ComponentItem, GraphData, SBOMDocument } from './types';
import { fetchComponents, fetchGraphData, fetchHealth, fetchSboms } from './api';
import { Layers, Network, Cpu, Activity } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'inventory' | 'graph'>('inventory');
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [selectedComponent, setSelectedComponent] = useState<ComponentItem | null>(null);
  
  const [components, setComponents] = useState<ComponentItem[]>([]);
  const [sboms, setSboms] = useState<SBOMDocument[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [systemStatus, setSystemStatus] = useState('Online · v2.0.0');

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEcosystem, setSelectedEcosystem] = useState('all');

  const loadData = async () => {
    try {
      const [health, comps, sbomList, graph] = await Promise.all([
        fetchHealth().catch(() => ({ status: 'healthy', version: '2.0.0' })),
        fetchComponents(selectedEcosystem === 'all' ? undefined : selectedEcosystem, searchQuery).catch(() => []),
        fetchSboms().catch(() => []),
        fetchGraphData().catch(() => ({ nodes: [], edges: [], summary: {} })),
      ]);
      setSystemStatus(`${health.status.toUpperCase()} · v${health.version}`);
      setComponents(comps);
      setSboms(sbomList);
      setGraphData(graph);
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    loadData();
  }, [selectedEcosystem, searchQuery]);

  // Compute summary metrics
  const totalComponents = components.length;
  const runningWorkloads = components.filter((c) => c.state === 'RUNNING').length;
  const distinctEcosystems = new Set(components.map((c) => c.ecosystem)).size;
  const graphNodesCount = graphData?.nodes?.length || 0;

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-['Plus_Jakarta_Sans',sans-serif]">
      {/* Navbar */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenUpload={() => setIsUploadOpen(true)}
        systemStatus={systemStatus}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* KPI Metric Summary Strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur shadow-lg">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Total Components</span>
              <Layers className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-extrabold text-white font-mono">{totalComponents}</div>
            <div className="text-[11px] text-slate-500 mt-1">Across {sboms.length} ingested SBOMs</div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur shadow-lg">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Running Workloads</span>
              <Activity className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-extrabold text-emerald-400 font-mono">{runningWorkloads}</div>
            <div className="text-[11px] text-slate-500 mt-1">Active in runtime environments</div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur shadow-lg">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Ecosystems</span>
              <Cpu className="w-4 h-4 text-indigo-400" />
            </div>
            <div className="text-2xl font-extrabold text-white font-mono">{distinctEcosystems}</div>
            <div className="text-[11px] text-slate-500 mt-1">Canonical package registries</div>
          </div>

          <div className="p-4 rounded-2xl bg-slate-900/60 border border-slate-800/80 backdrop-blur shadow-lg">
            <div className="flex items-center justify-between text-slate-400 mb-2">
              <span className="text-xs font-semibold uppercase tracking-wider">Graph Nodes</span>
              <Network className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-extrabold text-cyan-400 font-mono">{graphNodesCount}</div>
            <div className="text-[11px] text-slate-500 mt-1">{graphData?.edges?.length || 0} relational graph edges</div>
          </div>
        </div>

        {/* View Content */}
        {activeTab === 'inventory' ? (
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white tracking-tight">Software Inventory & Lineage</h2>
                <p className="text-xs text-slate-400">Canonical software components and dependency states</p>
              </div>
            </div>

            <InventoryTable
              components={components}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              selectedEcosystem={selectedEcosystem}
              setSelectedEcosystem={setSelectedEcosystem}
              onSelectComponent={(comp) => setSelectedComponent(comp)}
            />
          </section>
        ) : (
          <section className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-base font-bold text-white tracking-tight">Knowledge Graph Visualization</h2>
                <p className="text-xs text-slate-400">Multi-tier dependency relationships and asset connections</p>
              </div>
            </div>

            <DependencyGraphCanvas
              graphData={graphData}
              onRefresh={loadData}
            />
          </section>
        )}
      </main>

      {/* Upload Modal */}
      <SbomUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={loadData}
      />

      {/* Lineage "Why Am I Affected?" Modal */}
      <LineageModal
        component={selectedComponent}
        onClose={() => setSelectedComponent(null)}
      />
    </div>
  );
};
