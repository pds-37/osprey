import React, { useEffect, useState } from 'react';
import { Header, NavigationTab } from './components/Header';
import { FlagshipDemoBanner } from './components/FlagshipDemoBanner';
import { InventoryTable } from './components/InventoryTable';
import { DependencyGraphCanvas } from './components/DependencyGraphCanvas';
import { AttackPathsView } from './components/AttackPathsView';
import { PatchPropagationView } from './components/PatchPropagationView';
import { UpstreamChangesView } from './components/UpstreamChangesView';
import { RemediationCenter } from './components/RemediationCenter';
import { AiAnalystConsole } from './components/AiAnalystConsole';
import { SbomUploadModal } from './components/SbomUploadModal';
import { LineageModal } from './components/LineageModal';

import {
  AttackPath,
  CommitRecord,
  ComponentItem,
  ContextualRiskScore,
  GraphData,
  PatchPropagationRecord,
  RemediationTask,
  SBOMDocument,
} from './types';
import {
  approveRemediationTask,
  fetchAttackPaths,
  fetchComponents,
  fetchGraphData,
  fetchHealth,
  fetchPatchPropagation,
  fetchRemediationTasks,
  fetchRisks,
  fetchSboms,
  fetchUpstreamChanges,
  queryAIAnalyst,
  recalculateAttackPaths,
  verifyRemediationTask,
} from './api';
import {
  Layers,
  Route,
  GitPullRequest,
  RefreshCw,
  GitCommit,
} from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavigationTab>('inventory');
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [selectedComponent, setSelectedComponent] = useState<ComponentItem | null>(null);
  const [aiTargetComponent, setAiTargetComponent] = useState('libheif');

  // Core Data States
  const [components, setComponents] = useState<ComponentItem[]>([]);
  const [sboms, setSboms] = useState<SBOMDocument[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [propagationRecords, setPropagationRecords] = useState<PatchPropagationRecord[]>([]);
  const [upstreamCommits, setUpstreamCommits] = useState<CommitRecord[]>([]);
  const [remediationTasks, setRemediationTasks] = useState<RemediationTask[]>([]);
  const [risks, setRisks] = useState<ContextualRiskScore[]>([]);
  const [systemStatus, setSystemStatus] = useState('ONLINE · v2.0.0');

  // Inventory Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEcosystem, setSelectedEcosystem] = useState('all');

  const loadAllData = async () => {
    try {
      const [
        health,
        comps,
        sbomList,
        graph,
        paths,
        patches,
        commits,
        remediations,
        riskList,
      ] = await Promise.all([
        fetchHealth().catch(() => ({ status: 'healthy', version: '2.0.0' })),
        fetchComponents(selectedEcosystem === 'all' ? undefined : selectedEcosystem, searchQuery).catch(() => []),
        fetchSboms().catch(() => []),
        fetchGraphData().catch(() => ({ nodes: [], edges: [], summary: {} })),
        fetchAttackPaths().catch(() => []),
        fetchPatchPropagation().catch(() => []),
        fetchUpstreamChanges().catch(() => []),
        fetchRemediationTasks().catch(() => []),
        fetchRisks().catch(() => []),
      ]);

      setSystemStatus(`${health.status.toUpperCase()} · v${health.version}`);
      setComponents(comps);
      setSboms(sbomList);
      setGraphData(graph);
      setAttackPaths(paths);
      setPropagationRecords(patches);
      setUpstreamCommits(commits);
      setRemediationTasks(remediations);
      setRisks(riskList);
    } catch (e) {
      console.error('Error fetching dashboard data:', e);
    }
  };

  useEffect(() => {
    loadAllData();
  }, [selectedEcosystem, searchQuery]);

  // Actions
  const handleRecalculateAttackPaths = async () => {
    const updated = await recalculateAttackPaths();
    setAttackPaths(updated);
    await loadAllData();
  };

  const handleApproveTask = async (taskId: string, actor: string) => {
    await approveRemediationTask(taskId, actor);
    await loadAllData();
  };

  const handleVerifyTask = async (taskId: string) => {
    await verifyRemediationTask(taskId);
    await loadAllData();
  };

  const handleOpenAI = (componentName: string) => {
    setAiTargetComponent(componentName);
    setActiveTab('ai');
  };

  // Metric Computations
  const totalComponents = components.length;
  const runningComponents = components.filter((c) => c.state === 'RUNNING').length;
  const openAttackPathsCount = attackPaths.filter((p) => p.status === 'OPEN').length;
  const exposedPropagationCount = propagationRecords.filter((p) => p.is_production_exposed).length;
  const pendingApprovalsCount = remediationTasks.filter((t) => t.status === 'PENDING_APPROVAL').length;

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-['Plus_Jakarta_Sans',sans-serif]">
      {/* Top Application Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onOpenUpload={() => setIsUploadOpen(true)}
        systemStatus={systemStatus}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">
        {/* Interactive Flagship Demo Banner */}
        <FlagshipDemoBanner onDemoComplete={loadAllData} />

        {/* Real-time Telemetry & KPI Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3.5">
          {/* Total Components Card */}
          <div
            onClick={() => setActiveTab('inventory')}
            className={`p-4 rounded-2xl border transition-all cursor-pointer ${
              activeTab === 'inventory'
                ? 'bg-blue-950/40 border-blue-500/50 ring-1 ring-blue-500/30'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider">Components</span>
              <Layers className="w-4 h-4 text-blue-400" />
            </div>
            <div className="text-2xl font-extrabold text-white font-mono">{totalComponents}</div>
            <div className="text-[10px] text-slate-400 mt-1 flex items-center space-x-1">
              <span>{runningComponents} Running</span>
              <span>•</span>
              <span>{sboms.length} SBOMs</span>
            </div>
          </div>

          {/* Adversary Attack Paths Card */}
          <div
            onClick={() => setActiveTab('attack-paths')}
            className={`p-4 rounded-2xl border transition-all cursor-pointer ${
              openAttackPathsCount > 0
                ? 'bg-rose-950/30 border-rose-500/40'
                : 'bg-slate-900/60 border-slate-800'
            } ${activeTab === 'attack-paths' ? 'ring-1 ring-rose-500/50' : 'hover:border-slate-700'}`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider">Attack Paths</span>
              <Route className={`w-4 h-4 ${openAttackPathsCount > 0 ? 'text-rose-400' : 'text-emerald-400'}`} />
            </div>
            <div
              className={`text-2xl font-extrabold font-mono ${
                openAttackPathsCount > 0 ? 'text-rose-400' : 'text-emerald-400'
              }`}
            >
              {openAttackPathsCount} Open
            </div>
            <div className="text-[10px] text-slate-400 mt-1 flex items-center space-x-1">
              <span>{attackPaths.length} traversals</span>
              <span>•</span>
              <span className="text-amber-400 font-bold">{risks.length} Risk Scores</span>
            </div>
          </div>

          {/* Patch Propagation Lag Card */}
          <div
            onClick={() => setActiveTab('propagation')}
            className={`p-4 rounded-2xl border transition-all cursor-pointer ${
              exposedPropagationCount > 0
                ? 'bg-amber-950/20 border-amber-500/40'
                : 'bg-slate-900/60 border-slate-800'
            } ${activeTab === 'propagation' ? 'ring-1 ring-amber-500/50' : 'hover:border-slate-700'}`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider">Patch Lag</span>
              <RefreshCw className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-extrabold text-amber-400 font-mono">
              {exposedPropagationCount} Exposed
            </div>
            <div className="text-[10px] text-slate-400 mt-1">
              {propagationRecords.length} packages tracking fix
            </div>
          </div>

          {/* Upstream Changes Card */}
          <div
            onClick={() => setActiveTab('upstream')}
            className={`p-4 rounded-2xl border transition-all cursor-pointer ${
              activeTab === 'upstream'
                ? 'bg-indigo-950/40 border-indigo-500/50 ring-1 ring-indigo-500/30'
                : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider">Upstream Signals</span>
              <GitCommit className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-extrabold text-white font-mono">{upstreamCommits.length}</div>
            <div className="text-[10px] text-slate-400 mt-1">Heuristic commit classifications</div>
          </div>

          {/* Remediation Approval Gate Card */}
          <div
            onClick={() => setActiveTab('remediation')}
            className={`p-4 rounded-2xl border transition-all cursor-pointer ${
              pendingApprovalsCount > 0
                ? 'bg-emerald-950/30 border-emerald-500/40'
                : 'bg-slate-900/60 border-slate-800'
            } ${activeTab === 'remediation' ? 'ring-1 ring-emerald-500/50' : 'hover:border-slate-700'}`}
          >
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider">Approval Gate</span>
              <GitPullRequest className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-extrabold text-emerald-400 font-mono">
              {pendingApprovalsCount} PRs
            </div>
            <div className="text-[10px] text-slate-400 mt-1">
              Human-in-the-loop pending review
            </div>
          </div>
        </div>

        {/* View Switcher Container */}
        <div className="pt-2">
          {activeTab === 'inventory' && (
            <section className="space-y-4">
              <InventoryTable
                components={components}
                searchQuery={searchQuery}
                setSearchQuery={setSearchQuery}
                selectedEcosystem={selectedEcosystem}
                setSelectedEcosystem={setSelectedEcosystem}
                onSelectComponent={(comp) => setSelectedComponent(comp)}
              />
            </section>
          )}

          {activeTab === 'graph' && (
            <section className="space-y-4">
              <DependencyGraphCanvas
                graphData={graphData}
                onRefresh={loadAllData}
              />
            </section>
          )}

          {activeTab === 'attack-paths' && (
            <section className="space-y-4">
              <AttackPathsView
                attackPaths={attackPaths}
                onRecalculate={handleRecalculateAttackPaths}
                onOpenAI={handleOpenAI}
              />
            </section>
          )}

          {activeTab === 'propagation' && (
            <section className="space-y-4">
              <PatchPropagationView
                records={propagationRecords}
                onRefresh={loadAllData}
                onOpenAI={handleOpenAI}
                onOpenRemediation={() => setActiveTab('remediation')}
              />
            </section>
          )}

          {activeTab === 'upstream' && (
            <section className="space-y-4">
              <UpstreamChangesView commits={upstreamCommits} />
            </section>
          )}

          {activeTab === 'remediation' && (
            <section className="space-y-4">
              <RemediationCenter
                tasks={remediationTasks}
                onApprove={handleApproveTask}
                onVerify={handleVerifyTask}
                onRefresh={loadAllData}
              />
            </section>
          )}

          {activeTab === 'ai' && (
            <section className="space-y-4">
              <AiAnalystConsole
                onQuery={queryAIAnalyst}
                initialComponent={aiTargetComponent}
              />
            </section>
          )}
        </div>
      </main>

      {/* Ingestion Modal */}
      <SbomUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={loadAllData}
      />

      {/* Deep Component Lineage Modal */}
      <LineageModal
        component={selectedComponent}
        onClose={() => setSelectedComponent(null)}
      />
    </div>
  );
};
