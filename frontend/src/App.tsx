import React, { useEffect, useState } from 'react';
import { Header, MainWorkspace } from './components/Header';
import { ThreatCenterView } from './components/ThreatCenterView';
import { SupplyChainView } from './components/SupplyChainView';
import { RemediationCenter } from './components/RemediationCenter';
import { AiCopilotDrawer } from './components/AiCopilotDrawer';
import { SbomUploadModal } from './components/SbomUploadModal';
import { LineageModal } from './components/LineageModal';

import {
  AttackPath,
  CommitRecord,
  ComponentItem,
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
  fetchSboms,
  fetchUpstreamChanges,
  queryAIAnalyst,
  recalculateAttackPaths,
  runFlagshipDemo,
  verifyRemediationTask,
} from './api';

export const App: React.FC = () => {
  const [activeWorkspace, setActiveWorkspace] = useState<MainWorkspace>('threats');
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [copilotTarget, setCopilotTarget] = useState('libheif');
  const [selectedComponent, setSelectedComponent] = useState<ComponentItem | null>(null);

  // Core Data States
  const [components, setComponents] = useState<ComponentItem[]>([]);
  const [sboms, setSboms] = useState<SBOMDocument[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [propagationRecords, setPropagationRecords] = useState<PatchPropagationRecord[]>([]);
  const [upstreamCommits, setUpstreamCommits] = useState<CommitRecord[]>([]);
  const [remediationTasks, setRemediationTasks] = useState<RemediationTask[]>([]);
  const [systemStatus, setSystemStatus] = useState('ONLINE · v2.0.0');

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
      ] = await Promise.all([
        fetchHealth().catch(() => ({ status: 'healthy', version: '2.0.0' })),
        fetchComponents().catch(() => []),
        fetchSboms().catch(() => []),
        fetchGraphData().catch(() => ({ nodes: [], edges: [], summary: {} })),
        fetchAttackPaths().catch(() => []),
        fetchPatchPropagation().catch(() => []),
        fetchUpstreamChanges().catch(() => []),
        fetchRemediationTasks().catch(() => []),
      ]);

      setSystemStatus(`${health.status.toUpperCase()} · v${health.version}`);
      setComponents(comps);
      setSboms(sbomList);
      setGraphData(graph);
      setAttackPaths(paths);
      setPropagationRecords(patches);
      setUpstreamCommits(commits);
      setRemediationTasks(remediations);
    } catch (e) {
      console.error('Error fetching dashboard data:', e);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  // Global Keyboard Shortcut: Cmd+K / Ctrl+K opens Copilot
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setIsCopilotOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Action Handlers
  const handleRunDemo = async () => {
    await runFlagshipDemo();
    await loadAllData();
  };

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

  const handleOpenCopilot = (componentName: string) => {
    setCopilotTarget(componentName);
    setIsCopilotOpen(true);
  };

  const hasOpenThreats = attackPaths.some((p) => p.status === 'OPEN');
  const pendingPRsCount = remediationTasks.filter((t) => t.status === 'PENDING_APPROVAL').length;

  return (
    <div className="min-h-screen bg-black text-neutral-200 flex flex-col font-sans selection:bg-neutral-800 selection:text-white">
      {/* 1. Header with 3 Unified Workspaces */}
      <Header
        activeWorkspace={activeWorkspace}
        setActiveWorkspace={setActiveWorkspace}
        onOpenUpload={() => setIsUploadOpen(true)}
        onToggleCopilot={() => setIsCopilotOpen((prev) => !prev)}
        systemStatus={systemStatus}
        hasOpenThreats={hasOpenThreats}
        pendingPRsCount={pendingPRsCount}
      />

      {/* 2. Main Content Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5">
        {activeWorkspace === 'threats' && (
          <ThreatCenterView
            attackPaths={attackPaths}
            propagationRecords={propagationRecords}
            upstreamCommits={upstreamCommits}
            onOpenAI={handleOpenCopilot}
            onGoToRemediation={() => setActiveWorkspace('remediation')}
            onRunDemo={handleRunDemo}
            onRecalculate={handleRecalculateAttackPaths}
          />
        )}

        {activeWorkspace === 'supply-chain' && (
          <SupplyChainView
            components={components}
            sboms={sboms}
            graphData={graphData}
            onRefresh={loadAllData}
            onOpenLineage={(comp) => setSelectedComponent(comp)}
          />
        )}

        {activeWorkspace === 'remediation' && (
          <RemediationCenter
            tasks={remediationTasks}
            onApprove={handleApproveTask}
            onVerify={handleVerifyTask}
            onRefresh={loadAllData}
          />
        )}
      </main>

      {/* 3. Slide-Over AI Copilot Drawer (Cmd+K) */}
      <AiCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        targetComponent={copilotTarget}
        onQuery={queryAIAnalyst}
      />

      {/* 4. Ingest SBOM Modal */}
      <SbomUploadModal
        isOpen={isUploadOpen}
        onClose={() => setIsUploadOpen(false)}
        onSuccess={loadAllData}
      />

      {/* 5. Component Lineage Modal */}
      <LineageModal
        component={selectedComponent}
        onClose={() => setSelectedComponent(null)}
      />
    </div>
  );
};
