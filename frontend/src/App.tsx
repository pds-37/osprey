import React, { useEffect, useState } from 'react';
import { Header, MainWorkspace } from './components/Header';
import { LandingPage } from './components/LandingPage';
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
  scanLocalWorkspace,
  verifyRemediationTask,
} from './api';
import { FolderGit2, Sparkles, RefreshCw } from 'lucide-react';

export const App: React.FC = () => {
  const [isLanding, setIsLanding] = useState<boolean>(true);
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
  const [systemStatus, setSystemStatus] = useState('ONLINE · Osprey v2.0');
  const [isScanningWorkspace, setIsScanningWorkspace] = useState(false);
  const [targetPath, setTargetPath] = useState('.');
  const [scanFeedback, setScanFeedback] = useState<string | null>(null);

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

  // Render Public Landing Page
  if (isLanding) {
    return (
      <LandingPage
        onEnterApp={() => setIsLanding(false)}
        onRunDemoAndEnter={async () => {
          setIsLanding(false);
          await handleRunDemo();
        }}
      />
    );
  }

  // Render Enterprise Control Plane
  return (
    <div className="min-h-screen bg-black text-neutral-200 flex flex-col font-sans selection:bg-neutral-800 selection:text-white">
      {/* 1. Header with 3 Unified Workspaces & Return to Story trigger */}
      <Header
        activeWorkspace={activeWorkspace}
        setActiveWorkspace={setActiveWorkspace}
        onOpenUpload={() => setIsUploadOpen(true)}
        onToggleCopilot={() => setIsCopilotOpen((prev) => !prev)}
        onGoToLanding={() => setIsLanding(true)}
        systemStatus={systemStatus}
        hasOpenThreats={hasOpenThreats}
        pendingPRsCount={pendingPRsCount}
      />

      {/* 2. Workspace Project Target Extension Bar */}
      <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-4 pb-0">
        <div className="p-3 bg-neutral-950 border border-neutral-900 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5">
            <div className="w-6 h-6 rounded bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white shrink-0">
              <FolderGit2 className="w-3.5 h-3.5 text-neutral-300" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-white">Target Path:</span>
              <input
                type="text"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="Path to folder or repo (e.g. .)"
                className="text-xs font-mono text-neutral-200 bg-black px-2.5 py-1 rounded border border-neutral-800 focus:outline-none focus:border-neutral-600 w-36 sm:w-56"
              />
            </div>
            {scanFeedback ? (
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/50">
                {scanFeedback}
              </span>
            ) : (
              <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-900/50 hidden sm:inline">
                OSV.dev Connected
              </span>
            )}
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              disabled={isScanningWorkspace}
              onClick={async () => {
                setIsScanningWorkspace(true);
                try {
                  const res = await scanLocalWorkspace(targetPath);
                  const manifestCount = res.summary?.manifests?.length || 1;
                  setScanFeedback(`Indexed ${res.components_count} packages across ${manifestCount} manifests`);
                  await loadAllData();
                } catch (e: any) {
                  setScanFeedback(`Scan failed: ${e.message}`);
                } finally {
                  setIsScanningWorkspace(false);
                }
              }}
              className="px-3 py-1.5 bg-white hover:bg-neutral-200 text-black font-semibold text-xs rounded-md transition-all flex items-center space-x-1.5 disabled:opacity-50 shadow-sm"
            >
              {isScanningWorkspace ? (
                <>
                  <RefreshCw className="w-3 h-3 text-black animate-spin" />
                  <span>Scanning Target...</span>
                </>
              ) : (
                <>
                  <Sparkles className="w-3 h-3 text-black" />
                  <span>Scan Target Manifests</span>
                </>
              )}
            </button>
            <button
              onClick={() => setIsUploadOpen(true)}
              className="px-2.5 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border border-neutral-800 text-xs rounded-md transition-all font-mono"
            >
              + Ingest Custom SBOM
            </button>
          </div>
        </div>
      </div>

      {/* 3. Main Content Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-4">
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
