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
  VulnerabilityFinding,
} from './types';
import {
  approveRemediationTask,
  fetchAttackPaths,
  fetchComponents,
  fetchGraphData,
  fetchHealth,
  fetchVulnerabilities,
  fetchPatchPropagation,
  fetchRemediationTasks,
  fetchSboms,
  fetchUpstreamChanges,
  queryCopilot,
  recalculateAttackPaths,
  runFlagshipDemo,
  clearInventory,
  scanLocalWorkspace,
  verifyRemediationTask,
  clearAccessToken,
  getAccessToken,
  login,
} from './api';
import { FolderGit2, Sparkles, RefreshCw, Trash2, AlertCircle, CheckCircle2 } from 'lucide-react';

export const App: React.FC = () => {
  const [isLanding, setIsLanding] = useState<boolean>(true);
  const [activeWorkspace, setActiveWorkspace] = useState<MainWorkspace>('threats');
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isCopilotOpen, setIsCopilotOpen] = useState(false);
  const [copilotFindingId, setCopilotFindingId] = useState('');
  const [selectedComponent, setSelectedComponent] = useState<ComponentItem | null>(null);

  // Core Data States
  const [components, setComponents] = useState<ComponentItem[]>([]);
  const [sboms, setSboms] = useState<SBOMDocument[]>([]);
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [propagationRecords, setPropagationRecords] = useState<PatchPropagationRecord[]>([]);
  const [upstreamCommits, setUpstreamCommits] = useState<CommitRecord[]>([]);
  const [remediationTasks, setRemediationTasks] = useState<RemediationTask[]>([]);
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [systemStatus, setSystemStatus] = useState('API STATUS UNKNOWN');
  const [isScanningWorkspace, setIsScanningWorkspace] = useState(false);
  const [targetPath, setTargetPath] = useState('.');
  const [scanFeedback, setScanFeedback] = useState<string | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [dataLoadWarning, setDataLoadWarning] = useState<string | null>(null);
  const [apiAuthenticated, setApiAuthenticated] = useState<boolean>(Boolean(getAccessToken()));
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authError, setAuthError] = useState<string | null>(null);


  const loadAllData = async () => {
    setDataLoadWarning(null);
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
        currentFindings,
      ] = await Promise.all([
        fetchHealth().catch(() => ({ status: 'unavailable', version: 'unknown' })),
        fetchComponents().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
        fetchSboms().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
        fetchGraphData().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return { nodes: [], edges: [], summary: {} }; }),
        fetchAttackPaths().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
        fetchPatchPropagation().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
        fetchUpstreamChanges().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
        fetchRemediationTasks().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
        fetchVulnerabilities().catch(() => { setDataLoadWarning('Some protected data could not be loaded. Sign in or check your API permissions; empty results may be unavailable rather than empty.'); return []; }),
      ]);

      setSystemStatus(`${health.status.toUpperCase()} · v${health.version}`);
      setComponents(comps);
      setSboms(sbomList);
      setGraphData(graph);
      setAttackPaths(paths);
      setPropagationRecords(patches);
      setUpstreamCommits(commits);
      setRemediationTasks(remediations);
      setFindings(currentFindings);
    } catch (e) {
      console.error('Error fetching dashboard data:', e);
    }
  };

  useEffect(() => {
    loadAllData();
  }, []);

  const handleToggleCopilot = () => {
    setIsCopilotOpen((prev) => {
      const next = !prev;
      if (next && (!copilotFindingId || copilotFindingId === 'package')) {
        setCopilotFindingId(findings[0]?.id || '');
      }
      return next;
    });
  };

  // Global Keyboard Shortcut: Cmd+K / Ctrl+K opens the evidence summary
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        handleToggleCopilot();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [attackPaths, components, copilotFindingId, findings]);

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

  const handleApproveTask = async (taskId: string) => {
    await approveRemediationTask(taskId);
    await loadAllData();
  };

  const handleVerifyTask = async (taskId: string) => {
    await verifyRemediationTask(taskId);
    await loadAllData();
  };

  const handleApiLogin = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAuthError(null);
    try {
      await login(authUsername, authPassword);
      setApiAuthenticated(true);
      setAuthPassword('');
      await loadAllData();
    } catch (error: any) {
      setAuthError(error.message || 'Sign-in failed');
    }
  };

  const handleApiLogout = () => {
    clearAccessToken();
    setApiAuthenticated(false);
    setComponents([]);
    setSboms([]);
    setGraphData(null);
    setAttackPaths([]);
    setPropagationRecords([]);
    setUpstreamCommits([]);
    setRemediationTasks([]);
    setFindings([]);
    setSelectedComponent(null);
    setCopilotFindingId('');
    setIsCopilotOpen(false);
    setDataLoadWarning('Sign in to load organization-scoped inventory and findings.');
  };

  const handleOpenCopilot = (findingId: string) => {
    setCopilotFindingId(findingId);
    setIsCopilotOpen(true);
  };

  const hasOpenThreats = attackPaths.some((p) => p.status === 'OPEN');
  const pendingRecommendationsCount = remediationTasks.filter((t) => t.status === 'PENDING_APPROVAL').length;

  // Render Public Landing Page
  if (isLanding) {
    return (
      <LandingPage
        onEnterApp={() => setIsLanding(false)}
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
        onToggleCopilot={handleToggleCopilot}
        onGoToLanding={() => setIsLanding(true)}
        systemStatus={systemStatus}
        hasOpenThreats={hasOpenThreats}
        pendingPRsCount={pendingRecommendationsCount}
      />

      {/* 2. Workspace Project Target Extension Bar */}
      <div className="max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 pt-4 pb-0 space-y-2">
        {attackPaths.some((path) => path.fixture) && (
          <div role="status" className="p-3 rounded-xl border border-amber-900/60 bg-amber-950/20 text-xs text-amber-200">
            <strong>DEMO FIXTURE DATA LOADED.</strong> Some inventory, vulnerability, path, lifecycle, risk, and remediation values shown in the dashboard are synthetic examples, not observations about your application or environment.
          </div>
        )}
        {!apiAuthenticated ? (
          <form onSubmit={handleApiLogin} className="p-3 bg-neutral-950 border border-neutral-900 rounded-xl flex flex-col sm:flex-row sm:items-center gap-2">
            <span className="text-xs text-neutral-300">Sign in to access protected API actions.</span>
            <input aria-label="Username" autoComplete="username" value={authUsername} onChange={(event) => setAuthUsername(event.target.value)} placeholder="Username" className="px-2.5 py-1.5 rounded-md bg-black border border-neutral-800 text-xs text-white" />
            <input aria-label="Password" autoComplete="current-password" type="password" value={authPassword} onChange={(event) => setAuthPassword(event.target.value)} placeholder="Password" className="px-2.5 py-1.5 rounded-md bg-black border border-neutral-800 text-xs text-white" />
            <button type="submit" className="px-3 py-1.5 rounded-md text-xs font-semibold bg-white text-black">Sign in</button>
            {authError && <span role="alert" className="text-xs text-rose-400">{authError}</span>}
          </form>
        ) : (
          <div className="flex justify-end items-center gap-2 text-[11px] text-neutral-500">
            <span>Authenticated API session</span>
            <button onClick={handleApiLogout} className="text-neutral-300 hover:text-white">Sign out</button>
          </div>
        )}
        {dataLoadWarning && <div role="status" className="p-3 rounded-xl border border-amber-900/60 bg-amber-950/20 text-xs text-amber-200">{dataLoadWarning}</div>}
        <div className="p-3 bg-neutral-950 border border-neutral-900 rounded-xl flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2.5 flex-1">
            <div className="w-6 h-6 rounded bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white shrink-0">
              <FolderGit2 className="w-3.5 h-3.5 text-neutral-300" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-white">Target Path:</span>
              <input
                type="text"
                value={targetPath}
                onChange={(e) => {
                  setTargetPath(e.target.value);
                  setScanError(null);
                }}
                placeholder="Path to folder or repo (e.g. .)"
                className="text-xs font-mono text-neutral-200 bg-black px-2.5 py-1 rounded border border-neutral-800 focus:outline-none focus:border-neutral-600 w-36 sm:w-56"
              />
            </div>

            {/* Quick Presets */}
            <div className="hidden sm:flex items-center space-x-1.5 text-[11px] font-mono">
              <span className="text-neutral-500 text-[10px]">Presets:</span>
              {[
                { label: '. (Root)', path: '.' },
                { label: './backend', path: './backend' },
                { label: './frontend', path: './frontend' },
                { label: 'Downloads', path: 'downloads' },
              ].map((preset) => (
                <button
                  key={preset.path}
                  onClick={() => {
                    setTargetPath(preset.path);
                    setScanError(null);
                  }}
                  className={`px-2 py-0.5 rounded border transition-colors ${
                    targetPath === preset.path
                      ? 'bg-neutral-800 text-white border-neutral-600 font-semibold'
                      : 'bg-black text-neutral-400 border-neutral-800 hover:text-neutral-200 hover:border-neutral-700'
                  }`}
                >
                  {preset.label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              disabled={isScanningWorkspace}
              onClick={async () => {
                setIsScanningWorkspace(true);
                setScanError(null);
                setScanFeedback(null);
                try {
                  const res = await scanLocalWorkspace(targetPath, undefined, true);
                  const manifestList = res.summary?.manifests?.join(', ') || 'manifests';
                  setScanFeedback(`Indexed ${res.components_count} packages (${manifestList}) · Previous inventory cleared`);
                  await loadAllData();
                } catch (e: any) {
                  setScanError(e.message || 'Scan failed');
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
              title="Clear the current inventory and related analysis records (preserves independently stored endpoint and upstream inputs)"
              onClick={async () => {
                try {
                  await clearInventory();
                  setComponents([]);
                  setSboms([]);
                  setGraphData({ nodes: [], edges: [], summary: {} });
                  setAttackPaths([]);
                  setPropagationRecords([]);
                  setUpstreamCommits([]);
                  setRemediationTasks([]);
                  setSelectedComponent(null);
                  setScanFeedback('Inventory and related analysis records cleared. Target path and independently stored endpoint/upstream inputs are preserved.');
                  setScanError(null);
                } catch (e: any) {
                  setScanError(`Failed to clear: ${e.message}`);
                }
              }}
              className="px-2 py-1.5 bg-neutral-950 hover:bg-neutral-900 text-neutral-400 hover:text-rose-400 border border-neutral-800 text-xs rounded-md transition-all flex items-center space-x-1"
            >
              <Trash2 className="w-3 h-3" />
              <span className="hidden sm:inline">Clear</span>
            </button>

            <button
              onClick={() => setIsUploadOpen(true)}
              className="px-2.5 py-1.5 bg-neutral-900 hover:bg-neutral-800 text-neutral-300 border border-neutral-800 text-xs rounded-md transition-all font-mono"
            >
              + Ingest SBOM
            </button>
          </div>
        </div>

        {/* Scan Status / Error Diagnostics Banner */}
        {scanFeedback && (
          <div className="p-2.5 bg-emerald-950/40 border border-emerald-900/60 rounded-lg flex items-center justify-between text-xs font-mono text-emerald-300">
            <div className="flex items-center space-x-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>{scanFeedback}</span>
            </div>
            <button
              onClick={() => setScanFeedback(null)}
              className="text-neutral-400 hover:text-neutral-200 text-[10px]"
            >
              ✕
            </button>
          </div>
        )}

        {scanError && (
          <div className="p-3 bg-rose-950/50 border border-rose-900/70 rounded-lg text-xs font-mono text-rose-300 flex items-start space-x-2.5">
            <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1">
              <div className="font-semibold text-rose-200">Scan Notice:</div>
              <div className="text-neutral-300 whitespace-pre-wrap">{scanError}</div>
              <div className="text-[11px] text-neutral-400 pt-1">
                Tip: Choose one of the preset paths above (e.g. <span className="text-white font-mono">. (Root)</span>, <span className="text-white font-mono">./backend</span>, or <span className="text-white font-mono">./frontend</span>), or provide an absolute directory path.
              </div>
            </div>
            <button
              onClick={() => setScanError(null)}
              className="text-neutral-400 hover:text-neutral-200 text-xs"
            >
              ✕
            </button>
          </div>
        )}
      </div>


      {/* 3. Main Content Canvas */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-4">
        {activeWorkspace === 'threats' && (
          <ThreatCenterView
            attackPaths={attackPaths}
            propagationRecords={propagationRecords}
            upstreamCommits={upstreamCommits}
            findings={findings}
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

      {/* 3. Read-only, evidence-grounded copilot (Cmd+K) */}
      <AiCopilotDrawer
        isOpen={isCopilotOpen}
        onClose={() => setIsCopilotOpen(false)}
        findingId={copilotFindingId}
        onQuery={queryCopilot}
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
