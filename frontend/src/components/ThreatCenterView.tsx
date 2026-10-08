import React, { useState, useMemo } from 'react';
import { AttackPath, CommitRecord, PatchPropagationRecord, VulnerabilityFinding } from '../types';
import {
  ArrowRight,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  GitPullRequest,
  Play,
  Activity,
  Layers,
  CheckCircle2,
  GitCommit,
  RotateCcw,
  Search,
} from 'lucide-react';

interface ThreatCenterViewProps {
  attackPaths: AttackPath[];
  propagationRecords: PatchPropagationRecord[];
  upstreamCommits: CommitRecord[];
  findings: VulnerabilityFinding[];
  onOpenAI: (findingId: string) => void;
  onGoToRemediation: () => void;
  onRunDemo: () => Promise<void>;
  onRecalculate: () => void;
}

export const ThreatCenterView: React.FC<ThreatCenterViewProps> = ({
  attackPaths,
  propagationRecords,
  upstreamCommits,
  findings,
  onOpenAI,
  onGoToRemediation,
  onRunDemo,
  onRecalculate,
}) => {
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationStep, setSimulationStep] = useState<string | null>(null);
  const [threatSearch, setThreatSearch] = useState('');
  const [threatFilter, setThreatFilter] = useState<'ALL' | 'OPEN' | 'CLOSED'>('ALL');

  // 1. Deduplicate attack paths by component/package identifier
  const deduplicatedPaths = useMemo(() => {
    const byComp = new Map<string, AttackPath>();
    attackPaths.forEach((p) => {
      const key = p.vulnerable_component || p.name;
      if (!byComp.has(key)) {
        byComp.set(key, p);
      }
    });
    return Array.from(byComp.values());
  }, [attackPaths]);

  // 2. Filter by search query and status
  const filteredPaths = useMemo(() => {
    return deduplicatedPaths.filter((p) => {
      if (threatFilter !== 'ALL' && p.status !== threatFilter) return false;
      if (threatSearch.trim()) {
        const q = threatSearch.toLowerCase();
        return (
          p.name.toLowerCase().includes(q) ||
          p.vulnerability_id.toLowerCase().includes(q) ||
          p.vulnerable_component.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [deduplicatedPaths, threatFilter, threatSearch]);

  const openPaths = deduplicatedPaths.filter((p) => p.status === 'OPEN');
  const isExposed = openPaths.length > 0;
  const hasFixturePath = openPaths.some((path) => path.fixture);

  const handleSimulate = async () => {
    setIsSimulating(true);
    setSimulationStep('Seeding explicitly labeled demo records...');
    try {
      await onRunDemo();
      setSimulationStep('Fixture complete. No repository change or deployment was verified.');
    } catch (error) {
      setSimulationStep(error instanceof Error ? `Fixture failed: ${error.message}` : 'Fixture failed.');
    } finally {
      setIsSimulating(false);
      setTimeout(() => setSimulationStep(null), 4000);
    }
  };

  return (
    <div className="space-y-4">
      {/* 1. Posture Header & Verification Trigger */}
      <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-900 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div
            className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
              attackPaths.length === 0
                ? 'bg-neutral-900/60 border-neutral-800 text-neutral-400'
                : isExposed
                ? 'bg-red-950/40 border-red-900/60 text-red-400'
                : 'bg-emerald-950/40 border-emerald-900/60 text-emerald-400'
            }`}
          >
            {attackPaths.length === 0 ? (
              <ShieldCheck className="w-4 h-4" />
            ) : isExposed ? (
              <ShieldAlert className="w-4 h-4" />
            ) : (
              <ShieldCheck className="w-4 h-4" />
            )}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-white">
                {attackPaths.length === 0
                  ? 'No Attack Path Records'
                  : hasFixturePath
                  ? 'Demo Fixture Path'
                  : isExposed
                  ? 'Vulnerable Dependency Exposure'
                  : 'Attack Path Status Unknown'}
              </span>
              <span
                className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-medium border ${
                  attackPaths.length === 0
                    ? 'bg-neutral-900 text-neutral-400 border-neutral-800'
                    : isExposed
                    ? 'bg-red-950/50 text-red-400 border-red-900/60'
                    : 'bg-emerald-950/50 text-emerald-400 border-emerald-900/60'
                }`}
              >
                {attackPaths.length === 0
                  ? 'NOT OBSERVED'
                  : hasFixturePath
                  ? 'SIMULATED FIXTURE'
                  : isExposed
                  ? `${openPaths.length} OPEN RECORDS`
                  : 'UNKNOWN'}
              </span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-neutral-900 text-neutral-400 border border-neutral-800">
                Deduplicated View
              </span>
            </div>
            <p className="text-[11px] text-neutral-400 mt-0.5">
              {attackPaths.length === 0
                ? 'No verified end-to-end path is available. This is not proof that the application is isolated.'
                : isExposed
                ? hasFixturePath
                  ? 'This path uses explicitly seeded demo data and is not an application observation.'
                  : `Showing ${openPaths.length} path record(s); review their evidence before treating them as reachable.`
                : 'No verified end-to-end path evidence is available; exposure remains unknown.'}
            </p>
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex items-center space-x-2 self-start md:self-auto shrink-0">
          <button
            onClick={onRecalculate}
            className="p-1.5 rounded-md text-neutral-400 hover:text-white hover:bg-neutral-900 border border-neutral-900 transition-colors"
            title="Recalculate Attack Paths"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={handleSimulate}
            disabled={isSimulating}
            className="flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all disabled:opacity-50"
          >
            {isSimulating ? (
              <>
                <Activity className="w-3.5 h-3.5 animate-spin" />
                <span>Loading Fixture...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Run Seeded Demo Fixture</span>
              </>
            )}
          </button>
        </div>
      </div>

      {simulationStep && (
        <div className="p-2.5 rounded-lg bg-black border border-neutral-800 text-[11px] font-mono text-neutral-300 flex items-center space-x-2 animate-in fade-in duration-150">
          <Activity className="w-3 h-3 text-neutral-400 animate-spin" />
          <span>{simulationStep}</span>
        </div>
      )}

      {/* 2. Filter & Search Strip */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 px-3 py-2 bg-neutral-950 border border-neutral-900 rounded-lg">
        <div className="flex items-center space-x-2 flex-1">
          <div className="relative w-full sm:w-64">
            <Search className="w-3 h-3 text-neutral-500 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search vulnerable package..."
              value={threatSearch}
              onChange={(e) => setThreatSearch(e.target.value)}
              className="w-full pl-7 pr-3 py-1 bg-black border border-neutral-800 rounded text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700 font-mono"
            />
          </div>

          <div className="flex items-center space-x-1">
            {(['ALL', 'OPEN', 'CLOSED'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setThreatFilter(tab)}
                className={`px-2 py-0.5 rounded text-[10px] font-mono transition-all ${
                  threatFilter === tab
                    ? 'bg-white text-black font-semibold'
                    : 'bg-black text-neutral-400 hover:text-white border border-neutral-800'
                }`}
              >
                {tab === 'ALL' ? `All (${deduplicatedPaths.length})` : tab}
              </button>
            ))}
          </div>
        </div>

        <div className="text-[10px] font-mono text-neutral-500">
          {filteredPaths.length} package cards displayed
        </div>
      </div>

      {/* 3. Deduplicated Threat Cards List */}
      {attackPaths.length === 0 ? (
        <div className="p-12 text-center text-neutral-500 bg-neutral-950 border border-neutral-900 rounded-xl">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-40 text-neutral-400" />
          <p className="text-xs font-semibold text-neutral-300">No Path Records Loaded</p>
          <p className="text-[11px] text-neutral-500 mt-1">
            No attack path records are available. This does not establish that the application is free of vulnerabilities.
          </p>
        </div>
      ) : filteredPaths.length === 0 ? (
        <div className="p-12 text-center text-neutral-500 bg-neutral-950 border border-neutral-900 rounded-xl">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 opacity-30 text-emerald-400" />
          <p className="text-xs font-semibold text-neutral-300">No matching threat cards</p>
          <p className="text-[11px] text-neutral-500 mt-1">No loaded path records match the active filter.</p>
        </div>
      ) : (
        filteredPaths.map((path) => {
          const isOpen = path.status === 'OPEN';
          const propagation = propagationRecords.find((r) => r.component_name === path.vulnerable_component);

          // Robust component name extraction
          let compClean = '';
          if (path.vulnerable_component) {
            const namePart = path.vulnerable_component.split('@')[0].split('/').pop() || '';
            if (namePart && namePart !== 'package' && namePart !== 'unknown') {
              compClean = namePart;
            }
          }
          if (!compClean && path.nodes) {
            const vulnNode = path.nodes.find((n) => n.role === 'VULNERABLE_COMPONENT');
            if (vulnNode?.label) {
              compClean = vulnNode.label.split(' ')[0];
            }
          }
          if (!compClean && path.name) {
            const match = path.name.match(/via\s+([a-zA-Z0-9_\-\.]+)/i);
            if (match) compClean = match[1];
          }
          if (!compClean || compClean === 'package') {
            compClean = 'unknown';
          }
          const copilotFinding = findings.find((finding) =>
            finding.vulnerability_id === path.vulnerability_id &&
            finding.component_name.toLowerCase() === compClean.toLowerCase()
          );

          return (
            <div
              key={path.id}
              className={`p-4 rounded-xl border transition-all ${
                isOpen
                  ? 'bg-neutral-950 border-neutral-800 ring-1 ring-red-950/30'
                  : 'bg-neutral-950 border-neutral-900 opacity-80'
              }`}
            >
              {/* Finding Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-neutral-900">
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border uppercase ${
                        isOpen
                          ? 'bg-red-950/40 text-red-400 border-red-900/60'
                          : 'bg-emerald-950/40 text-emerald-400 border-emerald-900/60'
                      }`}
                    >
                      {path.status}
                    </span>
                    <h3 className="text-xs font-semibold text-white tracking-tight">{path.name}</h3>
                    {path.fixture && <span className="ml-2 px-1.5 py-0.5 rounded border border-amber-900/60 text-[9px] font-mono text-amber-400">DEMO FIXTURE · NOT OBSERVED</span>}
                  </div>
                  <p className="text-[11px] text-neutral-400">{path.exploitation_condition}</p>
                </div>

                <div className="flex items-center space-x-2 shrink-0">
                  <button
                    onClick={() => copilotFinding && onOpenAI(copilotFinding.id)}
                    disabled={!copilotFinding}
                    title={copilotFinding ? 'Ask about this Osprey finding' : 'No matching persisted Osprey finding is available'}
                    className="px-2.5 py-1 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 flex items-center space-x-1.5 transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    <Sparkles className="w-3 h-3 text-neutral-400" />
                    <span>Ask Evidence Copilot</span>
                  </button>
                </div>
              </div>

              {/* Exploit Chain Flow */}
              <div className="py-3">
                <div className="text-[10px] font-mono uppercase text-neutral-500 mb-2">Path Record · Review Evidence Before Treating as Reachable</div>
                <div className="overflow-x-auto pb-1">
                  <div className="flex items-center space-x-2 min-w-max">
                    {path.nodes.map((node, i) => (
                      <React.Fragment key={node.id}>
                        <div className="p-2 rounded-lg bg-black border border-neutral-900 w-40">
                          <span className="text-[8.5px] font-mono uppercase text-neutral-500 block truncate">{node.role}</span>
                          <span className="text-[11px] font-semibold text-white mt-0.5 block truncate">{node.label}</span>
                          <span className="text-[9.5px] text-neutral-400 mt-0.5 line-clamp-2 leading-tight">
                            {node.description}
                          </span>
                        </div>
                        {i < path.nodes.length - 1 && (
                          <div className="flex flex-col items-center text-neutral-600 px-0.5">
                            <ArrowRight className="w-3 h-3 text-neutral-500" />
                            <span className="text-[7.5px] font-mono text-neutral-400 mt-0.5 max-w-[70px] text-center truncate">
                              {path.step_edges[i]?.label || 'routes to'}
                            </span>
                          </div>
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              </div>

              {/* Integrated Propagation Lag Diagnosis */}
              {propagation && (
                <div className="p-2.5 rounded-lg bg-black border border-neutral-900 text-xs space-y-1 mb-2.5">
                  <div className="flex items-center space-x-1.5 text-[10px] font-mono text-amber-400">
                    <Layers className="w-3 h-3 text-amber-400" />
                    <span>Supply Chain Lag Diagnosis (Bottleneck: {propagation.bottleneck_stage})</span>
                  </div>
                  <p className="text-[10.5px] text-neutral-300 leading-relaxed">
                    {propagation.summary_explanation}
                  </p>
                </div>
              )}

              {/* Action Bar Footer */}
              <div className="pt-2.5 border-t border-neutral-900 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                <div className="text-[10.5px] text-neutral-400 font-mono truncate">
                  {path.fixture ? 'Demo target asset (fixture)' : 'Target asset'}: <strong className="text-neutral-200">{path.target_resource}</strong>
                </div>

                <div className="flex items-center space-x-2">
                  {isOpen ? (
                    <button
                      onClick={onGoToRemediation}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all"
                    >
                      <GitPullRequest className="w-3 h-3" />
                      <span>Review Recommendation</span>
                    </button>
                  ) : (
                    <div className="flex items-center space-x-1.5 text-[11px] font-mono text-emerald-400">
                      <CheckCircle2 className="w-3 h-3" />
                      <span>{path.fixture ? 'Simulated Fixture State: Closed' : 'Closed Path Record'}</span>
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })
      )}

      {/* 4. Upstream Heuristic Commits Strip */}
      {upstreamCommits.length > 0 && (
        <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
          <div className="flex items-center justify-between pb-2 border-b border-neutral-900">
            <div className="flex items-center space-x-2">
              <GitCommit className="w-3.5 h-3.5 text-neutral-400" />
              <h3 className="text-xs font-semibold text-white">Upstream Security Commits (Pre-Advisory Signals)</h3>
            </div>
            <span className="text-[10px] font-mono text-neutral-500">
              Heuristic bounds-check & overflow fixes
            </span>
          </div>

          <div className="space-y-2">
            {upstreamCommits.slice(0, 3).map((commit) => (
              <div key={commit.commit_sha} className="p-2.5 rounded-lg bg-black border border-neutral-900 flex items-center justify-between text-xs">
                <div className="space-y-0.5">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-amber-400 text-[10px]">{commit.commit_sha.slice(0, 7)}</span>
                    <span className="text-neutral-200 font-medium truncate max-w-sm">{commit.message}</span>
                  </div>
                  <div className="flex items-center space-x-2 text-[10px] text-neutral-500 font-mono">
                    <span>{commit.repository}</span>
                    <span>•</span>
                    <span>Signals: {commit.detected_signals.join(', ')}</span>
                  </div>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 text-neutral-400 border border-neutral-800">
                  {commit.classification}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
