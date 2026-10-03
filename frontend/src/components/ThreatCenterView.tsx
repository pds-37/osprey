import React, { useState } from 'react';
import { AttackPath, CommitRecord, PatchPropagationRecord } from '../types';
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
} from 'lucide-react';

interface ThreatCenterViewProps {
  attackPaths: AttackPath[];
  propagationRecords: PatchPropagationRecord[];
  upstreamCommits: CommitRecord[];
  onOpenAI: (component: string) => void;
  onGoToRemediation: () => void;
  onRunDemo: () => Promise<void>;
  onRecalculate: () => void;
}

export const ThreatCenterView: React.FC<ThreatCenterViewProps> = ({
  attackPaths,
  propagationRecords,
  upstreamCommits,
  onOpenAI,
  onGoToRemediation,
  onRunDemo,
  onRecalculate,
}) => {
  const [isSimulating, setIsSimulating] = useState(false);
  const [simulationStep, setSimulationStep] = useState<string | null>(null);

  const openPaths = attackPaths.filter((p) => p.status === 'OPEN');
  const isExposed = openPaths.length > 0;

  const handleSimulate = async () => {
    setIsSimulating(true);
    setSimulationStep('Ingesting multi-tier SBOM...');
    await new Promise((r) => setTimeout(r, 200));
    setSimulationStep('Correlating CVE & commit heuristics...');
    await new Promise((r) => setTimeout(r, 200));
    setSimulationStep('Traversing attack path & computing risk...');
    await new Promise((r) => setTimeout(r, 200));
    setSimulationStep('Generating PR proposal & verifying rescan...');
    try {
      await onRunDemo();
      setSimulationStep('Simulated: libheif 1.19.8 deployed. Attack path CLOSED.');
    } finally {
      setIsSimulating(false);
      setTimeout(() => setSimulationStep(null), 4000);
    }
  };

  return (
    <div className="space-y-4">
      {/* 1. Sleek Posture Header & 1-Line Simulation Trigger */}
      <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-900 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div
            className={`w-8 h-8 rounded-lg flex items-center justify-center border ${
              isExposed
                ? 'bg-red-950/40 border-red-900/60 text-red-400'
                : 'bg-emerald-950/40 border-emerald-900/60 text-emerald-400'
            }`}
          >
            {isExposed ? <ShieldAlert className="w-4 h-4" /> : <ShieldCheck className="w-4 h-4" />}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-white">
                {isExposed ? 'Critical Supply Chain Exposure Detected' : 'All Workloads Secured & Verified'}
              </span>
              <span
                className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-medium border ${
                  isExposed
                    ? 'bg-red-950/50 text-red-400 border-red-900/60'
                    : 'bg-emerald-950/50 text-emerald-400 border-emerald-900/60'
                }`}
              >
                {isExposed ? `${openPaths.length} OPEN THREAT` : 'SECURED'}
              </span>
            </div>
            <p className="text-[11px] text-neutral-400 mt-0.5">
              {isExposed
                ? 'Public ingress routes reach sensitive AWS cloud resources via vulnerable container components.'
                : 'Zero active traversals from external entrypoints to sensitive production cloud assets.'}
            </p>
          </div>
        </div>

        {/* Compact Simulation Button */}
        <div className="flex items-center space-x-2 self-start md:self-auto shrink-0">
          <button
            onClick={onRecalculate}
            className="p-1.5 rounded-md text-neutral-400 hover:text-white hover:bg-neutral-900 border border-neutral-900 transition-colors"
            title="Recalculate Traversals"
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
                <span>Simulating...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Simulate Attack & Fix</span>
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

      {/* 2. Primary Active Threat Story Card */}
      {attackPaths.map((path) => {
        const isOpen = path.status === 'OPEN';
        const propagation = propagationRecords.find((r) => r.component_name === path.vulnerable_component);

        return (
          <div
            key={path.id}
            className={`p-5 rounded-xl border transition-all ${
              isOpen
                ? 'bg-neutral-950 border-neutral-800 ring-1 ring-red-950/40'
                : 'bg-neutral-950 border-neutral-900 opacity-90'
            }`}
          >
            {/* Finding Header */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3.5 border-b border-neutral-900">
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
                </div>
                <p className="text-[11px] text-neutral-400">{path.exploitation_condition}</p>
              </div>

              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 text-neutral-300 border border-neutral-800">
                  Risk Score: 96.5 · Critical
                </span>
                <button
                  onClick={() => onOpenAI(path.vulnerable_component || 'libheif')}
                  className="px-2.5 py-1 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 flex items-center space-x-1.5 transition-all"
                >
                  <Sparkles className="w-3 h-3 text-neutral-400" />
                  <span>Ask Copilot</span>
                </button>
              </div>
            </div>

            {/* Visual Threat Exploit Chain */}
            <div className="py-4">
              <div className="text-[10px] font-mono uppercase text-neutral-400 mb-2">Exploit Chain Flow</div>
              <div className="overflow-x-auto pb-1">
                <div className="flex items-center space-x-2 min-w-max">
                  {path.nodes.map((node, i) => (
                    <React.Fragment key={node.id}>
                      <div className="p-2.5 rounded-lg bg-black border border-neutral-900 w-44">
                        <span className="text-[9px] font-mono uppercase text-neutral-400 block truncate">{node.role}</span>
                        <span className="text-xs font-semibold text-white mt-0.5 block truncate">{node.label}</span>
                        <span className="text-[10px] text-neutral-400 mt-1 line-clamp-2 leading-tight">
                          {node.description}
                        </span>
                      </div>
                      {i < path.nodes.length - 1 && (
                        <div className="flex flex-col items-center text-neutral-600 px-1">
                          <ArrowRight className="w-3.5 h-3.5 text-neutral-500" />
                          <span className="text-[8px] font-mono text-neutral-400 mt-0.5 max-w-[80px] text-center truncate">
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
              <div className="p-3 rounded-lg bg-black border border-neutral-900 text-xs space-y-1.5 mb-3">
                <div className="flex items-center space-x-2 text-[10px] font-mono text-amber-400">
                  <Layers className="w-3 h-3 text-amber-400" />
                  <span>Supply Chain Lag Diagnosis (Bottleneck: {propagation.bottleneck_stage})</span>
                </div>
                <p className="text-[11px] text-neutral-300 leading-relaxed">
                  {propagation.summary_explanation}
                </p>
              </div>
            )}

            {/* Action Bar Footer */}
            <div className="pt-3 border-t border-neutral-900 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="text-[11px] text-neutral-400 font-mono">
                Target Asset: <strong className="text-neutral-200">{path.target_resource}</strong>
              </div>

              <div className="flex items-center space-x-2">
                {isOpen ? (
                  <button
                    onClick={onGoToRemediation}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all"
                  >
                    <GitPullRequest className="w-3.5 h-3.5" />
                    <span>Review & Approve PR (1.19.8)</span>
                  </button>
                ) : (
                  <div className="flex items-center space-x-1.5 text-[11px] font-mono text-emerald-400">
                    <CheckCircle2 className="w-3.5 h-3.5" />
                    <span>Remediated & Verified in Production</span>
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}

      {/* 3. Upstream Heuristic Signals (Compact Drawer/Card) */}
      {upstreamCommits.length > 0 && (
        <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-900 space-y-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <GitCommit className="w-3.5 h-3.5 text-neutral-400" />
              <h4 className="text-xs font-semibold text-white">Upstream Early-Warning Signals</h4>
            </div>
            <span className="text-[10px] font-mono text-neutral-400">{upstreamCommits.length} commits monitored</span>
          </div>

          <div className="space-y-1.5">
            {upstreamCommits.slice(0, 3).map((c) => (
              <div
                key={c.id}
                className="p-2 rounded-lg bg-black border border-neutral-900 flex items-center justify-between text-xs font-mono"
              >
                <div className="flex items-center space-x-2 truncate">
                  <span className="text-neutral-400">{c.commit_sha.substring(0, 8)}</span>
                  <span className="text-neutral-200 truncate">{c.message}</span>
                </div>
                <span className="px-1.5 py-0.2 rounded text-[10px] bg-neutral-900 text-neutral-400 shrink-0">
                  {c.classification}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
