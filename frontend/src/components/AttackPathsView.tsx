import React from 'react';
import { AttackPath } from '../types';
import { ArrowRight, CheckCircle2, Sparkles } from 'lucide-react';

interface AttackPathsViewProps {
  attackPaths: AttackPath[];
  onRecalculate: () => void;
  onOpenAI: (component: string) => void;
}

export const AttackPathsView: React.FC<AttackPathsViewProps> = ({
  attackPaths,
  onRecalculate,
  onOpenAI,
}) => {
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight">Active Adversary Attack Paths</h2>
          <p className="text-xs text-neutral-400">Deterministic graph traversals from external ingress to cloud infrastructure</p>
        </div>
        <button
          onClick={onRecalculate}
          className="px-3 py-1.5 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-all font-mono"
        >
          Recalculate Paths
        </button>
      </div>

      {attackPaths.length === 0 ? (
        <div className="border border-neutral-900 rounded-xl bg-neutral-950 p-12 text-center text-neutral-500">
          <CheckCircle2 className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-60" />
          <p className="text-xs font-semibold text-white">No Open Attack Paths</p>
          <p className="text-[11px] text-neutral-400 mt-0.5">All ingress routes are either authenticated or isolated from high-value resources.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {attackPaths.map((path) => (
            <div
              key={path.id}
              className={`p-4 rounded-xl border transition-all ${
                path.status === 'OPEN'
                  ? 'bg-neutral-950 border-neutral-800 ring-1 ring-red-950/40'
                  : 'bg-neutral-950 border-neutral-900'
              }`}
            >
              {/* Path Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-neutral-900">
                <div>
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${
                        path.status === 'OPEN'
                          ? 'bg-red-950/40 text-red-400 border-red-900/60'
                          : 'bg-emerald-950/40 text-emerald-400 border-emerald-900/60'
                      }`}
                    >
                      {path.status}
                    </span>
                    <h3 className="font-semibold text-xs text-white">{path.name}</h3>
                  </div>
                  <p className="text-[11px] text-neutral-400 mt-1">{path.exploitation_condition}</p>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-[11px] font-mono text-neutral-400">Confidence: {(path.confidence * 100).toFixed(0)}%</span>
                  <button
                    onClick={() => onOpenAI('libheif')}
                    className="px-2.5 py-1 rounded-md text-xs font-medium bg-white hover:bg-neutral-200 text-black flex items-center space-x-1.5 transition-all"
                  >
                    <Sparkles className="w-3 h-3" />
                    <span>Analyze with AI</span>
                  </button>
                </div>
              </div>

              {/* Step-by-Step Node Chain */}
              <div className="py-4 overflow-x-auto">
                <div className="flex items-center space-x-2 min-w-max">
                  {path.nodes.map((node, i) => (
                    <React.Fragment key={node.id}>
                      <div className="p-2.5 rounded-lg bg-black border border-neutral-900 flex flex-col w-44">
                        <span className="text-[9px] font-mono uppercase text-neutral-400">{node.role}</span>
                        <span className="text-xs font-medium text-white mt-0.5 truncate">{node.label}</span>
                        <span className="text-[10px] text-neutral-400 mt-1 line-clamp-2 leading-tight">{node.description}</span>
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

              {/* Path Footer */}
              <div className="pt-2.5 border-t border-neutral-900 flex flex-col sm:flex-row sm:items-center justify-between text-[11px] text-neutral-400 gap-2">
                <div>
                  <span className="text-neutral-400">Recommended Action: </span>
                  <span className="text-neutral-200">{path.recommended_remediation}</span>
                </div>
                <div className="font-mono text-[10px] text-neutral-400">Target: {path.target_resource}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
