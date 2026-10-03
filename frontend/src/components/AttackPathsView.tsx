import React from 'react';
import { AttackPath } from '../types';
import { ArrowRight, CheckCircle2, ExternalLink } from 'lucide-react';

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
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight">Active Adversary Attack Paths</h2>
          <p className="text-xs text-slate-400">Deterministic graph traversals from external entrypoints to sensitive cloud assets</p>
        </div>
        <button
          onClick={onRecalculate}
          className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
        >
          Recalculate Traversal
        </button>
      </div>

      {attackPaths.length === 0 ? (
        <div className="border border-slate-800 rounded-2xl bg-slate-900/40 p-12 text-center text-slate-500">
          <CheckCircle2 className="w-10 h-10 mx-auto mb-2 text-emerald-400 opacity-80" />
          <p className="text-sm font-semibold text-white">No Open Attack Paths</p>
          <p className="text-xs text-slate-400 mt-1">All ingress routes are either authenticated or isolated from high-value resources.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {attackPaths.map((path) => (
            <div
              key={path.id}
              className={`p-6 rounded-2xl border transition-all ${
                path.status === 'OPEN'
                  ? 'bg-rose-950/20 border-rose-500/30 shadow-lg shadow-rose-950/20'
                  : 'bg-emerald-950/20 border-emerald-500/30'
              }`}
            >
              {/* Path Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-slate-800/80">
                <div>
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                        path.status === 'OPEN'
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/30 animate-pulse'
                          : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                      }`}
                    >
                      {path.status}
                    </span>
                    <h3 className="font-bold text-sm text-white">{path.name}</h3>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{path.exploitation_condition}</p>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono text-slate-400">Confidence: {(path.confidence * 100).toFixed(0)}%</span>
                  <button
                    onClick={() => onOpenAI('libheif')}
                    className="px-3 py-1 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white flex items-center space-x-1"
                  >
                    <span>Analyze with AI</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Step-by-Step Node Chain */}
              <div className="py-5 overflow-x-auto">
                <div className="flex items-center space-x-3 min-w-max">
                  {path.nodes.map((node, i) => (
                    <React.Fragment key={node.id}>
                      <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 flex flex-col w-48 shadow-md">
                        <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider">{node.role}</span>
                        <span className="text-xs font-bold text-white mt-1 truncate">{node.label}</span>
                        <span className="text-[11px] text-slate-400 mt-1 line-clamp-2">{node.description}</span>
                      </div>
                      {i < path.nodes.length - 1 && (
                        <div className="flex flex-col items-center text-slate-500">
                          <ArrowRight className="w-4 h-4 text-rose-400" />
                          <span className="text-[9px] font-mono text-slate-500 mt-0.5 max-w-[80px] text-center truncate">
                            {path.step_edges[i]?.label || 'routes to'}
                          </span>
                        </div>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>

              {/* Path Footer */}
              <div className="pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between text-xs text-slate-400 gap-2">
                <div>
                  <span className="font-semibold text-slate-300">Recommended Action: </span>
                  <span>{path.recommended_remediation}</span>
                </div>
                <div className="font-mono text-[11px] text-slate-500">Target: {path.target_resource}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
