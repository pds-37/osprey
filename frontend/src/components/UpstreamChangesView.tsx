import React from 'react';
import { CommitRecord } from '../types';
import { GitCommit, Sparkles } from 'lucide-react';

interface UpstreamChangesViewProps {
  commits: CommitRecord[];
}

export const UpstreamChangesView: React.FC<UpstreamChangesViewProps> = ({ commits }) => {
  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-base font-bold text-white tracking-tight">Upstream Change Intelligence</h2>
        <p className="text-xs text-slate-400">Heuristic early-warning detection on upstream commits, pull requests, and security fixes</p>
      </div>

      <div className="space-y-4">
        {commits.map((c) => (
          <div key={c.id} className="p-5 rounded-2xl bg-slate-900/60 border border-slate-800 backdrop-blur shadow-lg">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
              <div className="flex items-center space-x-2">
                <GitCommit className="w-4 h-4 text-indigo-400" />
                <span className="font-mono text-xs font-bold text-white">{c.commit_sha.substring(0, 10)}</span>
                <span className="text-xs text-slate-400">in <strong className="text-slate-200">{c.repository}</strong></span>
              </div>
              <div className="flex items-center space-x-2">
                <span
                  className={`px-2 py-0.5 rounded text-[11px] font-bold border ${
                    c.classification === 'SUSPECTED_SECURITY_CHANGE'
                      ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                      : 'bg-slate-500/10 text-slate-400 border-slate-500/20'
                  }`}
                >
                  {c.classification}
                </span>
                <span className="text-xs font-mono text-slate-400">Confidence: {(c.confidence * 100).toFixed(0)}%</span>
              </div>
            </div>

            <p className="text-xs text-slate-200 font-semibold mt-3">{c.message}</p>

            {c.diff_summary && (
              <div className="mt-3 p-3 rounded-xl bg-slate-950 font-mono text-[11px] text-emerald-400 border border-slate-800/80 overflow-x-auto whitespace-pre">
                {c.diff_summary}
              </div>
            )}

            {/* Detected Safety Signals Strip */}
            <div className="mt-4 pt-3 border-t border-slate-800 flex flex-wrap items-center gap-2">
              <span className="text-[11px] font-semibold text-slate-400 flex items-center space-x-1">
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                <span>Detected Safety Signals:</span>
              </span>
              {c.detected_signals.map((sig) => (
                <span key={sig} className="px-2 py-0.5 rounded text-[11px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  {sig}
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
