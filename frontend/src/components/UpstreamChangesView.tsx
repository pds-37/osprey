import React from 'react';
import { CommitRecord } from '../types';
import { GitCommit, Sparkles } from 'lucide-react';

interface UpstreamChangesViewProps {
  commits: CommitRecord[];
}

export const UpstreamChangesView: React.FC<UpstreamChangesViewProps> = ({ commits }) => {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-white tracking-tight">Upstream Change Intelligence</h2>
        <p className="text-xs text-neutral-400">Heuristic early-warning detection on upstream commits, pull requests, and security fixes</p>
      </div>

      <div className="space-y-3">
        {commits.map((c) => (
          <div key={c.id} className="p-4 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2.5 border-b border-neutral-900">
              <div className="flex items-center space-x-2">
                <GitCommit className="w-3.5 h-3.5 text-neutral-400" />
                <span className="font-mono text-xs font-semibold text-white">{c.commit_sha.substring(0, 10)}</span>
                <span className="text-xs text-neutral-400">in <strong className="text-neutral-200">{c.repository}</strong></span>
              </div>
              <div className="flex items-center space-x-2">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${
                    c.classification === 'CONFIRMED_VULNERABILITY_FIX'
                      ? 'bg-emerald-950/40 text-emerald-400 border-emerald-900/60'
                      : 'bg-neutral-900 text-neutral-400 border-neutral-800'
                  }`}
                >
                  {c.classification}
                </span>
                <span className="text-[11px] font-mono text-neutral-400">Confidence: {(c.confidence * 100).toFixed(0)}%</span>
              </div>
            </div>

            <p className="text-xs text-neutral-200 font-medium">{c.message}</p>

            {c.diff_summary && (
              <div className="p-2.5 rounded-lg bg-black font-mono text-[11px] text-neutral-300 border border-neutral-900 overflow-x-auto whitespace-pre leading-relaxed">
                {c.diff_summary}
              </div>
            )}

            {/* Detected Safety Signals Strip */}
            <div className="pt-2 border-t border-neutral-900 flex flex-wrap items-center gap-1.5">
              <span className="text-[10px] font-mono text-neutral-400 flex items-center space-x-1">
                <Sparkles className="w-3 h-3 text-neutral-400" />
                <span>Detected Signals:</span>
              </span>
              {c.detected_signals.map((sig) => (
                <span key={sig} className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 text-neutral-300 border border-neutral-800">
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
