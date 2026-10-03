import React, { useState } from 'react';
import { RemediationTask } from '../types';
import {
  GitPullRequest,
  CheckCircle2,
  ShieldCheck,
  FileCode,
  ArrowRight,
  UserCheck,
  Terminal,
} from 'lucide-react';

interface RemediationCenterProps {
  tasks: RemediationTask[];
  onApprove: (taskId: string, actor: string) => Promise<void>;
  onVerify: (taskId: string) => Promise<void>;
  onRefresh: () => void;
}

export const RemediationCenter: React.FC<RemediationCenterProps> = ({
  tasks,
  onApprove,
  onVerify,
  onRefresh,
}) => {
  const [approverName, setApproverName] = useState('secops-lead@guardian.internal');
  const [processingId, setProcessingId] = useState<string | null>(null);

  const handleApprove = async (taskId: string) => {
    try {
      setProcessingId(taskId);
      await onApprove(taskId, approverName);
    } finally {
      setProcessingId(null);
    }
  };

  const handleVerify = async (taskId: string) => {
    try {
      setProcessingId(taskId);
      await onVerify(taskId);
    } finally {
      setProcessingId(null);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight flex items-center space-x-2">
            <span>Remediation & Human Approval Gate</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
              Zero Autonomous Destruction
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Strict human-in-the-loop review for pull request proposals before CI/CD build, deployment, and post-fix verification.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <input
            type="text"
            value={approverName}
            onChange={(e) => setApproverName(e.target.value)}
            placeholder="Approving Engineer"
            className="px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 font-mono"
            title="Approver identity recorded in immutable audit log"
          />
          <button
            onClick={onRefresh}
            className="px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all"
          >
            Refresh Tasks
          </button>
        </div>
      </div>

      {tasks.length === 0 ? (
        <div className="border border-slate-800 rounded-2xl bg-slate-900/40 p-12 text-center text-slate-500">
          <ShieldCheck className="w-10 h-10 mx-auto mb-2 text-emerald-400 opacity-80" />
          <p className="text-sm font-semibold text-white">All Dependencies Remediated</p>
          <p className="text-xs text-slate-400 mt-1">No open remediation tasks requiring human approval or verification.</p>
        </div>
      ) : (
        <div className="space-y-6">
          {tasks.map((task) => {
            const pr = task.pull_request;
            const isApproved = task.status === 'APPROVED';
            const isVerified = task.status === 'VERIFIED_CLOSED';
            const isPending = task.status === 'PENDING_APPROVAL';

            return (
              <div
                key={task.id}
                className={`p-6 rounded-2xl border transition-all ${
                  isVerified
                    ? 'bg-slate-900/50 border-emerald-500/30'
                    : isApproved
                    ? 'bg-slate-900/70 border-cyan-500/30'
                    : 'bg-slate-900/80 border-amber-500/30 shadow-lg shadow-amber-950/10'
                }`}
              >
                {/* Task Header */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                        <GitPullRequest className="w-4 h-4" />
                      </div>
                      <h3 className="font-bold text-sm text-white">{pr.title}</h3>
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold border tracking-wider uppercase ${
                          isVerified
                            ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                            : isApproved
                            ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30'
                            : 'bg-amber-500/20 text-amber-400 border-amber-500/30 animate-pulse'
                        }`}
                      >
                        {task.status.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="flex items-center space-x-2 text-xs text-slate-400">
                      <span>Vulnerability: <strong className="text-rose-400 font-mono">{task.vulnerability_id}</strong></span>
                      <span>•</span>
                      <span>Target: <strong className="text-slate-200 font-mono">{task.component_name}</strong></span>
                      <span>•</span>
                      <span className="flex items-center space-x-1 font-mono text-slate-300">
                        <span>{task.current_version}</span>
                        <ArrowRight className="w-3 h-3 text-slate-500" />
                        <span className="text-emerald-400 font-bold">{task.target_version}</span>
                      </span>
                    </div>
                  </div>

                  {/* Actions Bar */}
                  <div className="flex items-center space-x-3">
                    {isPending && (
                      <button
                        onClick={() => handleApprove(task.id)}
                        disabled={processingId === task.id}
                        className="flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20 transition-all disabled:opacity-50"
                      >
                        <UserCheck className="w-4 h-4" />
                        <span>{processingId === task.id ? 'Approving...' : 'Approve Pull Request'}</span>
                      </button>
                    )}

                    {isApproved && (
                      <button
                        onClick={() => handleVerify(task.id)}
                        disabled={processingId === task.id}
                        className="flex items-center space-x-2 px-4 py-2 rounded-xl text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-600/20 transition-all disabled:opacity-50"
                      >
                        <ShieldCheck className="w-4 h-4" />
                        <span>{processingId === task.id ? 'Verifying...' : 'Verify Rescan (Close Attack Path)'}</span>
                      </button>
                    )}

                    {isVerified && (
                      <div className="flex items-center space-x-2 text-xs font-semibold text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-xl">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Remediated & Verified in Production</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Pull Request Details */}
                <div className="py-4 space-y-3">
                  <p className="text-xs text-slate-300 leading-relaxed">{pr.body}</p>

                  <div className="flex items-center space-x-4 text-xs font-mono text-slate-400 bg-slate-950/60 p-2.5 rounded-xl border border-slate-800/80">
                    <span className="flex items-center space-x-1.5">
                      <FileCode className="w-3.5 h-3.5 text-blue-400" />
                      <span>Target: <strong className="text-slate-200">{pr.target_file}</strong></span>
                    </span>
                    <span>•</span>
                    <span>Branch: <strong className="text-purple-400">{pr.branch_name}</strong></span>
                  </div>

                  {/* Unified Diff Box */}
                  <div className="rounded-xl overflow-hidden border border-slate-800 bg-[#080d16]">
                    <div className="bg-slate-950 px-4 py-2 border-b border-slate-800/80 flex items-center justify-between text-xs text-slate-400">
                      <span className="font-mono text-[11px] flex items-center space-x-1.5">
                        <Terminal className="w-3.5 h-3.5 text-slate-500" />
                        <span>Proposed Patch Diff</span>
                      </span>
                      <span className="text-[10px] text-slate-500 uppercase font-semibold">Git Patch</span>
                    </div>
                    <pre className="p-4 text-xs font-mono overflow-x-auto leading-relaxed">
                      {pr.diff_content.split('\n').map((line, idx) => {
                        let lineStyle = 'text-slate-400';
                        if (line.startsWith('+') && !line.startsWith('+++')) {
                          lineStyle = 'text-emerald-400 bg-emerald-950/30';
                        } else if (line.startsWith('-') && !line.startsWith('---')) {
                          lineStyle = 'text-rose-400 bg-rose-950/30';
                        } else if (line.startsWith('@@')) {
                          lineStyle = 'text-cyan-400 bg-cyan-950/20';
                        }
                        return (
                          <div key={idx} className={`px-2 py-0.5 rounded ${lineStyle}`}>
                            {line}
                          </div>
                        );
                      })}
                    </pre>
                  </div>
                </div>

                {/* Audit & Verification Log */}
                <div className="pt-3 border-t border-slate-800 text-xs text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center space-x-3">
                    {task.approval_actor && (
                      <span className="text-slate-300">
                        Approved by <strong className="text-white font-mono">{task.approval_actor}</strong> at{' '}
                        <span className="font-mono">{new Date(task.approved_at || '').toLocaleTimeString()}</span>
                      </span>
                    )}
                    {task.verified_at && (
                      <>
                        <span>•</span>
                        <span className="text-emerald-400 font-semibold">
                          Rescan confirmed: Attack Path Closed
                        </span>
                      </>
                    )}
                  </div>
                  <span className="font-mono text-[11px] text-slate-500">ID: {task.id}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
