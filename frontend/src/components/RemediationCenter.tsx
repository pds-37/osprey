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
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center space-x-2">
            <span>Remediation & Human Approval Gate</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-neutral-900 text-neutral-400 border border-neutral-800">
              Non-destructive
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-0.5">
            Strict human review for PR proposals prior to CI/CD build, deployment, and post-fix verification.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <input
            type="text"
            value={approverName}
            onChange={(e) => setApproverName(e.target.value)}
            placeholder="Approving Engineer"
            className="px-2.5 py-1.5 rounded-md bg-neutral-950 border border-neutral-900 text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700 font-mono"
            title="Approver identity recorded in immutable audit log"
          />
          <button
            onClick={onRefresh}
            className="px-3 py-1.5 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-all font-mono"
          >
            Refresh Tasks
          </button>
        </div>
      </div>

      {tasks.length === 0 ? (
        <div className="border border-neutral-900 rounded-xl bg-neutral-950 p-12 text-center text-neutral-500">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-60" />
          <p className="text-xs font-semibold text-white">All Dependencies Remediated</p>
          <p className="text-[11px] text-neutral-400 mt-0.5">No open remediation tasks requiring human approval or verification.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {tasks.map((task) => {
            const pr = task.pull_request;
            const isApproved = task.status === 'APPROVED';
            const isVerified = task.status === 'VERIFIED_CLOSED';
            const isPending = task.status === 'PENDING_APPROVAL';

            return (
              <div
                key={task.id}
                className={`p-4 rounded-xl border transition-all ${
                  isVerified
                    ? 'bg-neutral-950 border-neutral-900'
                    : isApproved
                    ? 'bg-neutral-950 border-neutral-800'
                    : 'bg-neutral-950 border-amber-900/60'
                }`}
              >
                {/* Task Header */}
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-neutral-900">
                  <div className="space-y-0.5">
                    <div className="flex items-center space-x-2">
                      <div className="p-1 rounded bg-neutral-900 border border-neutral-800 text-neutral-300">
                        <GitPullRequest className="w-3.5 h-3.5" />
                      </div>
                      <h3 className="font-semibold text-xs text-white">{pr.title}</h3>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-medium border uppercase ${
                          isVerified
                            ? 'bg-emerald-950/40 text-emerald-400 border-emerald-900/60'
                            : isApproved
                            ? 'bg-neutral-900 text-neutral-300 border-neutral-800'
                            : 'bg-amber-950/40 text-amber-400 border-amber-900/60'
                        }`}
                      >
                        {task.status.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="flex items-center space-x-2 text-[11px] text-neutral-400">
                      <span>Vulnerability: <strong className="text-red-400 font-mono">{task.vulnerability_id}</strong></span>
                      <span>•</span>
                      <span>Target: <strong className="text-neutral-200 font-mono">{task.component_name}</strong></span>
                      <span>•</span>
                      <span className="flex items-center space-x-1 font-mono text-neutral-300">
                        <span>{task.current_version}</span>
                        <ArrowRight className="w-3 h-3 text-neutral-600" />
                        <span className="text-emerald-400 font-bold">{task.target_version}</span>
                      </span>
                    </div>
                  </div>

                  {/* Actions Bar */}
                  <div className="flex items-center space-x-2">
                    {isPending && (
                      <button
                        onClick={() => handleApprove(task.id)}
                        disabled={processingId === task.id}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all disabled:opacity-50"
                      >
                        <UserCheck className="w-3.5 h-3.5" />
                        <span>{processingId === task.id ? 'Approving...' : 'Approve Pull Request'}</span>
                      </button>
                    )}

                    {isApproved && (
                      <button
                        onClick={() => handleVerify(task.id)}
                        disabled={processingId === task.id}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-neutral-100 hover:bg-neutral-300 text-black transition-all disabled:opacity-50"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>{processingId === task.id ? 'Verifying...' : 'Verify Rescan (Close Attack Path)'}</span>
                      </button>
                    )}

                    {isVerified && (
                      <div className="flex items-center space-x-1.5 text-[11px] font-mono text-emerald-400 bg-emerald-950/30 border border-emerald-900/50 px-2.5 py-1 rounded-md">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Remediated & Verified in Production</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Pull Request Details */}
                <div className="py-3 space-y-2.5">
                  <p className="text-[11px] text-neutral-400 leading-relaxed">{pr.body}</p>

                  <div className="flex items-center space-x-3 text-[11px] font-mono text-neutral-400 bg-black p-2 rounded-md border border-neutral-900">
                    <span className="flex items-center space-x-1">
                      <FileCode className="w-3 h-3 text-neutral-500" />
                      <span>Target: <strong className="text-neutral-200">{pr.target_file}</strong></span>
                    </span>
                    <span>•</span>
                    <span>Branch: <strong className="text-neutral-300">{pr.branch_name}</strong></span>
                  </div>

                  {/* Unified Diff Box */}
                  <div className="rounded-lg overflow-hidden border border-neutral-900 bg-black">
                    <div className="bg-neutral-950 px-3 py-1.5 border-b border-neutral-900 flex items-center justify-between text-xs text-neutral-400">
                      <span className="font-mono text-[10px] flex items-center space-x-1.5">
                        <Terminal className="w-3 h-3 text-neutral-500" />
                        <span>Proposed Patch Diff</span>
                      </span>
                      <span className="text-[9px] font-mono text-neutral-400 uppercase">Git Unified Diff</span>
                    </div>
                    <pre className="p-3 text-[11px] font-mono overflow-x-auto leading-relaxed">
                      {pr.diff_content.split('\n').map((line, idx) => {
                        let lineStyle = 'text-neutral-400';
                        if (line.startsWith('+') && !line.startsWith('+++')) {
                          lineStyle = 'text-emerald-400 bg-emerald-950/20';
                        } else if (line.startsWith('-') && !line.startsWith('---')) {
                          lineStyle = 'text-red-400 bg-red-950/20';
                        } else if (line.startsWith('@@')) {
                          lineStyle = 'text-neutral-400 bg-neutral-900';
                        }
                        return (
                          <div key={idx} className={`px-1.5 py-0.5 rounded ${lineStyle}`}>
                            {line}
                          </div>
                        );
                      })}
                    </pre>
                  </div>
                </div>

                {/* Audit & Verification Log */}
                <div className="pt-2 border-t border-neutral-900 text-[11px] text-neutral-400 flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                  <div className="flex items-center space-x-2">
                    {task.approval_actor && (
                      <span className="text-neutral-400">
                        Approved by <strong className="text-neutral-200 font-mono">{task.approval_actor}</strong> at{' '}
                        <span className="font-mono">{new Date(task.approved_at || '').toLocaleTimeString()}</span>
                      </span>
                    )}
                    {task.verified_at && (
                      <>
                        <span>•</span>
                        <span className="text-emerald-400 font-medium">
                          Rescan confirmed: Attack Path Closed
                        </span>
                      </>
                    )}
                  </div>
                  <span className="font-mono text-[10px] text-neutral-400">ID: {task.id}</span>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
