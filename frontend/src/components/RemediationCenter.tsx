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
  onApprove: (taskId: string) => Promise<void>;
  onVerify: (taskId: string) => Promise<void>;
  onRefresh: () => void;
}

const renderInlineMarkdown = (text: string) => {
  const parts: React.ReactNode[] = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let lastIndex = 0;
  let match;

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push(text.slice(lastIndex, match.index));
    }
    const token = match[0];
    if (token.startsWith('**') && token.endsWith('**')) {
      parts.push(
        <strong key={match.index} className="text-white font-semibold">
          {token.slice(2, -2)}
        </strong>
      );
    } else if (token.startsWith('`') && token.endsWith('`')) {
      parts.push(
        <code
          key={match.index}
          className="px-1.5 py-0.5 rounded bg-neutral-900 text-emerald-400 font-mono text-[10.5px] border border-neutral-800"
        >
          {token.slice(1, -1)}
        </code>
      );
    }
    lastIndex = regex.lastIndex;
  }
  if (lastIndex < text.length) {
    parts.push(text.slice(lastIndex));
  }
  return parts.length > 0 ? parts : text;
};

const renderFormattedBody = (body: string) => {
  if (!body) return null;

  const lines = body.split('\n');
  const elements: React.ReactNode[] = [];
  let currentList: React.ReactNode[] = [];

  const flushList = () => {
    if (currentList.length > 0) {
      elements.push(
        <div
          key={`list-${elements.length}`}
          className="grid grid-cols-1 sm:grid-cols-2 gap-2 p-2.5 rounded-lg bg-black border border-neutral-900 my-1.5"
        >
          {currentList}
        </div>
      );
      currentList = [];
    }
  };

  lines.forEach((rawLine, idx) => {
    const line = rawLine.trim();
    if (!line) return;

    if (line.startsWith('## ')) {
      flushList();
      elements.push(
        <div
          key={`h2-${idx}`}
          className="text-xs font-bold text-white tracking-tight flex items-center space-x-1.5 pb-1 border-b border-neutral-900 mt-1 mb-1.5"
        >
          <span>{line.replace(/^##\s+/, '')}</span>
        </div>
      );
    } else if (line.startsWith('### ')) {
      flushList();
      elements.push(
        <div
          key={`h3-${idx}`}
          className="text-[10px] font-mono uppercase tracking-wider text-neutral-400 mt-2.5 mb-1"
        >
          <span>{line.replace(/^###\s+/, '')}</span>
        </div>
      );
    } else if (line.startsWith('- ') || line.startsWith('* ')) {
      const itemText = line.replace(/^[-\*]\s+/, '');
      currentList.push(
        <div key={`item-${idx}`} className="text-xs text-neutral-300 flex items-start space-x-1.5 py-0.5">
          <span className="text-neutral-500 mt-0.5">•</span>
          <span className="leading-snug">{renderInlineMarkdown(itemText)}</span>
        </div>
      );
    } else {
      flushList();
      elements.push(
        <p key={`p-${idx}`} className="text-xs text-neutral-300 leading-relaxed my-1">
          {renderInlineMarkdown(line)}
        </p>
      );
    }
  });

  flushList();
  return <div className="space-y-1.5 text-xs py-1">{elements}</div>;
};

export const RemediationCenter: React.FC<RemediationCenterProps> = ({
  tasks,
  onApprove,
  onVerify,
  onRefresh,
}) => {
  const [processingId, setProcessingId] = useState<string | null>(null);

  const handleApprove = async (taskId: string) => {
    try {
      setProcessingId(taskId);
      await onApprove(taskId);
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
            <span>Remediation Recommendations</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-neutral-900 text-neutral-400 border border-neutral-800">
              Non-destructive
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-0.5">
            Recommendations only. Osprey does not edit repositories, create branches, or deploy changes.
          </p>
        </div>

        <div className="flex items-center space-x-2">
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
          <p className="text-xs font-semibold text-white">No Recommendations Available</p>
          <p className="text-[11px] text-neutral-400 mt-0.5">No remediation recommendations are available in the current records.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {tasks.map((task) => {
            const pr = task.pull_request;
            const isApproved = task.status === 'APPROVED';
            const isVerified = task.status === 'VERIFIED_CLOSED' || task.status === 'VERIFIED_RESOLVED';
            const isUnverified = task.status === 'UNVERIFIED';
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
                      {task.fixture && <span className="px-1.5 py-0.5 rounded border border-amber-900/60 text-[9px] font-mono text-amber-400">DEMO FIXTURE</span>}
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
                        <span>{processingId === task.id ? 'Approving...' : 'Approve Recommendation'}</span>
                      </button>
                    )}

                    {(isApproved || isUnverified) && (
                      <button
                        onClick={() => handleVerify(task.id)}
                        disabled={processingId === task.id}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-neutral-100 hover:bg-neutral-300 text-black transition-all disabled:opacity-50"
                      >
                        <ShieldCheck className="w-3.5 h-3.5" />
                        <span>{processingId === task.id ? 'Checking...' : isUnverified ? 'Check New Inventory' : 'Check Inventory'}</span>
                      </button>
                    )}

                    {isVerified && (
                      <div className="flex items-center space-x-1.5 text-[11px] font-mono text-emerald-400 bg-emerald-950/30 border border-emerald-900/50 px-2.5 py-1 rounded-md">
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>{task.fixture ? 'Simulated fixture state' : 'Target version observed in inventory'}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Recommendation Details */}
                <div className="py-3 space-y-2.5">
                  {renderFormattedBody(pr.body)}

                  <div className="flex items-center space-x-3 text-[11px] font-mono text-neutral-400 bg-black p-2 rounded-md border border-neutral-900">
                    <span className="flex items-center space-x-1">
                      <FileCode className="w-3 h-3 text-neutral-500" />
                      <span>Repository change: <strong className="text-neutral-200">{pr.target_file || 'Not generated'}</strong></span>
                    </span>
                    <span>•</span>
                    <span>Branch: <strong className="text-neutral-300">{pr.branch_name || 'Not created'}</strong></span>
                  </div>

                  {/* Unified Diff Box */}
                  {pr.diff_content ? <div className="rounded-lg overflow-hidden border border-neutral-900 bg-black">
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
                  </div> : <div className="rounded-lg border border-neutral-900 bg-black p-3 text-xs text-neutral-400">No repository diff was generated. Apply the recommended version in the manifest or image build that supplies this component, then upload a fresh SBOM to check its status.</div>}
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
                          A fresh inventory observation was checked
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
