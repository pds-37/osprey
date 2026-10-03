import React, { useState, useEffect } from 'react';
import { AIAnalysisReport } from '../types';
import {
  X,
  Sparkles,
  Search,
  Activity,
  Layers,
  ShieldAlert,
  ArrowRight,
  ShieldCheck,
  BookmarkCheck,
  Lock,
  Cpu,
} from 'lucide-react';

interface AiCopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  targetComponent: string;
  onQuery: (component: string, question: string) => Promise<AIAnalysisReport>;
}

const PRESET_QUERIES = [
  'Why is this component dangerous and how can it be reached?',
  'Explain the attack path from the Internet to AWS S3 storage.',
  'What changed in upstream commits and why did the fix lag in production?',
  'What is the recommended remediation Pull Request?',
];

export const AiCopilotDrawer: React.FC<AiCopilotDrawerProps> = ({
  isOpen,
  onClose,
  targetComponent,
  onQuery,
}) => {
  const [component, setComponent] = useState(targetComponent || 'libheif');
  const [question, setQuestion] = useState(PRESET_QUERIES[0]);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<AIAnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (targetComponent) {
      setComponent(targetComponent);
    }
  }, [targetComponent]);

  useEffect(() => {
    // Auto-fetch if drawer opens with a valid component
    if (isOpen && component && !report) {
      handleAnalyze(component, question);
    }
  }, [isOpen, component]);

  const handleAnalyze = async (compName: string, q: string) => {
    if (!compName.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await onQuery(compName.trim(), q.trim());
      setReport(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to complete AI synthesis');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity">
      <div className="w-full max-w-lg bg-black border-l border-neutral-900 h-full flex flex-col shadow-2xl animate-in slide-in-from-right duration-200">
        {/* Drawer Header */}
        <div className="px-5 py-3.5 border-b border-neutral-900 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-6 h-6 rounded bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
              <Sparkles className="w-3.5 h-3.5" />
            </div>
            <div>
              <h3 className="text-xs font-semibold text-white tracking-tight">AI Security Copilot</h3>
              <p className="text-[10px] text-neutral-400 font-mono">Evidence-Grounded Threat Synthesis</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-neutral-500 hover:text-white hover:bg-neutral-900 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Query Input Area */}
        <div className="p-4 border-b border-neutral-900 space-y-2.5 bg-neutral-950">
          <div className="flex gap-2">
            <input
              type="text"
              value={component}
              onChange={(e) => setComponent(e.target.value)}
              placeholder="Component (e.g. libheif)"
              className="w-36 px-2.5 py-1.5 rounded-md bg-black border border-neutral-900 text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700 font-mono"
            />
            <input
              type="text"
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask inquiry..."
              className="flex-1 px-2.5 py-1.5 rounded-md bg-black border border-neutral-900 text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700"
            />
            <button
              onClick={() => handleAnalyze(component, question)}
              disabled={loading || !component.trim()}
              className="px-3 py-1.5 rounded-md text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all shrink-0 disabled:opacity-50"
            >
              {loading ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Quick Presets */}
          <div className="flex flex-wrap gap-1">
            {PRESET_QUERIES.map((q, idx) => (
              <button
                key={idx}
                onClick={() => {
                  setQuestion(q);
                  handleAnalyze(component, q);
                }}
                className="px-2 py-0.5 rounded text-[10px] text-neutral-400 bg-black hover:bg-neutral-900 hover:text-white border border-neutral-900 transition-all truncate max-w-[220px]"
              >
                {q}
              </button>
            ))}
          </div>
        </div>

        {/* Report Content Body */}
        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {error && (
            <div className="p-3 rounded-lg bg-neutral-950 border border-red-900/60 text-red-400 text-xs font-mono">
              {error}
            </div>
          )}

          {loading && !report && (
            <div className="py-20 text-center space-y-2">
              <Activity className="w-6 h-6 text-neutral-400 animate-spin mx-auto" />
              <p className="text-xs text-neutral-400 font-mono">Grounding graph facts & CVE data...</p>
            </div>
          )}

          {report && (
            <div className="space-y-3.5 animate-in fade-in duration-150">
              {/* Meta strip */}
              <div className="flex items-center justify-between text-[10px] font-mono pb-2 border-b border-neutral-900">
                <span className="text-neutral-400">
                  Target: <strong className="text-white">{report.target_component}</strong>
                </span>
                <span className="text-emerald-400 flex items-center space-x-1">
                  <Lock className="w-3 h-3" />
                  <span>Confidence: {(report.confidence_score * 100).toFixed(0)}%</span>
                </span>
              </div>

              {/* Executive Summary */}
              <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-900 space-y-1">
                <span className="text-[10px] font-mono uppercase text-neutral-400">Executive Summary</span>
                <p className="text-xs text-neutral-200 leading-relaxed">{report.executive_summary}</p>
              </div>

              {/* Lineage Breakdown */}
              <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-900 space-y-1">
                <span className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1">
                  <Layers className="w-3 h-3 text-neutral-400" />
                  <span>Lineage & Packaging</span>
                </span>
                <p className="text-xs text-neutral-300 leading-relaxed">{report.lineage_explanation}</p>
              </div>

              {/* Exposure Verdict */}
              <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-900 space-y-1">
                <span className="text-[10px] font-mono uppercase text-red-400 flex items-center space-x-1">
                  <ShieldAlert className="w-3 h-3 text-red-400" />
                  <span>Runtime Exposure</span>
                </span>
                <p className="text-xs text-neutral-300 leading-relaxed">{report.exposure_verdict}</p>
              </div>

              {/* Attack Path */}
              <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-900 space-y-1">
                <span className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1">
                  <ArrowRight className="w-3 h-3 text-neutral-400" />
                  <span>Exploit Traversal</span>
                </span>
                <p className="text-xs text-neutral-300 leading-relaxed">{report.attack_path_summary}</p>
              </div>

              {/* Upstream Changes */}
              <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-900 space-y-1">
                <span className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1">
                  <Cpu className="w-3 h-3 text-neutral-400" />
                  <span>Upstream Commit Signals</span>
                </span>
                <p className="text-xs text-neutral-300 leading-relaxed">{report.upstream_change_summary}</p>
              </div>

              {/* Remediation */}
              <div className="p-3 rounded-lg bg-neutral-950 border border-emerald-900/50 space-y-1">
                <span className="text-[10px] font-mono uppercase text-emerald-400 flex items-center space-x-1">
                  <ShieldCheck className="w-3 h-3 text-emerald-400" />
                  <span>Recommended Remediation</span>
                </span>
                <p className="text-xs text-neutral-200 leading-relaxed">{report.remediation_recommendation}</p>
              </div>

              {/* Citations */}
              <div className="pt-2 border-t border-neutral-900 space-y-1.5">
                <div className="text-[10px] font-mono text-neutral-400 flex items-center space-x-1">
                  <BookmarkCheck className="w-3 h-3" />
                  <span>Verified Graph Citations ({report.evidence_citations.length})</span>
                </div>
                <div className="flex flex-wrap gap-1">
                  {report.evidence_citations.map((cite, i) => (
                    <span
                      key={i}
                      className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-950 border border-neutral-900 text-neutral-400"
                    >
                      {cite}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
