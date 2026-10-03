import React, { useState } from 'react';
import { AIAnalysisReport } from '../types';
import {
  Sparkles,
  Search,
  ShieldCheck,
  ShieldAlert,
  ArrowRight,
  Layers,
  Activity,
  Cpu,
  BookmarkCheck,
  Lock,
} from 'lucide-react';

interface AiAnalystConsoleProps {
  onQuery: (component: string, question: string) => Promise<AIAnalysisReport>;
  initialComponent?: string;
}

const SAMPLE_QUESTIONS = [
  'Why is this component dangerous and how can it be reached?',
  'Explain the attack path from the Internet to AWS S3 storage.',
  'What changed in upstream commits and why did the fix lag in production?',
  'What is the recommended remediation Pull Request?',
];

const COMMON_COMPONENTS = ['libheif', 'imagemagick', 'urllib3', 'semver', 'axios'];

export const AiAnalystConsole: React.FC<AiAnalystConsoleProps> = ({
  onQuery,
  initialComponent = 'libheif',
}) => {
  const [componentName, setComponentName] = useState(initialComponent);
  const [question, setQuestion] = useState(SAMPLE_QUESTIONS[0]);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<AIAnalysisReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleRunAnalysis = async () => {
    if (!componentName.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const res = await onQuery(componentName.trim(), question.trim());
      setReport(res);
    } catch (err: any) {
      setError(err?.message || 'Failed to complete AI analysis');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Console Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight flex items-center space-x-2">
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>AI Security Analyst</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
              Evidence-Grounded Synthesis
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Deterministic graph & CVE evidence synthesized with zero hallucination and strict prompt-injection defenses.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400">Quick Targets:</span>
          {COMMON_COMPONENTS.map((c) => (
            <button
              key={c}
              onClick={() => setComponentName(c)}
              className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all ${
                componentName === c
                  ? 'bg-blue-600 text-white font-bold'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {c}
            </button>
          ))}
        </div>
      </div>

      {/* Query Bar */}
      <div className="p-5 rounded-2xl bg-slate-900/80 border border-slate-800 space-y-4 shadow-xl">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          <div className="space-y-1">
            <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Component Name
            </label>
            <input
              type="text"
              value={componentName}
              onChange={(e) => setComponentName(e.target.value)}
              placeholder="e.g. libheif, urllib3"
              className="w-full px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="md:col-span-3 space-y-1">
            <label className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Investigation Prompt
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Ask specific threat, lineage, or attack path questions..."
                className="flex-1 px-3 py-2 rounded-xl bg-slate-950 border border-slate-700 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={handleRunAnalysis}
                disabled={loading || !componentName.trim()}
                className="px-5 py-2 rounded-xl text-xs font-semibold bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-cyan-600/25 transition-all flex items-center space-x-2 shrink-0 disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Activity className="w-3.5 h-3.5 animate-spin" />
                    <span>Reasoning...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Run Synthesis</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Preset Prompt Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80">
          <span className="text-[10px] text-slate-500 uppercase font-semibold">Templates:</span>
          {SAMPLE_QUESTIONS.map((q, idx) => (
            <button
              key={idx}
              onClick={() => setQuestion(q)}
              className="px-2.5 py-1 rounded-lg text-[11px] text-slate-400 bg-slate-950 hover:bg-slate-800 hover:text-slate-200 border border-slate-800 transition-all text-left truncate max-w-sm"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs">
          {error}
        </div>
      )}

      {/* Synthesis Output Report Card */}
      {report && (
        <div className="p-6 rounded-2xl bg-slate-900/90 border border-cyan-500/30 shadow-2xl space-y-6">
          {/* Report Top Meta */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
            <div>
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-cyan-500/20 text-cyan-300 border border-cyan-500/30">
                  CONFIDENCE: {(report.confidence_score * 100).toFixed(0)}%
                </span>
                <h3 className="font-bold text-sm text-white">
                  Threat Synthesis Report for <span className="font-mono text-cyan-400">{report.target_component}</span>
                </h3>
              </div>
              <p className="text-xs text-slate-400 mt-1 italic">"{report.query}"</p>
            </div>

            <div className="flex items-center space-x-2">
              <span className="text-[10px] font-mono text-slate-500">Security Rule: Deterministic Grounding</span>
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
            </div>
          </div>

          {/* Executive Summary */}
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 space-y-2">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center space-x-2">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>Executive Synthesis</span>
            </h4>
            <p className="text-xs text-slate-200 leading-relaxed font-sans">{report.executive_summary}</p>
          </div>

          {/* Multi-Section Analysis Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Supply Chain Lineage */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1.5">
              <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
                <Layers className="w-3.5 h-3.5 text-blue-400" />
                <span>Supply Chain Lineage</span>
              </h5>
              <p className="text-xs text-slate-300 leading-relaxed">{report.lineage_explanation}</p>
            </div>

            {/* Runtime Exposure Verdict */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1.5">
              <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
                <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                <span>Runtime Exposure Verdict</span>
              </h5>
              <p className="text-xs text-slate-300 leading-relaxed">{report.exposure_verdict}</p>
            </div>

            {/* Adversary Attack Path */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1.5">
              <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
                <ArrowRight className="w-3.5 h-3.5 text-amber-400" />
                <span>Attack Path Traversal</span>
              </h5>
              <p className="text-xs text-slate-300 leading-relaxed">{report.attack_path_summary}</p>
            </div>

            {/* Upstream Change Signal */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-1.5">
              <h5 className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center space-x-2">
                <Cpu className="w-3.5 h-3.5 text-purple-400" />
                <span>Upstream Intelligence & Commits</span>
              </h5>
              <p className="text-xs text-slate-300 leading-relaxed">{report.upstream_change_summary}</p>
            </div>
          </div>

          {/* Remediation Callout */}
          <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 space-y-1.5">
            <h5 className="text-[11px] font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-2">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
              <span>Remediation Recommendation</span>
            </h5>
            <p className="text-xs text-slate-200 leading-relaxed">{report.remediation_recommendation}</p>
          </div>

          {/* Verified Evidence Citations */}
          <div className="pt-4 border-t border-slate-800 space-y-2">
            <div className="flex items-center space-x-2 text-xs font-semibold text-slate-400">
              <BookmarkCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span>Authoritative Grounding Citations ({report.evidence_citations.length} verified facts)</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {report.evidence_citations.map((cite, i) => (
                <span
                  key={i}
                  className="px-2.5 py-1 rounded-lg text-[10px] font-mono bg-slate-950 border border-slate-800 text-cyan-300/90 shadow-sm"
                >
                  {cite}
                </span>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
