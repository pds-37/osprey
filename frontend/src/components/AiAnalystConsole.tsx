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
  'Which evidence supports this finding and what remains unknown?',
  'Is there a reachability result in the current records?',
  'What remediation is recommended from the current records?',
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
    <div className="space-y-4">
      {/* Console Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center space-x-2">
            <Sparkles className="w-3.5 h-3.5 text-neutral-300" />
            <span>Evidence Summary</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-neutral-900 text-neutral-400 border border-neutral-800">
              Deterministic
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-0.5">
            Summarizes existing inventory and advisory records; it does not create evidence or use a language model.
          </p>
        </div>

        <div className="flex items-center space-x-1.5">
          <span className="text-[11px] font-mono text-neutral-400">Targets:</span>
          {COMMON_COMPONENTS.map((c) => (
            <button
              key={c}
              onClick={() => setComponentName(c)}
              className={`px-2 py-0.5 rounded text-[11px] font-mono transition-all ${
                componentName === c
                  ? 'bg-neutral-100 text-black font-semibold'
                  : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-900'
              }`}
            >
              {c}
            </button>
          ))}
        </div>
      </div>

      {/* Query Bar */}
      <div className="p-4 rounded-xl bg-neutral-950 border border-neutral-900 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
          <div className="space-y-1">
            <label className="text-[10px] font-mono uppercase text-neutral-400">
              Component Name
            </label>
            <input
              type="text"
              value={componentName}
              onChange={(e) => setComponentName(e.target.value)}
              placeholder="e.g. libheif"
              className="w-full px-2.5 py-1.5 rounded-lg bg-black border border-neutral-900 text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700 font-mono"
            />
          </div>

          <div className="md:col-span-3 space-y-1">
            <label className="text-[10px] font-mono uppercase text-neutral-400">
              Question about stored records
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Ask about observed components, advisories, or evidence..."
                className="flex-1 px-2.5 py-1.5 rounded-lg bg-black border border-neutral-900 text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700"
              />
              <button
                onClick={handleRunAnalysis}
                disabled={loading || !componentName.trim()}
                className="px-4 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all flex items-center space-x-1.5 shrink-0 disabled:opacity-50"
              >
                {loading ? (
                  <>
                    <Activity className="w-3.5 h-3.5 animate-spin" />
                    <span>Summarizing...</span>
                  </>
                ) : (
                  <>
                    <Search className="w-3.5 h-3.5" />
                    <span>Summarize Records</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Preset Prompt Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-1.5 border-t border-neutral-900">
          <span className="text-[9px] font-mono text-neutral-400 uppercase">Templates:</span>
          {SAMPLE_QUESTIONS.map((q, idx) => (
            <button
              key={idx}
              onClick={() => setQuestion(q)}
              className="px-2 py-0.5 rounded text-[10px] text-neutral-400 bg-black hover:bg-neutral-900 hover:text-neutral-200 border border-neutral-900 transition-all text-left truncate max-w-sm"
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-black border border-red-900/50 text-red-400 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Deterministic Summary */}
      {report && (
        <div className="p-5 rounded-xl bg-neutral-950 border border-neutral-800 space-y-4">
          {/* Report Top Meta */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-neutral-900">
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="font-semibold text-xs text-white">
                  Evidence Summary: <span className="font-mono text-neutral-200">{report.target_component}</span>
                </h3>
              </div>
              <p className="text-[11px] text-neutral-400 mt-0.5 italic">"{report.query}"</p>
            </div>

            <div className="flex items-center space-x-1.5 text-neutral-400 text-[10px] font-mono">
              <span>Rule: Deterministic Grounding</span>
              <Lock className="w-3 h-3 text-emerald-400" />
            </div>
          </div>

          {/* Executive Summary */}
          <div className="p-3 rounded-lg bg-black border border-neutral-900 space-y-1">
            <h4 className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1.5">
              <Activity className="w-3 h-3 text-neutral-400" />
              <span>Summary</span>
            </h4>
            <p className="text-xs text-neutral-200 leading-relaxed">{report.executive_summary}</p>
          </div>

          {/* Multi-Section Analysis Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {/* Supply Chain Lineage */}
            <div className="p-3 rounded-lg bg-black border border-neutral-900 space-y-1">
              <h5 className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1.5">
                <Layers className="w-3 h-3 text-neutral-400" />
                <span>Supply Chain Lineage</span>
              </h5>
              <p className="text-xs text-neutral-300 leading-relaxed">{report.lineage_explanation}</p>
            </div>

            {/* Endpoint Context */}
            <div className="p-3 rounded-lg bg-black border border-neutral-900 space-y-1">
              <h5 className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1.5">
                <ShieldAlert className="w-3 h-3 text-red-400" />
                <span>Endpoint Context</span>
              </h5>
              <p className="text-xs text-neutral-300 leading-relaxed">{report.exposure_verdict}</p>
            </div>

            {/* Adversary Attack Path */}
            <div className="p-3 rounded-lg bg-black border border-neutral-900 space-y-1">
              <h5 className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1.5">
                <ArrowRight className="w-3 h-3 text-neutral-400" />
                <span>Attack Path Records</span>
              </h5>
              <p className="text-xs text-neutral-300 leading-relaxed">{report.attack_path_summary}</p>
            </div>

            {/* Upstream Change Signal */}
            <div className="p-3 rounded-lg bg-black border border-neutral-900 space-y-1">
              <h5 className="text-[10px] font-mono uppercase text-neutral-400 flex items-center space-x-1.5">
                <Cpu className="w-3 h-3 text-neutral-400" />
                <span>Upstream Intelligence</span>
              </h5>
              <p className="text-xs text-neutral-300 leading-relaxed">{report.upstream_change_summary}</p>
            </div>
          </div>

          {/* Remediation Callout */}
          <div className="p-3 rounded-lg bg-black border border-emerald-900/40 space-y-1">
            <h5 className="text-[10px] font-mono uppercase text-emerald-400 flex items-center space-x-1.5">
              <ShieldCheck className="w-3 h-3 text-emerald-400" />
              <span>Remediation Recommendation</span>
            </h5>
            <p className="text-xs text-neutral-200 leading-relaxed">{report.remediation_recommendation}</p>
          </div>

          {/* Verified Evidence Citations */}
          <div className="pt-2 border-t border-neutral-900 space-y-1.5">
            <div className="flex items-center space-x-1.5 text-[10px] font-mono text-neutral-400">
              <BookmarkCheck className="w-3 h-3 text-neutral-400" />
              <span>Evidence References ({report.evidence_citations.length})</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {report.evidence_citations.map((cite, i) => (
                <span
                  key={i}
                  className="px-2 py-0.5 rounded text-[10px] font-mono bg-black border border-neutral-900 text-neutral-300"
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
