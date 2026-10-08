import React, { useEffect, useState } from 'react';
import { CopilotResponse } from '../types';
import { Activity, BookmarkCheck, Lock, Search, Sparkles, X } from 'lucide-react';

interface AiCopilotDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  findingId: string;
  onQuery: (findingId: string, question: string) => Promise<CopilotResponse>;
}

const PRESET_QUESTIONS = [
  'Why is this vulnerability risky?',
  'Is the vulnerable function reachable?',
  'What runtime evidence exists?',
  'Why was remediation not verified?',
];

export const AiCopilotDrawer: React.FC<AiCopilotDrawerProps> = ({
  isOpen,
  onClose,
  findingId,
  onQuery,
}) => {
  const [question, setQuestion] = useState(PRESET_QUESTIONS[0]);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<CopilotResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    setError(null);
  }, [findingId]);

  useEffect(() => {
    if (isOpen && findingId) void handleQuery(findingId, question);
  }, [isOpen, findingId]);

  const handleQuery = async (id: string, q: string) => {
    if (!id.trim() || !q.trim()) return;
    setLoading(true);
    setError(null);
    try {
      setReport(await onQuery(id.trim(), q.trim()));
    } catch (err: any) {
      setError(err?.message || 'Copilot query failed');
    } finally {
      setLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg bg-black border-l border-neutral-900 h-full flex flex-col shadow-2xl">
        <div className="px-5 py-3.5 border-b border-neutral-900 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-neutral-300" />
            <div>
              <h3 className="text-xs font-semibold text-white">Evidence Copilot</h3>
              <p className="text-[10px] text-neutral-400 font-mono">AI explanation · read-only · evidence-grounded</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded text-neutral-500 hover:text-white" aria-label="Close copilot">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-4 border-b border-neutral-900 space-y-2 bg-neutral-950">
          <div className="text-[10px] font-mono text-neutral-400">Finding ID: <span className="text-neutral-200">{findingId || 'UNKNOWN'}</span></div>
          <div className="flex gap-2">
            <input
              aria-label="Ask about finding"
              value={question}
              onChange={(event) => setQuestion(event.target.value)}
              maxLength={2000}
              placeholder="Ask about this finding..."
              className="flex-1 px-2.5 py-1.5 rounded-md bg-black border border-neutral-900 text-xs text-white"
            />
            <button
              onClick={() => void handleQuery(findingId, question)}
              disabled={loading || !findingId || !question.trim()}
              className="px-3 py-1.5 rounded-md text-xs font-semibold bg-white text-black disabled:opacity-50"
              aria-label="Query evidence copilot"
            >
              {loading ? <Activity className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
            </button>
          </div>
          <div className="flex flex-wrap gap-1">
            {PRESET_QUESTIONS.map((preset) => (
              <button key={preset} onClick={() => { setQuestion(preset); void handleQuery(findingId, preset); }} className="px-2 py-0.5 rounded text-[10px] text-neutral-400 bg-black border border-neutral-900 hover:text-white">
                {preset}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 p-5 overflow-y-auto space-y-4">
          {error && <div role="alert" className="p-3 rounded-lg bg-neutral-950 border border-red-900/60 text-red-400 text-xs">{error}</div>}
          {loading && <div className="py-12 text-center text-xs text-neutral-400"><Activity className="w-5 h-5 mx-auto mb-2 animate-spin" />Loading verified records...</div>}

          {report && (
            <div className="space-y-4">
              <section className="p-3 rounded-lg border border-sky-900/50 bg-sky-950/10 space-y-2">
                <div className="flex items-center gap-1.5 text-[10px] font-mono uppercase text-sky-300"><Lock className="w-3 h-3" />Deterministic Osprey Finding</div>
                <div className="text-xs text-neutral-200">{report.deterministic_finding.vulnerability_id} · {report.deterministic_finding.package} · {report.deterministic_finding.severity}</div>
                <div className="text-[11px] text-neutral-400">Static reachability: {report.deterministic_finding.reachability}</div>
                <div className="text-[10px] font-mono text-neutral-500">Runtime: {Object.entries(report.deterministic_finding.runtime_state).map(([key, value]) => `${key}=${value}`).join(' · ')}</div>
              </section>

              <section className="p-3 rounded-lg bg-neutral-950 border border-neutral-900 space-y-2">
                <div className="text-[10px] font-mono uppercase text-violet-300">AI Explanation</div>
                <p className="text-xs text-neutral-200 leading-relaxed">{report.answer}</p>
                <p className="text-[10px] text-neutral-500">Osprey renders every factual claim from verified evidence. The provider cannot change severity, reachability, runtime state, risk, or verification.</p>
                <p className="text-[10px] text-neutral-500">Provider: {report.provider} · Output validation: {report.validation_status} · AI explanation confidence: {report.ai_explanation_confidence}</p>
              </section>

              <section className="space-y-2">
                <div className="text-[10px] font-mono uppercase text-neutral-400 flex items-center gap-1"><BookmarkCheck className="w-3 h-3" />Evidence-backed claims</div>
                {report.claims.map((claim, index) => (
                  <div key={`${claim.text}-${index}`} className="p-2.5 rounded bg-neutral-950 border border-neutral-900 text-xs text-neutral-300">
                    <p>{claim.text}</p>
                    <div className="mt-1 text-[10px] font-mono text-sky-300">Evidence: {claim.evidence_ids.length ? claim.evidence_ids.join(', ') : 'No verified evidence reference'}</div>
                  </div>
                ))}
              </section>

              {report.unknowns.length > 0 && <section className="p-3 rounded-lg bg-amber-950/10 border border-amber-900/40"><div className="text-[10px] font-mono uppercase text-amber-300 mb-1">Unknowns</div><ul className="list-disc pl-4 text-xs text-neutral-300 space-y-1">{report.unknowns.map((item, index) => <li key={index}>{item}</li>)}</ul></section>}
              {report.limitations.length > 0 && <section className="p-3 rounded-lg bg-neutral-950 border border-neutral-900"><div className="text-[10px] font-mono uppercase text-neutral-400 mb-1">Limitations</div><ul className="list-disc pl-4 text-xs text-neutral-400 space-y-1">{report.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></section>}
              {report.recommended_next_steps.length > 0 && <section className="p-3 rounded-lg bg-neutral-950 border border-neutral-900"><div className="text-[10px] font-mono uppercase text-neutral-400 mb-1">Recommended next investigation</div><ul className="list-disc pl-4 text-xs text-neutral-300 space-y-1">{report.recommended_next_steps.map((item, index) => <li key={index}>{item}</li>)}</ul></section>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
