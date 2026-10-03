import React, { useState } from 'react';
import { runFlagshipDemo } from '../api';
import { Play, CheckCircle2, Activity } from 'lucide-react';

interface FlagshipDemoBannerProps {
  onDemoComplete: () => void;
}

export const FlagshipDemoBanner: React.FC<FlagshipDemoBannerProps> = ({ onDemoComplete }) => {
  const [isRunning, setIsRunning] = useState(false);
  const [demoResult, setDemoResult] = useState<any | null>(null);
  const [activeStep, setActiveStep] = useState<number>(-1);
  const [error, setError] = useState<string | null>(null);

  const steps = [
    { title: '1. Ingest Multi-Tier SBOM', detail: 'App, Debian OS & libheif packages' },
    { title: '2. Correlate Vulnerability', detail: 'CVE-2023-44398 (CVSS 9.8 Heap Overflow)' },
    { title: '3. Upstream Fix Detection', detail: 'Commit 66f6cfb (libheif integer conversion)' },
    { title: '4. Patch Propagation Analysis', detail: 'Bottleneck: BASE_IMAGE_REBUILD' },
    { title: '5. Runtime Exposure Profiling', detail: 'Public Ingress: POST /upload (No Auth)' },
    { title: '6. Attack Path Traversal', detail: 'Internet -> image-service -> AWS S3' },
    { title: '7. Contextual Risk Engine', detail: 'Score 96.5 (CRITICAL) with 4 weighted factors' },
    { title: '8. AI Analyst Synthesis', detail: 'Evidence-grounded threat explanation' },
    { title: '9. PR Proposal Generation', detail: 'Dockerfile bump to libheif 1.19.8' },
    { title: '10. Human Approval Gate', detail: 'SecOps lead review & authorization' },
    { title: '11. Verification Rescan', detail: 'Attack Path CLOSED in production' },
  ];

  const handleRunDemo = async () => {
    setIsRunning(true);
    setError(null);
    setDemoResult(null);

    // Visual step sequence animation
    for (let i = 0; i < steps.length; i++) {
      setActiveStep(i);
      await new Promise((resolve) => setTimeout(resolve, 150));
    }

    try {
      const result = await runFlagshipDemo();
      setDemoResult(result);
      setActiveStep(steps.length);
      onDemoComplete();
    } catch (err: any) {
      setError(err?.message || 'Failed to run demonstration scenario');
    } finally {
      setIsRunning(false);
    }
  };

  return (
    <div className="rounded-2xl border border-indigo-500/30 bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 p-5 shadow-2xl space-y-4">
      {/* Top Banner Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 uppercase tracking-wider">
              Flagship Scenario
            </span>
            <h3 className="font-extrabold text-sm text-white tracking-tight">
              libheif / ImageMagick Supply Chain & Attack Path Walkthrough
            </h3>
          </div>
          <p className="text-xs text-slate-300">
            Simulate complete end-to-end lifecycle: ingestion, 3-state tracking, upstream commit signals, propagation lag, attack path discovery, PR generation, approval gate, and verification rescan.
          </p>
        </div>

        <button
          onClick={handleRunDemo}
          disabled={isRunning}
          className="flex items-center space-x-2 px-5 py-2.5 rounded-xl text-xs font-bold bg-gradient-to-r from-indigo-500 via-purple-600 to-pink-600 hover:from-indigo-400 hover:to-pink-500 text-white shadow-lg shadow-purple-900/40 transition-all shrink-0 disabled:opacity-50"
        >
          {isRunning ? (
            <>
              <Activity className="w-4 h-4 animate-spin" />
              <span>Simulating 11 Lifecycle Stages...</span>
            </>
          ) : (
            <>
              <Play className="w-4 h-4 fill-current" />
              <span>Run Live Demo Scenario</span>
            </>
          )}
        </button>
      </div>

      {/* 11 Steps Progress Bar / Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-11 gap-2 pt-2">
        {steps.map((st, i) => {
          const isDone = demoResult ? true : activeStep > i;
          const isCurrent = activeStep === i && isRunning;

          return (
            <div
              key={i}
              className={`p-2 rounded-xl border flex flex-col justify-between transition-all text-left ${
                isDone
                  ? 'bg-emerald-950/30 border-emerald-500/40'
                  : isCurrent
                  ? 'bg-indigo-950/60 border-indigo-500/60 ring-1 ring-indigo-400'
                  : 'bg-slate-950/40 border-slate-800/80 opacity-60'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[9px] font-mono font-bold text-slate-400">{i + 1}</span>
                  {isDone ? (
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  ) : isCurrent ? (
                    <Activity className="w-3 h-3 text-cyan-400 animate-spin" />
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-full bg-slate-700"></span>
                  )}
                </div>
                <div className="text-[10px] font-bold text-white truncate">{st.title.split('. ')[1]}</div>
              </div>
              <div className="text-[9px] text-slate-400 truncate mt-1">{st.detail}</div>
            </div>
          );
        })}
      </div>

      {error && (
        <div className="p-3 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-300 text-xs">
          {error}
        </div>
      )}

      {/* Result Callout Strip */}
      {demoResult && (
        <div className="p-3.5 rounded-xl bg-slate-950/90 border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
          <div className="flex items-center space-x-2 text-emerald-300 font-semibold">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>
              Demo Complete: libheif 1.19.8 verified in production. Attack Path has transitioned to{' '}
              <strong className="text-emerald-400 font-mono underline">CLOSED</strong>.
            </span>
          </div>

          <div className="flex items-center space-x-2 text-slate-400 font-mono text-[11px]">
            <span>PR: #{demoResult.steps?.propose_remediation_pr?.pull_request?.branch_name || 'patch/libheif-1.19.8'}</span>
            <span>•</span>
            <span>Actor: {demoResult.steps?.human_approval_gate?.approval_actor || 'secops-lead'}</span>
          </div>
        </div>
      )}
    </div>
  );
};
