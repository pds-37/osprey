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
    { title: '1. Ingest SBOM', detail: 'App, Debian OS & packages' },
    { title: '2. Correlate CVE', detail: 'CVE-2023-44398 (RCE)' },
    { title: '3. Upstream Fix', detail: 'Commit 66f6cfb' },
    { title: '4. Propagation Lag', detail: 'Bottleneck: Base Image' },
    { title: '5. Runtime Exposure', detail: 'POST /upload (Public)' },
    { title: '6. Attack Path', detail: 'Internet -> AWS S3' },
    { title: '7. Contextual Risk', detail: 'Score 96.5 / CRITICAL' },
    { title: '8. AI Analyst', detail: 'Grounded Synthesis' },
    { title: '9. PR Proposal', detail: 'Dockerfile bump 1.19.8' },
    { title: '10. Approval Gate', detail: 'Human Review' },
    { title: '11. Verification', detail: 'Rescan: CLOSED' },
  ];

  const handleRunDemo = async () => {
    setIsRunning(true);
    setError(null);
    setDemoResult(null);

    for (let i = 0; i < steps.length; i++) {
      setActiveStep(i);
      await new Promise((resolve) => setTimeout(resolve, 140));
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
    <div className="rounded-xl border border-neutral-900 bg-neutral-950 p-4 space-y-3.5">
      {/* Banner Top Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="space-y-0.5">
          <div className="flex items-center space-x-2">
            <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-neutral-900 text-neutral-400 border border-neutral-800">
              FLAGSHIP SCENARIO
            </span>
            <h3 className="font-semibold text-xs tracking-tight text-white">
              libheif / ImageMagick Supply Chain & Attack Path Walkthrough
            </h3>
          </div>
          <p className="text-[11px] text-neutral-400">
            Simulate complete end-to-end lifecycle: ingestion, 3-state tracking, upstream commit signals, propagation bottleneck, attack path traversal, PR proposal, human gate, and verification rescan.
          </p>
        </div>

        <button
          onClick={handleRunDemo}
          disabled={isRunning}
          className="flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all shrink-0 disabled:opacity-50"
        >
          {isRunning ? (
            <>
              <Activity className="w-3.5 h-3.5 animate-spin" />
              <span>Simulating 11 Stages...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Run Live Demo Scenario</span>
            </>
          )}
        </button>
      </div>

      {/* 11 Steps Progress Minimal Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-11 gap-1.5 pt-1">
        {steps.map((st, i) => {
          const isDone = demoResult ? true : activeStep > i;
          const isCurrent = activeStep === i && isRunning;

          return (
            <div
              key={i}
              className={`p-2 rounded-lg border flex flex-col justify-between transition-all text-left ${
                isDone
                  ? 'bg-black border-emerald-900/40 text-emerald-400'
                  : isCurrent
                  ? 'bg-neutral-900 border-neutral-700 text-white'
                  : 'bg-black border-neutral-900 text-neutral-500'
              }`}
            >
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[9px] font-mono font-medium opacity-60">{i + 1}</span>
                  {isDone ? (
                    <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                  ) : isCurrent ? (
                    <Activity className="w-3 h-3 text-white animate-spin" />
                  ) : (
                    <span className="w-1.5 h-1.5 rounded-full bg-neutral-800"></span>
                  )}
                </div>
                <div className="text-[10px] font-medium text-white truncate">{st.title.split('. ')[1]}</div>
              </div>
              <div className="text-[9px] text-neutral-400 truncate mt-1">{st.detail}</div>
            </div>
          );
        })}
      </div>

      {error && (
        <div className="p-2.5 rounded-lg bg-neutral-950 border border-red-900/50 text-red-400 text-xs font-mono">
          {error}
        </div>
      )}

      {/* Result Callout Strip */}
      {demoResult && (
        <div className="p-3 rounded-lg bg-black border border-emerald-900/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex items-center space-x-2 text-emerald-400 font-medium">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
            <span>
              Demo Complete: libheif 1.19.8 verified in production container. Attack Path status:{' '}
              <strong className="font-mono underline">CLOSED</strong>.
            </span>
          </div>

          <div className="flex items-center space-x-2 text-neutral-400 font-mono text-[11px]">
            <span>Branch: {demoResult.steps?.propose_remediation_pr?.pull_request?.branch_name || 'patch/libheif-1.19.8'}</span>
            <span>•</span>
            <span>Approver: {demoResult.steps?.human_approval_gate?.approval_actor || 'secops-lead'}</span>
          </div>
        </div>
      )}
    </div>
  );
};
