import React from 'react';
import { PatchPropagationRecord } from '../types';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Layers,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react';

interface PatchPropagationViewProps {
  records: PatchPropagationRecord[];
  onRefresh: () => void;
  onOpenAI: (component: string) => void;
  onOpenRemediation: () => void;
}

const STAGE_ORDER = [
  'UPSTREAM_FIX',
  'SECURITY_ADVISORY',
  'DISTRIBUTION_PACKAGE',
  'BASE_IMAGE_REBUILD',
  'APPLICATION_IMAGE_REBUILD',
  'PRODUCTION_DEPLOYMENT',
];

const STAGE_LABELS: Record<string, string> = {
  UPSTREAM_FIX: '1. Upstream Fix',
  SECURITY_ADVISORY: '2. Advisory Issued',
  DISTRIBUTION_PACKAGE: '3. Distro Package',
  BASE_IMAGE_REBUILD: '4. Base Image',
  APPLICATION_IMAGE_REBUILD: '5. App Image',
  PRODUCTION_DEPLOYMENT: '6. Production',
};

export const PatchPropagationView: React.FC<PatchPropagationViewProps> = ({
  records,
  onRefresh,
  onOpenAI,
  onOpenRemediation,
}) => {
  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-tight flex items-center space-x-2">
            <span>Patch Propagation Lifecycle</span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-purple-500/20 text-purple-300 border border-purple-500/30">
              6-Stage Pipeline
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Understanding why "Upstream has fixed the vulnerability" does NOT mean "Production is safe."
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="flex items-center space-x-2 px-3 py-1.5 rounded-xl text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-all self-start sm:self-auto"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          <span>Re-evaluate Stages</span>
        </button>
      </div>

      {records.length === 0 ? (
        <div className="border border-slate-800 rounded-2xl bg-slate-900/40 p-12 text-center text-slate-500">
          <ShieldCheck className="w-10 h-10 mx-auto mb-2 text-emerald-400 opacity-80" />
          <p className="text-sm font-semibold text-white">No Patch Propagation Records</p>
          <p className="text-xs text-slate-400 mt-1">
            No known vulnerable components currently tracking upstream propagation.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {records.map((rec) => {
            return (
              <div
                key={rec.id}
                className={`p-6 rounded-2xl border transition-all ${
                  rec.is_production_exposed
                    ? 'bg-slate-900/70 border-rose-500/30 shadow-lg shadow-rose-950/10'
                    : 'bg-slate-900/60 border-emerald-500/30'
                }`}
              >
                {/* Header Info */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-4 border-b border-slate-800">
                  <div className="space-y-1">
                    <div className="flex items-center space-x-3">
                      <span className="font-bold text-base text-white font-mono">{rec.component_name}</span>
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                        Installed: {rec.installed_version}
                      </span>
                      <ArrowRight className="w-3.5 h-3.5 text-slate-500" />
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                        Target: {rec.fixed_version}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2 text-xs text-slate-400">
                      <span>Vulnerability: <strong className="text-rose-400 font-mono">{rec.vulnerability_id}</strong></span>
                      <span>•</span>
                      <span>App: <strong className="text-slate-200">{rec.application}</strong></span>
                      <span>•</span>
                      <span>Env: <strong className="text-slate-200">{rec.environment}</strong></span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <div className="text-[10px] uppercase font-bold text-slate-500 tracking-wider">Identified Bottleneck</div>
                      <span className="text-xs font-mono font-bold text-amber-400">
                        {STAGE_LABELS[rec.bottleneck_stage] || rec.bottleneck_stage}
                      </span>
                    </div>
                    <span
                      className={`px-3 py-1 rounded-xl text-xs font-bold border flex items-center space-x-1.5 ${
                        rec.is_production_exposed
                          ? 'bg-rose-500/20 text-rose-400 border-rose-500/30 animate-pulse'
                          : 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                      }`}
                    >
                      {rec.is_production_exposed ? (
                        <>
                          <ShieldAlert className="w-3.5 h-3.5" />
                          <span>PRODUCTION EXPOSED</span>
                        </>
                      ) : (
                        <>
                          <ShieldCheck className="w-3.5 h-3.5" />
                          <span>PRODUCTION SECURED</span>
                        </>
                      )}
                    </span>
                  </div>
                </div>

                {/* 6-Stage Propagation Stepper */}
                <div className="py-6">
                  <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                    {STAGE_ORDER.map((stageKey, idx) => {
                      const stageData = rec.stages[stageKey] || {
                        stage: stageKey,
                        status: 'PENDING',
                        evidence: 'Awaiting upstream update',
                      };
                      const isCompleted = stageData.status === 'COMPLETED' || stageData.status === 'FIXED' || stageData.status === 'RELEASED';
                      const isBottleneck = rec.bottleneck_stage === stageKey;

                      return (
                        <div
                          key={stageKey}
                          className={`p-3.5 rounded-xl border flex flex-col justify-between transition-all ${
                            isBottleneck
                              ? 'bg-amber-950/30 border-amber-500/50 ring-1 ring-amber-500/30'
                              : isCompleted
                              ? 'bg-slate-900/90 border-emerald-500/30'
                              : 'bg-slate-950/60 border-slate-800/80 opacity-70'
                          }`}
                        >
                          <div>
                            <div className="flex items-center justify-between mb-2">
                              <span className="text-[10px] font-bold text-slate-400 uppercase tracking-wider">
                                Step {idx + 1}
                              </span>
                              {isCompleted ? (
                                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                              ) : isBottleneck ? (
                                <AlertTriangle className="w-4 h-4 text-amber-400 animate-bounce" />
                              ) : (
                                <Clock className="w-4 h-4 text-slate-500" />
                              )}
                            </div>
                            <div className="text-xs font-bold text-white mb-1">
                              {STAGE_LABELS[stageKey]}
                            </div>
                            <div className="text-[10px] text-slate-400 line-clamp-3 leading-snug">
                              {stageData.evidence}
                            </div>
                          </div>

                          <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between">
                            <span
                              className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${
                                isCompleted
                                  ? 'bg-emerald-500/10 text-emerald-400'
                                  : isBottleneck
                                  ? 'bg-amber-500/20 text-amber-300 font-extrabold'
                                  : 'bg-slate-800 text-slate-500'
                              }`}
                            >
                              {stageData.status}
                            </span>
                            {stageData.version_or_tag && (
                              <span className="text-[9px] font-mono text-slate-400 truncate max-w-[60px]">
                                {stageData.version_or_tag}
                              </span>
                            )}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                {/* Summary Explanation Box */}
                <div className="p-3.5 rounded-xl bg-slate-950/80 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                  <div className="flex items-start space-x-2 text-slate-300">
                    <Layers className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white">Propagation Diagnosis: </strong>
                      <span className="text-slate-300">{rec.summary_explanation}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    <button
                      onClick={() => onOpenAI(rec.component_name)}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 border border-blue-500/30 flex items-center space-x-1 transition-all"
                    >
                      <Zap className="w-3.5 h-3.5 text-blue-400" />
                      <span>Ask AI Analyst</span>
                    </button>
                    <button
                      onClick={onOpenRemediation}
                      className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow transition-all"
                    >
                      <span>Fix in Dockerfile</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
