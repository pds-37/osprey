import React from 'react';
import { PatchPropagationRecord } from '../types';
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  Layers,
  RefreshCw,
  ShieldCheck,
  Sparkles,
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
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white tracking-tight flex items-center space-x-2">
            <span>Patch Propagation Lifecycle</span>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-neutral-900 text-neutral-400 border border-neutral-800">
              6 Stages
            </span>
          </h2>
          <p className="text-xs text-neutral-400 mt-0.5">
            Understanding why "Upstream has fixed the vulnerability" does NOT mean "Production is safe."
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-all font-mono self-start sm:self-auto"
        >
          <RefreshCw className="w-3 h-3" />
          <span>Re-evaluate Stages</span>
        </button>
      </div>

      {records.length === 0 ? (
        <div className="border border-neutral-900 rounded-xl bg-neutral-950 p-12 text-center text-neutral-500">
          <ShieldCheck className="w-8 h-8 mx-auto mb-2 text-emerald-400 opacity-60" />
          <p className="text-xs font-semibold text-white">No Propagation Records</p>
          <p className="text-[11px] text-neutral-400 mt-0.5">
            No known vulnerable components currently tracking upstream propagation.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {records.map((rec) => {
            return (
              <div
                key={rec.id}
                className={`p-4 rounded-xl border transition-all ${
                  rec.is_production_exposed
                    ? 'bg-neutral-950 border-neutral-800'
                    : 'bg-neutral-950 border-neutral-900'
                }`}
              >
                {/* Header Info */}
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-neutral-900">
                  <div className="space-y-0.5">
                    <div className="flex items-center space-x-2">
                      <span className="font-semibold text-sm text-white font-mono">{rec.component_name}</span>
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-neutral-900 text-neutral-300 border border-neutral-800">
                        Installed: {rec.installed_version}
                      </span>
                      <ArrowRight className="w-3 h-3 text-neutral-600" />
                      <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-emerald-950/40 text-emerald-400 border border-emerald-900/50">
                        Target: {rec.fixed_version}
                      </span>
                    </div>
                    <div className="flex items-center space-x-2 text-[11px] text-neutral-400">
                      <span>Vulnerability: <strong className="text-red-400 font-mono">{rec.vulnerability_id}</strong></span>
                      <span>•</span>
                      <span>App: <strong className="text-neutral-300">{rec.application}</strong></span>
                      <span>•</span>
                      <span>Env: <strong className="text-neutral-300">{rec.environment}</strong></span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-3">
                    <div className="text-right">
                      <div className="text-[9px] uppercase font-mono text-neutral-400">Bottleneck</div>
                      <span className="text-xs font-mono font-medium text-amber-400">
                        {STAGE_LABELS[rec.bottleneck_stage] || rec.bottleneck_stage}
                      </span>
                    </div>
                    <span
                      className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-medium border ${
                        rec.is_production_exposed
                          ? 'bg-red-950/40 text-red-400 border-red-900/60'
                          : 'bg-emerald-950/40 text-emerald-400 border-emerald-900/60'
                      }`}
                    >
                      {rec.is_production_exposed ? 'PRODUCTION EXPOSED' : 'PRODUCTION SECURED'}
                    </span>
                  </div>
                </div>

                {/* 6-Stage Propagation Minimal Grid */}
                <div className="py-4">
                  <div className="grid grid-cols-2 md:grid-cols-6 gap-2">
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
                          className={`p-2.5 rounded-lg border flex flex-col justify-between transition-all ${
                            isBottleneck
                              ? 'bg-black border-amber-900/60'
                              : isCompleted
                              ? 'bg-black border-neutral-800'
                              : 'bg-black border-neutral-900/60 opacity-60'
                          }`}
                        >
                          <div>
                            <div className="flex items-center justify-between mb-1.5">
                              <span className="text-[9px] font-mono text-neutral-400">
                                Step {idx + 1}
                              </span>
                              {isCompleted ? (
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                              ) : isBottleneck ? (
                                <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                              ) : (
                                <Clock className="w-3.5 h-3.5 text-neutral-600" />
                              )}
                            </div>
                            <div className="text-[11px] font-medium text-white mb-1">
                              {STAGE_LABELS[stageKey]}
                            </div>
                            <div className="text-[10px] text-neutral-400 line-clamp-3 leading-snug">
                              {stageData.evidence}
                            </div>
                          </div>

                          <div className="mt-2 pt-1.5 border-t border-neutral-900 flex items-center justify-between">
                            <span
                              className={`text-[9px] font-mono font-medium px-1.5 py-0.2 rounded ${
                                isCompleted
                                  ? 'text-emerald-400'
                                  : isBottleneck
                                  ? 'text-amber-400 font-bold'
                                  : 'text-neutral-500'
                              }`}
                            >
                              {stageData.status}
                            </span>
                            {stageData.version_or_tag && (
                              <span className="text-[9px] font-mono text-neutral-400 truncate max-w-[60px]">
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
                <div className="p-3 rounded-lg bg-black border border-neutral-900 flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs">
                  <div className="flex items-start space-x-2 text-neutral-300">
                    <Layers className="w-4 h-4 text-neutral-400 shrink-0 mt-0.5" />
                    <div>
                      <strong className="text-white">Propagation Diagnosis: </strong>
                      <span className="text-neutral-400">{rec.summary_explanation}</span>
                    </div>
                  </div>

                  <div className="flex items-center space-x-2 shrink-0">
                    <button
                      onClick={() => onOpenAI(rec.component_name)}
                      className="px-2.5 py-1 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 flex items-center space-x-1.5 transition-all"
                    >
                      <Sparkles className="w-3 h-3 text-neutral-400" />
                      <span>Ask AI Analyst</span>
                    </button>
                    <button
                      onClick={onOpenRemediation}
                      className="px-2.5 py-1 rounded-md text-xs font-semibold bg-white hover:bg-neutral-200 text-black transition-all"
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
