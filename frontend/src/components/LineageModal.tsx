import React, { useEffect, useState } from 'react';
import { X, GitBranch, Layers, ArrowDown, Package } from 'lucide-react';
import { ComponentItem } from '../types';
import { fetchComponentLineage } from '../api';

interface LineageModalProps {
  component: ComponentItem | null;
  onClose: () => void;
}

export const LineageModal: React.FC<LineageModalProps> = ({ component, onClose }) => {
  const [loading, setLoading] = useState(false);
  const [lineageData, setLineageData] = useState<any>(null);

  useEffect(() => {
    if (component) {
      setLoading(true);
      fetchComponentLineage(component.purl)
        .then((data) => setLineageData(data))
        .catch(() => setLineageData(null))
        .finally(() => setLoading(false));
    }
  }, [component]);

  if (!component) return null;

  const nodes = lineageData?.subgraph?.nodes || [];

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="bg-[#0f172a] border border-slate-700 w-full max-w-xl rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-8 h-8 rounded-lg bg-indigo-500/10 flex items-center justify-center text-indigo-400">
              <GitBranch className="w-4 h-4" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Dependency Lineage & Propagation</h2>
              <p className="text-xs text-slate-400">Ancestry trail from Workload to Component</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {/* Target Component Header Card */}
          <div className="p-4 rounded-xl bg-slate-900 border border-slate-800">
            <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">Inspected Target</div>
            <div className="flex items-center justify-between">
              <div>
                <span className="font-bold text-base text-white">{component.name}</span>
                <span className="ml-2 font-mono text-xs text-slate-400">{component.version}</span>
              </div>
              <span className="px-2.5 py-0.5 rounded text-xs font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                {component.ecosystem}
              </span>
            </div>
            <div className="font-mono text-xs text-slate-500 mt-2 truncate">{component.purl}</div>
          </div>

          {/* Visual Propagation / Lineage Stack */}
          <div>
            <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-3 flex items-center space-x-2">
              <Layers className="w-3.5 h-3.5 text-blue-400" />
              <span>Hierarchical Propagation Chain</span>
            </h3>

            {loading ? (
              <div className="text-center py-8 text-xs text-slate-400">Traversing knowledge graph...</div>
            ) : nodes.length === 0 ? (
              <div className="text-center py-6 text-xs text-slate-500">
                Direct component with no recorded parents in current scan.
              </div>
            ) : (
              <div className="space-y-3">
                {/* Visual Stack Step */}
                <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className="w-6 h-6 rounded-lg bg-blue-500/20 text-blue-400 text-xs font-bold flex items-center justify-center">1</span>
                    <div>
                      <div className="text-xs font-bold text-white">Application Workload</div>
                      <div className="text-[11px] text-slate-400">{component.application} ({component.environment})</div>
                    </div>
                  </div>
                  <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    {component.state}
                  </span>
                </div>

                <div className="flex justify-center text-slate-600">
                  <ArrowDown className="w-4 h-4" />
                </div>

                {/* Connected Parent Packages */}
                {nodes.filter((n: any) => n.id !== component.purl).map((node: any, idx: number) => (
                  <React.Fragment key={node.id}>
                    <div className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className="w-6 h-6 rounded-lg bg-indigo-500/20 text-indigo-400 text-xs font-bold flex items-center justify-center">{idx + 2}</span>
                        <div>
                          <div className="text-xs font-bold text-white">{node.label}</div>
                          <div className="text-[11px] font-mono text-slate-400">{node.properties?.name || node.id}</div>
                        </div>
                      </div>
                      <span className="text-[11px] text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                        {node.properties?.version || 'parent'}
                      </span>
                    </div>

                    <div className="flex justify-center text-slate-600">
                      <ArrowDown className="w-4 h-4" />
                    </div>
                  </React.Fragment>
                ))}

                {/* Final Target Node */}
                <div className="p-3 rounded-xl bg-blue-950/40 border border-blue-500/40 flex items-center justify-between shadow-lg shadow-blue-500/10">
                  <div className="flex items-center space-x-3">
                    <Package className="w-5 h-5 text-blue-400" />
                    <div>
                      <div className="text-xs font-bold text-blue-300">Target Leaf Component</div>
                      <div className="text-[11px] font-mono text-slate-300">{component.name} @ {component.version}</div>
                    </div>
                  </div>
                  <span className="text-[11px] text-blue-400 bg-blue-500/20 px-2 py-0.5 rounded border border-blue-500/30 font-semibold">
                    Resolved
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-white rounded-xl transition-all"
          >
            Close Lineage
          </button>
        </div>
      </div>
    </div>
  );
};
