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
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-md">
      <div className="bg-neutral-950 border border-neutral-900 w-full max-w-xl rounded-xl shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-neutral-900 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <div className="w-7 h-7 rounded-md bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
              <GitBranch className="w-3.5 h-3.5 text-neutral-300" />
            </div>
            <div>
              <h2 className="text-sm font-semibold text-white">Dependency Lineage & Propagation</h2>
              <p className="text-[11px] text-neutral-400">Ancestry trail from Workload to Component</p>
            </div>
          </div>
          <button onClick={onClose} className="p-1 rounded text-neutral-500 hover:text-white hover:bg-neutral-900">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">
          {/* Target Component Header Card */}
          <div className="p-3 rounded-lg bg-black border border-neutral-900">
            <div className="text-[10px] font-mono text-neutral-400 uppercase tracking-wider mb-1">Target Component</div>
            <div className="flex items-center justify-between">
              <div>
                <span className="font-semibold text-sm text-white">{component.name}</span>
                <span className="ml-2 font-mono text-xs text-neutral-400">{component.version}</span>
              </div>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 text-neutral-300 border border-neutral-800">
                {component.ecosystem}
              </span>
            </div>
            <div className="font-mono text-[10px] text-neutral-400 mt-1 truncate">{component.purl}</div>
          </div>

          {/* Visual Propagation / Lineage Stack */}
          <div>
            <h3 className="text-[10px] font-mono text-neutral-400 uppercase tracking-wider mb-2 flex items-center space-x-1.5">
              <Layers className="w-3 h-3 text-neutral-400" />
              <span>Propagation Chain</span>
            </h3>

            {loading ? (
              <div className="text-center py-6 text-xs text-neutral-400 font-mono">Traversing knowledge graph...</div>
            ) : nodes.length === 0 ? (
              <div className="text-center py-4 text-xs text-neutral-500 font-mono">
                Direct component with no recorded parents in current scan.
              </div>
            ) : (
              <div className="space-y-2">
                {/* Visual Stack Step */}
                <div className="p-2.5 rounded-lg bg-black border border-neutral-900 flex items-center justify-between">
                  <div className="flex items-center space-x-2.5">
                    <span className="w-5 h-5 rounded bg-neutral-900 text-neutral-300 text-[10px] font-mono font-bold flex items-center justify-center">1</span>
                    <div>
                      <div className="text-xs font-medium text-white">Application Workload</div>
                      <div className="text-[10px] font-mono text-neutral-400">{component.application} ({component.environment})</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/40">
                    {component.state}
                  </span>
                </div>

                <div className="flex justify-center text-neutral-600">
                  <ArrowDown className="w-3.5 h-3.5" />
                </div>

                {/* Connected Parent Packages */}
                {nodes.filter((n: any) => n.id !== component.purl).map((node: any, idx: number) => (
                  <React.Fragment key={node.id}>
                    <div className="p-2.5 rounded-lg bg-black border border-neutral-900 flex items-center justify-between">
                      <div className="flex items-center space-x-2.5">
                        <span className="w-5 h-5 rounded bg-neutral-900 text-neutral-300 text-[10px] font-mono font-bold flex items-center justify-center">{idx + 2}</span>
                        <div>
                          <div className="text-xs font-medium text-white">{node.label}</div>
                          <div className="text-[10px] font-mono text-neutral-400">{node.properties?.name || node.id}</div>
                        </div>
                      </div>
                      <span className="text-[10px] font-mono text-neutral-400 bg-neutral-900 px-2 py-0.5 rounded border border-neutral-800">
                        {node.properties?.version || 'parent'}
                      </span>
                    </div>

                    <div className="flex justify-center text-neutral-600">
                      <ArrowDown className="w-3.5 h-3.5" />
                    </div>
                  </React.Fragment>
                ))}

                {/* Final Target Node */}
                <div className="p-2.5 rounded-lg bg-black border border-neutral-800 flex items-center justify-between">
                  <div className="flex items-center space-x-2.5">
                    <Package className="w-4 h-4 text-neutral-300" />
                    <div>
                      <div className="text-xs font-medium text-white">Target Leaf Component</div>
                      <div className="text-[10px] font-mono text-neutral-400">{component.name} @ {component.version}</div>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono text-white bg-neutral-900 px-2 py-0.5 rounded border border-neutral-800 font-semibold">
                    Resolved
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-neutral-900 flex justify-end">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-white rounded-md border border-neutral-800 transition-all font-mono"
          >
            Close Lineage
          </button>
        </div>
      </div>
    </div>
  );
};
