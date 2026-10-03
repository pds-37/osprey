import React from 'react';
import { ComponentItem } from '../types';
import { Search, GitBranch, Package } from 'lucide-react';

interface InventoryTableProps {
  components: ComponentItem[];
  searchQuery: string;
  setSearchQuery: (q: string) => void;
  selectedEcosystem: string;
  setSelectedEcosystem: (eco: string) => void;
  onSelectComponent: (comp: ComponentItem) => void;
}

export const InventoryTable: React.FC<InventoryTableProps> = ({
  components,
  searchQuery,
  setSearchQuery,
  selectedEcosystem,
  setSelectedEcosystem,
  onSelectComponent,
}) => {
  const ecosystems = ['all', 'debian', 'pypi', 'npm', 'docker', 'golang', 'maven'];

  return (
    <div className="space-y-3.5">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3">
        {/* Minimal Search Input */}
        <div className="relative w-full sm:w-80">
          <Search className="w-3.5 h-3.5 text-neutral-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filter components or PURL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-neutral-950 border border-neutral-900 rounded-lg text-xs text-white placeholder-neutral-600 focus:outline-none focus:border-neutral-700 font-mono transition-colors"
          />
        </div>

        {/* Minimalist Ecosystem Pills */}
        <div className="flex items-center space-x-1 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
          {ecosystems.map((eco) => (
            <button
              key={eco}
              onClick={() => setSelectedEcosystem(eco)}
              className={`px-2.5 py-1 rounded-md text-xs font-mono capitalize transition-all ${
                selectedEcosystem === eco
                  ? 'bg-neutral-100 text-black font-semibold'
                  : 'bg-neutral-950 text-neutral-400 hover:text-white border border-neutral-900 hover:border-neutral-800'
              }`}
            >
              {eco}
            </button>
          ))}
        </div>
      </div>

      {/* Minimalist Table Container */}
      <div className="border border-neutral-900 rounded-xl bg-neutral-950 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-black text-neutral-400 border-b border-neutral-900 uppercase font-mono text-[10px] tracking-wider">
              <tr>
                <th className="py-2.5 px-4 font-medium">Component & PURL</th>
                <th className="py-2.5 px-4 font-medium">Ecosystem</th>
                <th className="py-2.5 px-4 font-medium">Version</th>
                <th className="py-2.5 px-4 font-medium">Lifecycle State</th>
                <th className="py-2.5 px-4 font-medium">Application</th>
                <th className="py-2.5 px-4 font-medium">Environment</th>
                <th className="py-2.5 px-4 text-right font-medium">Lineage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-900/80">
              {components.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-neutral-600">
                    <Package className="w-6 h-6 mx-auto mb-2 opacity-30" />
                    <span className="text-xs">No components found in inventory.</span>
                  </td>
                </tr>
              ) : (
                components.map((comp) => {
                  return (
                    <tr key={comp.id} className="hover:bg-neutral-900/40 transition-colors">
                      <td className="py-2.5 px-4">
                        <div className="font-medium text-white">{comp.name}</div>
                        <div className="font-mono text-[10px] text-neutral-400 truncate max-w-xs">{comp.purl}</div>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-neutral-900 text-neutral-300 border border-neutral-800 capitalize">
                          {comp.ecosystem}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 font-mono text-neutral-300 text-[11px]">
                        {comp.version}
                      </td>
                      <td className="py-2.5 px-4">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-medium border ${
                            comp.state === 'RUNNING'
                              ? 'bg-emerald-950/40 text-emerald-400 border-emerald-900/50'
                              : comp.state === 'INSTALLED'
                              ? 'bg-neutral-900 text-neutral-300 border-neutral-800'
                              : 'bg-neutral-950 text-neutral-400 border-neutral-900'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                              comp.state === 'RUNNING'
                                ? 'bg-emerald-400'
                                : comp.state === 'INSTALLED'
                                ? 'bg-neutral-400'
                                : 'bg-neutral-600'
                            }`}
                          ></span>
                          {comp.state}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-neutral-300">
                        {comp.application}
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="capitalize text-neutral-400 font-mono text-[11px]">{comp.environment}</span>
                      </td>
                      <td className="py-2.5 px-4 text-right">
                        <button
                          onClick={() => onSelectComponent(comp)}
                          className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-[11px] font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-all"
                        >
                          <GitBranch className="w-3 h-3 text-neutral-400" />
                          <span>Lineage</span>
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
