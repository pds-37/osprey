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

const ECOSYSTEM_BADGES: Record<string, { bg: string; text: string; border: string }> = {
  pypi: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20' },
  npm: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20' },
  debian: { bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/20' },
  docker: { bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/20' },
  golang: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20' },
  maven: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20' },
  generic: { bg: 'bg-slate-500/10', text: 'text-slate-400', border: 'border-slate-500/20' },
};

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
    <div className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        {/* Search Input */}
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filter by name or PURL..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        {/* Ecosystem Pills */}
        <div className="flex items-center space-x-1.5 overflow-x-auto w-full sm:w-auto pb-1 sm:pb-0">
          {ecosystems.map((eco) => (
            <button
              key={eco}
              onClick={() => setSelectedEcosystem(eco)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold capitalize transition-all ${
                selectedEcosystem === eco
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                  : 'bg-slate-900/60 text-slate-400 hover:text-white border border-slate-800/80'
              }`}
            >
              {eco}
            </button>
          ))}
        </div>
      </div>

      {/* Table Container */}
      <div className="border border-slate-800/80 rounded-2xl bg-slate-900/40 backdrop-blur overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-950/60 text-slate-400 border-b border-slate-800/80 uppercase tracking-wider text-[11px] font-semibold">
              <tr>
                <th className="py-3 px-4">Component & PURL</th>
                <th className="py-3 px-4">Ecosystem</th>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Lifecycle State</th>
                <th className="py-3 px-4">Application</th>
                <th className="py-3 px-4">Environment</th>
                <th className="py-3 px-4 text-right">Lineage</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {components.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-slate-500">
                    <Package className="w-8 h-8 mx-auto mb-2 opacity-40" />
                    No components discovered. Ingest an SBOM to begin intelligence analysis.
                  </td>
                </tr>
              ) : (
                components.map((comp) => {
                  const ecoBadge = ECOSYSTEM_BADGES[comp.ecosystem] || ECOSYSTEM_BADGES.generic;
                  return (
                    <tr key={comp.id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white">{comp.name}</div>
                        <div className="font-mono text-[11px] text-slate-500 truncate max-w-xs">{comp.purl}</div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[11px] font-semibold border ${ecoBadge.bg} ${ecoBadge.text} ${ecoBadge.border} capitalize`}>
                          {comp.ecosystem}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-slate-300">
                        {comp.version}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-semibold border ${
                            comp.state === 'RUNNING'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                              : comp.state === 'INSTALLED'
                              ? 'bg-blue-500/10 text-blue-400 border-blue-500/20'
                              : 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                          }`}
                        >
                          <span className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                            comp.state === 'RUNNING' ? 'bg-emerald-400' : comp.state === 'INSTALLED' ? 'bg-blue-400' : 'bg-purple-400'
                          }`}></span>
                          {comp.state}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-slate-300">
                        {comp.application}
                      </td>
                      <td className="py-3 px-4">
                        <span className="capitalize text-slate-400">{comp.environment}</span>
                      </td>
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => onSelectComponent(comp)}
                          className="inline-flex items-center space-x-1.5 px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-800 hover:bg-blue-600 text-slate-300 hover:text-white transition-all border border-slate-700/60 hover:border-blue-500"
                        >
                          <GitBranch className="w-3.5 h-3.5" />
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
