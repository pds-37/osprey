import React from 'react';
import {
  Shield,
  Network,
  Layers,
  Upload,
  Route,
  RefreshCw,
  GitCommit,
  GitPullRequest,
  Sparkles,
} from 'lucide-react';

export type NavigationTab =
  | 'inventory'
  | 'graph'
  | 'attack-paths'
  | 'propagation'
  | 'upstream'
  | 'remediation'
  | 'ai';

interface HeaderProps {
  activeTab: NavigationTab;
  setActiveTab: (tab: NavigationTab) => void;
  onOpenUpload: () => void;
  systemStatus: string;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  onOpenUpload,
  systemStatus,
}) => {
  const tabs: { id: NavigationTab; label: string; icon: React.FC<{ className?: string }> }[] = [
    { id: 'inventory', label: 'Inventory', icon: Layers },
    { id: 'graph', label: 'Knowledge Graph', icon: Network },
    { id: 'attack-paths', label: 'Attack Paths', icon: Route },
    { id: 'propagation', label: 'Propagation', icon: RefreshCw },
    { id: 'upstream', label: 'Upstream Changes', icon: GitCommit },
    { id: 'remediation', label: 'Remediation PRs', icon: GitPullRequest },
    { id: 'ai', label: 'AI Analyst', icon: Sparkles },
  ];

  return (
    <header className="border-b border-slate-800 bg-[#0c1322]/95 backdrop-blur sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="h-16 flex items-center justify-between gap-4">
          {/* Logo & Platform Info */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-blue-600 via-indigo-500 to-cyan-400 flex items-center justify-center shadow-lg shadow-blue-500/20">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-base text-white tracking-tight">GuardianOS</span>
                <span className="px-1.5 py-0.2 rounded text-[10px] font-semibold bg-blue-500/10 text-blue-400 border border-blue-500/20">
                  v2.0
                </span>
              </div>
              <p className="text-[10px] text-slate-400 font-medium hidden sm:block">
                Supply Chain & Attack Path Control Plane
              </p>
            </div>
          </div>

          {/* Center Navigation Tabs */}
          <nav className="hidden lg:flex items-center space-x-1 bg-slate-900/90 p-1 rounded-xl border border-slate-800/80">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    isActive
                      ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30 font-bold'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Actions */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="hidden md:flex items-center space-x-1.5 text-[11px] font-mono px-2.5 py-1 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>{systemStatus}</span>
            </div>

            <button
              onClick={onOpenUpload}
              className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white shadow-lg shadow-indigo-600/25 transition-all"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Ingest SBOM</span>
            </button>
          </div>
        </div>

        {/* Responsive sub-bar for smaller screens */}
        <div className="lg:hidden pb-2.5 overflow-x-auto flex items-center space-x-1 border-t border-slate-800/60 pt-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-1.5 px-3 py-1 rounded-lg text-xs font-semibold whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-blue-600 text-white shadow font-bold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
