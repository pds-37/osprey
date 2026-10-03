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
    { id: 'graph', label: 'Graph', icon: Network },
    { id: 'attack-paths', label: 'Attack Paths', icon: Route },
    { id: 'propagation', label: 'Propagation', icon: RefreshCw },
    { id: 'upstream', label: 'Upstream', icon: GitCommit },
    { id: 'remediation', label: 'Remediation', icon: GitPullRequest },
    { id: 'ai', label: 'AI Analyst', icon: Sparkles },
  ];

  return (
    <header className="border-b border-neutral-900 bg-black/95 backdrop-blur sticky top-0 z-40 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="h-14 flex items-center justify-between gap-4">
          {/* Minimalist Logo & Brand */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-sm tracking-tight text-white">GuardianOS</span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-medium bg-neutral-900 text-neutral-400 border border-neutral-800">
                v2.0
              </span>
            </div>
          </div>

          {/* Minimalist Center Navigation Tabs */}
          <nav className="hidden lg:flex items-center space-x-1 bg-neutral-950 p-1 rounded-lg border border-neutral-900">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs transition-all ${
                    isActive
                      ? 'bg-neutral-100 text-black font-semibold shadow-sm'
                      : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900/80 font-normal'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Right Status & Ingest Action */}
          <div className="flex items-center space-x-3 shrink-0">
            <div className="hidden sm:flex items-center space-x-1.5 text-[11px] font-mono px-2.5 py-1 rounded-md bg-neutral-950 border border-neutral-900 text-neutral-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
              <span>{systemStatus}</span>
            </div>

            <button
              onClick={onOpenUpload}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-white hover:bg-neutral-200 text-black transition-all"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Ingest SBOM</span>
            </button>
          </div>
        </div>

        {/* Responsive sub-bar for smaller screens */}
        <div className="lg:hidden pb-2 overflow-x-auto flex items-center space-x-1 border-t border-neutral-900 pt-1.5">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center space-x-1.5 px-2.5 py-1 rounded-md text-xs whitespace-nowrap transition-all ${
                  isActive
                    ? 'bg-neutral-100 text-black font-semibold'
                    : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
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
