import React from 'react';
import {
  Shield,
  Layers,
  Upload,
  GitPullRequest,
  Sparkles,
  Flame,
} from 'lucide-react';

export type MainWorkspace = 'threats' | 'supply-chain' | 'remediation';

interface HeaderProps {
  activeWorkspace: MainWorkspace;
  setActiveWorkspace: (ws: MainWorkspace) => void;
  onOpenUpload: () => void;
  onToggleCopilot: () => void;
  onGoToLanding?: () => void;
  systemStatus: string;
  hasOpenThreats: boolean;
  pendingPRsCount: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeWorkspace,
  setActiveWorkspace,
  onOpenUpload,
  onToggleCopilot,
  onGoToLanding,
  systemStatus,
  hasOpenThreats,
  pendingPRsCount,
}) => {
  return (
    <header className="border-b border-neutral-900 bg-black/95 backdrop-blur sticky top-0 z-40 transition-colors">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="h-14 flex items-center justify-between gap-4">
          {/* Brand */}
          <div
            onClick={onGoToLanding}
            className="flex items-center space-x-3 shrink-0 cursor-pointer group"
            title="Return to Landing Page & Story"
          >
            <div className="w-8 h-8 rounded-lg bg-neutral-900 border border-neutral-800 flex items-center justify-center text-white group-hover:border-neutral-700 transition-colors">
              <Shield className="w-4 h-4 text-white" />
            </div>
            <div className="flex items-center space-x-2">
              <span className="font-bold text-sm tracking-tight text-white group-hover:text-neutral-200 transition-colors">GuardianOS</span>
              <span className="px-1.5 py-0.2 rounded text-[10px] font-mono font-medium bg-neutral-900 text-neutral-400 border border-neutral-800">
                v2.0
              </span>
            </div>
          </div>

          {/* 3 Core Minimalist Workspaces */}
          <nav className="flex items-center space-x-1 bg-neutral-950 p-1 rounded-lg border border-neutral-900">
            <button
              onClick={() => setActiveWorkspace('threats')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs transition-all ${
                activeWorkspace === 'threats'
                  ? 'bg-neutral-100 text-black font-semibold shadow-sm'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              <Flame className="w-3.5 h-3.5" />
              <span>Threat Center</span>
              {hasOpenThreats && (
                <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse"></span>
              )}
            </button>

            <button
              onClick={() => setActiveWorkspace('supply-chain')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs transition-all ${
                activeWorkspace === 'supply-chain'
                  ? 'bg-neutral-100 text-black font-semibold shadow-sm'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Supply Chain</span>
            </button>

            <button
              onClick={() => setActiveWorkspace('remediation')}
              className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs transition-all ${
                activeWorkspace === 'remediation'
                  ? 'bg-neutral-100 text-black font-semibold shadow-sm'
                  : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-900'
              }`}
            >
              <GitPullRequest className="w-3.5 h-3.5" />
              <span>Remediation</span>
              {pendingPRsCount > 0 && (
                <span className="px-1 py-0.1 rounded text-[9px] font-mono bg-neutral-800 text-neutral-300">
                  {pendingPRsCount}
                </span>
              )}
            </button>
          </nav>

          {/* Right Actions: Status, Copilot & Ingest */}
          <div className="flex items-center space-x-2.5 shrink-0">
            {/* System Status */}
            <div className="hidden md:flex items-center space-x-1.5 text-[10px] font-mono px-2 py-1 rounded bg-neutral-950 border border-neutral-900 text-neutral-400">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500"></span>
              <span>{systemStatus}</span>
            </div>

            {/* AI Copilot Drawer Trigger */}
            <button
              onClick={onToggleCopilot}
              className="flex items-center space-x-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium bg-neutral-900 hover:bg-neutral-800 text-neutral-200 border border-neutral-800 transition-all"
              title="Open AI Security Copilot (Cmd+K)"
            >
              <Sparkles className="w-3.5 h-3.5 text-neutral-300" />
              <span>Copilot</span>
              <kbd className="hidden sm:inline-block px-1 py-0.5 rounded text-[9px] font-mono bg-black text-neutral-400 border border-neutral-850">
                ⌘K
              </kbd>
            </button>

            {/* Ingest SBOM */}
            <button
              onClick={onOpenUpload}
              className="flex items-center space-x-1 px-3 py-1.5 rounded-md text-xs font-medium bg-white hover:bg-neutral-200 text-black transition-all"
            >
              <Upload className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Ingest SBOM</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
