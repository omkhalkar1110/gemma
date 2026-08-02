import React from 'react';
import { LayoutDashboard, MessageSquareText, Activity, ShieldAlert, ShieldCheck, Bot } from 'lucide-react';
import { DashboardKPIs } from '../types';

interface HeaderProps {
  activeView: 'command_center' | 'employee_workspace' | 'soc_agent_mcp';
  setActiveView: (view: 'command_center' | 'employee_workspace' | 'soc_agent_mcp') => void;
  wsConnected: boolean;
  kpis: DashboardKPIs | null;
}

export const Header: React.FC<HeaderProps> = ({
  activeView,
  setActiveView,
  wsConnected,
  kpis
}) => {
  return (
    <header className="sticky top-0 z-40 bg-neutral-900/40 backdrop-blur-md border-b border-neutral-800 text-neutral-100 px-4 lg:px-8 py-3.5">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Brand & Status */}
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 bg-[#00ff9d] rounded flex items-center justify-center shadow-[0_0_15px_rgba(0,255,157,0.4)] shrink-0">
            <div className="w-4 h-4 border-2 border-black rotate-45"></div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-tight uppercase text-white font-sans">
                Aegis Gateway
              </h1>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-800 text-[#00ff9d] border border-neutral-700 uppercase font-semibold">
                v1.0.4-stable
              </span>
            </div>
            <p className="text-[10px] text-neutral-400 uppercase tracking-widest leading-none flex items-center gap-2 mt-1 font-mono">
              <span>Local DLP Proxy</span>
              <span className="text-neutral-600">•</span>
              <span>aegis.db</span>
              <span className="text-neutral-600">•</span>
              <span className="flex items-center gap-1">
                <span className={`w-2 h-2 rounded-full ${wsConnected || kpis !== null ? 'bg-[#00ff9d] animate-pulse shadow-[0_0_8px_#00ff9d]' : 'bg-amber-400 animate-ping'}`}></span>
                <span className={wsConnected || kpis !== null ? 'text-[#00ff9d] font-bold' : 'text-amber-400'}>
                  {wsConnected ? 'SCANNER ACTIVE (WS)' : kpis !== null ? 'SCANNER ACTIVE' : 'CONNECTING...'}
                </span>
              </span>
            </p>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="flex items-center bg-neutral-900/80 p-1 rounded-xl border border-neutral-800">
          <button
            onClick={() => setActiveView('command_center')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              activeView === 'command_center'
                ? 'bg-neutral-800 text-[#00ff9d] border border-neutral-700 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40'
            }`}
          >
            <LayoutDashboard className="w-3.5 h-3.5" />
            <span>Command Center</span>
            {kpis && kpis.threats_blocked > 0 && (
              <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-red-500/20 text-red-400 font-mono font-bold border border-red-500/30">
                {kpis.threats_blocked}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveView('employee_workspace')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              activeView === 'employee_workspace'
                ? 'bg-neutral-800 text-[#00ff9d] border border-neutral-700 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40'
            }`}
          >
            <MessageSquareText className="w-3.5 h-3.5" />
            <span>Employee Workspace</span>
            <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-[#00ff9d]/10 text-[#00ff9d] font-mono border border-[#00ff9d]/20">
              PROMPT
            </span>
          </button>

          <button
            onClick={() => setActiveView('soc_agent_mcp')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold uppercase tracking-wider transition-all duration-200 ${
              activeView === 'soc_agent_mcp'
                ? 'bg-neutral-800 text-[#00ff9d] border border-neutral-700 shadow-sm'
                : 'text-neutral-400 hover:text-neutral-200 hover:bg-neutral-800/40'
            }`}
          >
            <Bot className="w-3.5 h-3.5" />
            <span>SOC Agent (MCP)</span>
            <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-blue-500/20 text-blue-400 font-mono font-bold border border-blue-500/30">
              ELASTIC
            </span>
          </button>
        </div>

        {/* Quick KPI ticker */}
        <div className="hidden lg:flex items-center gap-4 text-xs font-mono bg-neutral-900/50 border border-neutral-800 px-3.5 py-2 rounded-xl">
          <div className="flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-neutral-400" />
            <span className="text-neutral-500 uppercase text-[10px] font-sans font-semibold">Total:</span>
            <span className="text-white font-bold">{kpis?.total_intercepted ?? '--'}</span>
          </div>
          <div className="h-3 w-px bg-neutral-800"></div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
            <span className="text-neutral-500 uppercase text-[10px] font-sans font-semibold">Blocked:</span>
            <span className="text-red-400 font-bold">{kpis?.threats_blocked ?? '--'}</span>
          </div>
          <div className="h-3 w-px bg-neutral-800"></div>
          <div className="flex items-center gap-2">
            <ShieldCheck className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-neutral-500 uppercase text-[10px] font-sans font-semibold">Redacted:</span>
            <span className="text-amber-400 font-bold">{kpis?.pii_redacted ?? '--'}</span>
          </div>
        </div>
      </div>
    </header>
  );
};

