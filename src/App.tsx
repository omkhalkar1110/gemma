import React, { useState } from 'react';
import { Header } from './components/Header';
import { CommandCenterView } from './components/CommandCenterView';
import { EmployeeWorkspaceView } from './components/EmployeeWorkspaceView';
import { SocAgentMcpView } from './components/SocAgentMcpView';
import { SocChatbotWidget } from './components/SocChatbotWidget';
import { useRealtimeFeed } from './hooks/useRealtimeFeed';
import { ShieldCheck } from 'lucide-react';

export default function App() {
  const [activeView, setActiveView] = useState<'command_center' | 'employee_workspace' | 'soc_agent_mcp'>('command_center');

  const {
    logs,
    kpis,
    policies,
    loading,
    wsConnected,
    kpiPulsing,
    togglePolicy,
    refreshData
  } = useRealtimeFeed();

  if (loading) {
    return (
      <div className="min-h-screen bg-[#050505] text-neutral-100 flex items-center justify-center p-6 font-mono">
        <div className="flex flex-col items-center gap-4 text-center">
          <div className="relative flex items-center justify-center w-12 h-12 rounded bg-neutral-900 border border-[#00ff9d]/30 text-[#00ff9d] animate-pulse">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-white">Initializing Aegis Gateway</h2>
            <p className="text-xs text-neutral-500 mt-1">Booting Security Engine & SQLite aegis.db...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050505] text-neutral-100 font-sans selection:bg-[#00ff9d] selection:text-black flex flex-col relative">
      {/* Header Bar */}
      <Header
        activeView={activeView}
        setActiveView={setActiveView}
        wsConnected={wsConnected}
        kpis={kpis}
      />

      {/* Main Views Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 lg:p-6 space-y-6">
        {activeView === 'command_center' ? (
          <CommandCenterView
            logs={logs}
            kpis={kpis}
            policies={policies}
            kpiPulsing={kpiPulsing}
            onTogglePolicy={togglePolicy}
          />
        ) : activeView === 'employee_workspace' ? (
          <EmployeeWorkspaceView
            onNewActivityCreated={() => {
              refreshData();
            }}
          />
        ) : (
          <SocAgentMcpView />
        )}
      </main>

      {/* Floating SOC Chatbot Widget (Bottom Right Corner) */}
      <SocChatbotWidget />

      {/* Footer */}
      <footer className="border-t border-neutral-900 bg-neutral-950 py-3 px-6 text-center text-[10px] text-neutral-500 mt-8 font-mono">
        <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AEGIS GATEWAY DLP PROXY • LOCAL SECURITY HEURISTICS ENGINE</span>
          <span className="text-neutral-400">
            AEGIS.DB SQLITE PERSISTENT STORE • ZERO EXTERNAL LLM APIS
          </span>
        </div>
      </footer>
    </div>
  );
}

