import React, { useState } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ShieldCheck,
  ShieldAlert,
  Activity,
  Search,
  Eye,
  ToggleLeft,
  ToggleRight,
  TrendingUp,
  Lock,
  Zap,
  Info
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';
import { ActivityLogItem, DashboardKPIs, PolicySetting } from '../types';
import { LogDetailModal } from './LogDetailModal';

interface CommandCenterViewProps {
  logs: ActivityLogItem[];
  kpis: DashboardKPIs | null;
  policies: PolicySetting[];
  kpiPulsing: boolean;
  onTogglePolicy: (key: string, enabled: boolean) => void;
}

export const CommandCenterView: React.FC<CommandCenterViewProps> = ({
  logs,
  kpis,
  policies,
  kpiPulsing,
  onTogglePolicy
}) => {
  const [selectedLog, setSelectedLog] = useState<ActivityLogItem | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [actionFilter, setActionFilter] = useState<'ALL' | 'BLOCKED' | 'REDACTED' | 'ALLOWED'>('ALL');

  // Filter logs
  const filteredLogs = logs.filter((log) => {
    const matchesAction = actionFilter === 'ALL' || log.action === actionFilter;
    const matchesSearch =
      log.employee_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.original_prompt.toLowerCase().includes(searchQuery.toLowerCase()) ||
      log.department.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesAction && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* 1. 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1 */}
        <motion.div
          animate={kpiPulsing ? { scale: [1, 1.02, 1] } : {}}
          transition={{ duration: 0.4 }}
          className={`relative p-4 rounded-xl bg-neutral-900/50 border transition-all duration-300 ${
            kpiPulsing ? 'border-[#00ff9d] ring-1 ring-[#00ff9d]/30' : 'border-neutral-800'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-neutral-500 uppercase font-semibold">
              Total Scanned
            </span>
            <div className="p-1.5 rounded bg-neutral-800 text-neutral-400">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {kpis?.total_intercepted ?? logs.length}
          </div>
          <div className="text-[10px] text-neutral-400 mt-1 uppercase font-mono flex items-center gap-1">
            <span className="text-[#00ff9d] font-bold">100% Monitored</span>
            <span className="text-neutral-600">•</span>
            <span>Local Proxy</span>
          </div>
        </motion.div>

        {/* KPI 2 */}
        <motion.div
          animate={kpiPulsing ? { scale: [1, 1.02, 1] } : {}}
          transition={{ duration: 0.4, delay: 0.1 }}
          className={`relative p-4 rounded-xl bg-neutral-900/50 border transition-all duration-300 ${
            kpiPulsing ? 'border-red-500 ring-1 ring-red-500/30' : 'border-neutral-800'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-red-500 uppercase font-semibold">
              Violations Blocked
            </span>
            <div className="p-1.5 rounded bg-red-500/10 text-red-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-red-400">
            {kpis?.threats_blocked ?? logs.filter((l) => l.action === 'BLOCKED').length}
          </div>
          <div className="text-[10px] text-red-400 mt-1 uppercase font-bold tracking-wider font-mono">
            High Risk Intercepted
          </div>
        </motion.div>

        {/* KPI 3 */}
        <motion.div
          animate={kpiPulsing ? { scale: [1, 1.02, 1] } : {}}
          transition={{ duration: 0.4, delay: 0.2 }}
          className={`relative p-4 rounded-xl bg-neutral-900/50 border transition-all duration-300 ${
            kpiPulsing ? 'border-amber-500 ring-1 ring-amber-500/30' : 'border-neutral-800'
          }`}
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-amber-500 uppercase font-semibold">
              Data Masked
            </span>
            <div className="p-1.5 rounded bg-amber-500/10 text-amber-400">
              <Lock className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {kpis?.pii_redacted ?? logs.filter((l) => l.action === 'REDACTED').length}
          </div>
          <div className="text-[10px] text-neutral-400 mt-1 uppercase font-mono">
            Token Masked Entities
          </div>
        </motion.div>

        {/* KPI 4 */}
        <motion.div
          animate={kpiPulsing ? { scale: [1, 1.02, 1] } : {}}
          transition={{ duration: 0.4, delay: 0.3 }}
          className="relative p-4 rounded-xl bg-neutral-900/50 border border-neutral-800"
        >
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-[#00ff9d] uppercase font-semibold">
              Avg Risk Score
            </span>
            <div className="p-1.5 rounded bg-[#00ff9d]/10 text-[#00ff9d]">
              <Zap className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-[#00ff9d]">
            {kpis?.average_risk_score ?? 38.5} <span className="text-xs text-neutral-500">/ 100</span>
          </div>
          <div className="text-[10px] text-neutral-400 mt-1 uppercase font-mono">
            Local Node Stable
          </div>
        </motion.div>
      </div>

      {/* 2. Charts & Policy Switches Row */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Trend Area Chart (Spans 8 Columns) */}
        <div className="lg:col-span-8 bg-neutral-900/50 border border-neutral-800 p-5 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-[#00ff9d]" />
                Interception Feed Trend
              </h3>
              <p className="text-[10px] text-neutral-400 font-mono">Real-time prompt traffic vs DLP enforcement</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-neutral-800 text-neutral-400 uppercase">
              REFRESH RATE: 1S
            </span>
          </div>

          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={kpis?.threat_trend || []}>
                <defs>
                  <linearGradient id="colorIntercepted" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00ff9d" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#00ff9d" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#262626" />
                <XAxis dataKey="time" stroke="#737373" fontSize={10} fontFamily="monospace" />
                <YAxis stroke="#737373" fontSize={10} fontFamily="monospace" />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0a0a0a', borderColor: '#262626', borderRadius: '8px' }}
                  labelStyle={{ color: '#00ff9d', fontWeight: 'bold', fontFamily: 'monospace' }}
                />
                <Area
                  type="monotone"
                  dataKey="intercepted"
                  name="Scanned Prompts"
                  stroke="#00ff9d"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorIntercepted)"
                />
                <Area
                  type="monotone"
                  dataKey="blocked"
                  name="Blocked Threats"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorBlocked)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Real-time Security Policies (Spans 4 Columns) */}
        <div className="lg:col-span-4 bg-neutral-900/50 border border-neutral-800 p-5 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 mb-4 border-b border-neutral-800">
              <h3 className="text-sm font-bold uppercase tracking-wider text-white">
                Security Policies
              </h3>
              <span className="text-[10px] font-mono text-[#00ff9d] bg-[#00ff9d]/10 px-2 py-0.5 rounded border border-[#00ff9d]/20 uppercase">
                ACTIVE
              </span>
            </div>

            <div className="space-y-3">
              {policies.map((pol) => (
                <div
                  key={pol.key}
                  className="flex items-center justify-between p-3 bg-neutral-800/50 rounded-lg border border-neutral-700/50 transition hover:border-neutral-600"
                >
                  <div className="pr-2">
                    <span className="text-xs font-semibold text-neutral-200 block">{pol.label}</span>
                    <span className="text-[10px] text-neutral-400 leading-tight block mt-0.5">
                      {pol.description}
                    </span>
                  </div>

                  <button
                    onClick={() => onTogglePolicy(pol.key, !pol.enabled)}
                    className="p-1 transition focus:outline-none shrink-0"
                  >
                    {pol.enabled ? (
                      <ToggleRight className="w-7 h-7 text-[#00ff9d]" />
                    ) : (
                      <ToggleLeft className="w-7 h-7 text-neutral-600" />
                    )}
                  </button>
                </div>
              ))}
            </div>
          </div>

          <p className="text-[10px] text-neutral-500 mt-4 font-mono flex items-center gap-1">
            <Info className="w-3.5 h-3.5 text-[#00ff9d]" />
            Policies execute locally in-memory & persist to aegis.db.
          </p>
        </div>
      </div>

      {/* 3. Live Security Feed Table */}
      <div className="bg-neutral-900/50 border border-neutral-800 rounded-xl flex flex-col overflow-hidden">
        {/* Table Header Controls */}
        <div className="p-4 border-b border-neutral-800 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4 bg-neutral-900/80">
          <div>
            <h2 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-[#00ff9d]" />
              Live Security Feed
            </h2>
            <p className="text-[10px] text-neutral-500 font-mono">Real-time prompt logs in aegis.db</p>
          </div>

          <div className="flex flex-col sm:flex-row items-center gap-3">
            {/* Search Input */}
            <div className="relative w-full sm:w-60">
              <Search className="w-3.5 h-3.5 text-neutral-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search prompt or user..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-8 pr-3 py-1.5 bg-neutral-950 border border-neutral-800 rounded text-xs text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-[#00ff9d] font-mono"
              />
            </div>

            {/* Filter Pills */}
            <div className="flex items-center bg-neutral-950 p-1 rounded border border-neutral-800 w-full sm:w-auto font-mono text-xs">
              {(['ALL', 'BLOCKED', 'REDACTED', 'ALLOWED'] as const).map((action) => (
                <button
                  key={action}
                  onClick={() => setActionFilter(action)}
                  className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase transition ${
                    actionFilter === action
                      ? 'bg-neutral-800 text-[#00ff9d] border border-neutral-700'
                      : 'text-neutral-500 hover:text-neutral-300'
                  }`}
                >
                  {action}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Table Content */}
        <div className="overflow-x-auto font-mono text-xs">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-neutral-950/50 border-b border-neutral-800 text-neutral-500 uppercase font-bold text-[10px]">
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Origin</th>
                <th className="py-3 px-4">Detection Signature</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4 text-right">Action</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-neutral-800/80">
              <AnimatePresence>
                {filteredLogs.map((log) => (
                  <motion.tr
                    key={log.id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0 }}
                    transition={{ duration: 0.15 }}
                    className={`hover:bg-neutral-800/40 transition-colors ${
                      log.action === 'BLOCKED' ? 'bg-red-950/10' : ''
                    }`}
                  >
                    {/* Time */}
                    <td className="py-3 px-4 text-neutral-500 whitespace-nowrap">
                      {new Date(log.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </td>

                    {/* Origin */}
                    <td className="py-3 px-4">
                      <div className="text-neutral-300 font-semibold">{log.employee_name}</div>
                      <div className="text-[10px] text-neutral-500 uppercase">{log.department}</div>
                    </td>

                    {/* Detection Signature */}
                    <td className="py-3 px-4 max-w-xs">
                      <div className="flex flex-wrap gap-1 mb-1">
                        {log.entities_found.length > 0 ? (
                          log.entities_found.map((e, idx) => (
                            <span
                              key={idx}
                              className={`px-1.5 py-0.5 rounded text-[10px] uppercase font-bold border ${
                                e.type.includes('CARD') || e.type.includes('SSN') || e.type.includes('SECRET')
                                  ? 'bg-red-500/20 text-red-400 border-red-500/30'
                                  : e.type.includes('EMAIL') || e.type.includes('PHONE')
                                  ? 'bg-amber-500/20 text-amber-400 border-amber-500/30'
                                  : 'bg-blue-500/20 text-blue-400 border-blue-500/30'
                              }`}
                            >
                              {e.type}
                            </span>
                          ))
                        ) : (
                          <span className="bg-neutral-800 text-neutral-400 px-1.5 py-0.5 rounded text-[10px]">
                            CLEAN_REST
                          </span>
                        )}
                      </div>
                      <div className="text-[11px] text-neutral-400 truncate max-w-sm">
                        {log.original_prompt}
                      </div>
                    </td>

                    {/* Risk Gauge */}
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`font-bold ${
                        log.risk_score >= 70 ? 'text-red-400' : log.risk_score >= 30 ? 'text-amber-400' : 'text-[#00ff9d]'
                      }`}>
                        {log.risk_score}/100
                      </span>
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <span
                        className={`font-bold uppercase italic ${
                          log.action === 'BLOCKED'
                            ? 'text-red-500'
                            : log.action === 'REDACTED'
                            ? 'text-amber-500'
                            : 'text-[#00ff9d]'
                        }`}
                      >
                        {log.action}
                      </span>
                    </td>

                    {/* Inspect Button */}
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={() => setSelectedLog(log)}
                        className="p-1 rounded bg-neutral-800 text-neutral-400 hover:text-white hover:bg-neutral-700 transition"
                      >
                        <Eye className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </motion.tr>
                ))}
              </AnimatePresence>
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspect Detail Modal */}
      <LogDetailModal item={selectedLog} onClose={() => setSelectedLog(null)} />
    </div>
  );
};

