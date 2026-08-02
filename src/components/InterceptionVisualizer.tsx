import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { Shield, ScanSearch, Lock, CheckCircle2, AlertTriangle, Cpu } from 'lucide-react';
import { ActivityLogItem, InterceptionStep } from '../types';

interface InterceptionVisualizerProps {
  activeStep: number; // 1 to 4
  steps: InterceptionStep[];
  currentLogItem?: ActivityLogItem | null;
  isProcessing: boolean;
}

export const InterceptionVisualizer: React.FC<InterceptionVisualizerProps> = ({
  activeStep,
  steps,
  currentLogItem,
  isProcessing
}) => {
  const getIconForStep = (stepId: number, status: string) => {
    switch (stepId) {
      case 1:
        return <Shield className="w-4 h-4 text-[#00ff9d]" />;
      case 2:
        return <ScanSearch className="w-4 h-4 text-blue-400" />;
      case 3:
        return <Lock className="w-4 h-4 text-amber-400" />;
      case 4:
        return status === 'blocked' ? (
          <AlertTriangle className="w-4 h-4 text-red-400" />
        ) : (
          <CheckCircle2 className="w-4 h-4 text-[#00ff9d]" />
        );
      default:
        return <Cpu className="w-4 h-4 text-[#00ff9d]" />;
    }
  };

  return (
    <div className="bg-neutral-900/50 rounded-xl border border-neutral-800 p-5 shadow-xl overflow-hidden">
      <div className="flex items-center justify-between pb-4 mb-4 border-b border-neutral-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded bg-neutral-800 text-[#00ff9d] border border-neutral-700">
            <Cpu className="w-4 h-4 animate-pulse" />
          </div>
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-white">
              DLP Interception Pipeline
            </h3>
            <p className="text-[10px] text-neutral-400 font-mono">
              Socket proxy analyzing prompts before outbound LLM transmission
            </p>
          </div>
        </div>

        {isProcessing && (
          <div className="flex items-center gap-2 px-3 py-1 rounded bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 text-xs font-mono font-bold animate-pulse">
            <span className="w-2 h-2 rounded-full bg-[#00ff9d] animate-ping"></span>
            <span>INTERCEPTING PROMPT...</span>
          </div>
        )}
      </div>

      {/* 4 Steps Flow */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        {steps.map((step) => {
          const isActive = activeStep === step.id;
          const isCompleted = activeStep > step.id || step.status === 'completed';
          const isBlocked = step.status === 'blocked';

          return (
            <motion.div
              key={step.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3, delay: step.id * 0.08 }}
              className={`relative p-3.5 rounded-lg border transition-all duration-300 ${
                isBlocked
                  ? 'bg-red-950/20 border-red-500/50'
                  : isActive
                  ? 'bg-neutral-800/80 border-[#00ff9d]/60 shadow-[0_0_10px_rgba(0,255,157,0.1)]'
                  : isCompleted
                  ? 'bg-neutral-800/40 border-neutral-700 text-neutral-200'
                  : 'bg-neutral-900/30 border-neutral-800/80 opacity-50'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <div
                    className={`p-1.5 rounded ${
                      isBlocked
                        ? 'bg-red-500/20 text-red-400'
                        : isActive
                        ? 'bg-[#00ff9d]/20 text-[#00ff9d]'
                        : isCompleted
                        ? 'bg-[#00ff9d]/10 text-[#00ff9d]'
                        : 'bg-neutral-800 text-neutral-500'
                    }`}
                  >
                    {getIconForStep(step.id, step.status)}
                  </div>
                  <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-neutral-400">
                    STEP 0{step.id}
                  </span>
                </div>

                {isCompleted && !isBlocked && (
                  <CheckCircle2 className="w-3.5 h-3.5 text-[#00ff9d]" />
                )}
                {isBlocked && <AlertTriangle className="w-3.5 h-3.5 text-red-400" />}
              </div>

              <h4 className="text-xs font-bold text-white mb-1 uppercase tracking-tight">{step.title}</h4>
              <p className="text-[10px] text-neutral-400 leading-snug font-sans">{step.description}</p>

              {/* Detail snippet when active or complete */}
              {step.detail && (
                <div className="mt-2 pt-2 border-t border-neutral-800 text-[10px] font-mono text-[#00ff9d] truncate bg-neutral-950 px-2 py-1 rounded">
                  {step.detail}
                </div>
              )}
            </motion.div>
          );
        })}
      </div>

      {/* Live Entity Detection Visual Feedback */}
      <AnimatePresence>
        {currentLogItem && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-4 pt-4 border-t border-neutral-800"
          >
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3 bg-neutral-950 p-3.5 rounded-lg border border-neutral-800 font-mono">
              <div>
                <span className="text-xs font-bold text-neutral-300 uppercase tracking-wider flex items-center gap-2">
                  <span>Detection Results:</span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase border ${
                      currentLogItem.action === 'BLOCKED'
                        ? 'bg-red-500/20 text-red-400 border-red-500/30'
                        : currentLogItem.action === 'REDACTED'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                        : 'bg-[#00ff9d]/10 text-[#00ff9d] border-[#00ff9d]/30'
                    }`}
                  >
                    {currentLogItem.action} (Risk Score: {currentLogItem.risk_score}/100)
                  </span>
                </span>

                <div className="flex flex-wrap gap-1.5 mt-2">
                  {currentLogItem.entities_found.length > 0 ? (
                    currentLogItem.entities_found.map((e, idx) => (
                      <span
                        key={idx}
                        className="px-2 py-1 rounded text-[10px] bg-neutral-800 text-[#00ff9d] border border-neutral-700 flex items-center gap-1"
                      >
                        <span className="w-1.5 h-1.5 rounded-full bg-[#00ff9d]"></span>
                        <span>{e.type}:</span>
                        <span className="text-white font-bold">{e.value}</span>
                      </span>
                    ))
                  ) : (
                    <span className="text-xs text-neutral-500 italic">No sensitive entities detected in prompt.</span>
                  )}
                </div>
              </div>

              <div className="text-right">
                <span className="text-[10px] text-neutral-500 uppercase block">Sanitized Forward Preview</span>
                <p className="text-xs text-[#00ff9d] max-w-sm truncate bg-neutral-900 px-2 py-1 rounded border border-neutral-800 mt-1">
                  {currentLogItem.processed_prompt}
                </p>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

