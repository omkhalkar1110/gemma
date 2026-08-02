import React from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { downloadSanitizedFile } from '../utils/fileDownloader';
import { X, ShieldAlert, ShieldCheck, User, Calendar, FileText, Cpu, AlertCircle, Copy, Check, Download } from 'lucide-react';
import { ActivityLogItem } from '../types';

interface LogDetailModalProps {
  item: ActivityLogItem | null;
  onClose: () => void;
}

export const LogDetailModal: React.FC<LogDetailModalProps> = ({ item, onClose }) => {
  const [copied, setCopied] = React.useState(false);

  if (!item) return null;

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm font-sans">
        <motion.div
          initial={{ opacity: 0, scale: 0.95, y: 10 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 10 }}
          className="relative w-full max-w-3xl bg-neutral-900 border border-neutral-800 rounded-xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh]"
        >
          {/* Header */}
          <div className="flex items-center justify-between p-5 border-b border-neutral-800 bg-neutral-950">
            <div className="flex items-center gap-3">
              <div
                className={`p-2 rounded border ${
                  item.action === 'BLOCKED'
                    ? 'bg-red-500/10 text-red-400 border-red-500/30'
                    : item.action === 'REDACTED'
                    ? 'bg-amber-500/10 text-amber-300 border-amber-500/30'
                    : 'bg-[#00ff9d]/10 text-[#00ff9d] border-[#00ff9d]/30'
                }`}
              >
                {item.action === 'BLOCKED' ? (
                  <ShieldAlert className="w-5 h-5" />
                ) : (
                  <ShieldCheck className="w-5 h-5" />
                )}
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold uppercase tracking-wider text-white">Log Entry #{item.id}</h3>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${
                      item.action === 'BLOCKED'
                        ? 'bg-red-500/20 text-red-400 border-red-500/40'
                        : item.action === 'REDACTED'
                        ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                        : 'bg-[#00ff9d]/10 text-[#00ff9d] border-[#00ff9d]/30'
                    }`}
                  >
                    {item.action}
                  </span>
                </div>
                <p className="text-[10px] text-neutral-400 font-mono mt-0.5">
                  Full inspection log & entity extraction telemetry
                </p>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-1.5 rounded text-neutral-400 hover:text-white hover:bg-neutral-800 transition"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Modal Body */}
          <div className="p-6 overflow-y-auto space-y-6">
            {/* Metadata Bar */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-neutral-950 p-4 rounded-lg border border-neutral-800 font-mono">
              <div className="flex items-center gap-2">
                <User className="w-3.5 h-3.5 text-[#00ff9d]" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-neutral-500 block">Employee</span>
                  <span className="text-xs text-neutral-200">{item.employee_name}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <Calendar className="w-3.5 h-3.5 text-blue-400" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-neutral-500 block">Timestamp</span>
                  <span className="text-xs text-neutral-200">{new Date(item.timestamp).toLocaleTimeString()}</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <AlertCircle className="w-3.5 h-3.5 text-amber-400" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-neutral-500 block">Risk Rating</span>
                  <span className="text-xs font-bold text-amber-300">{item.risk_score} / 100</span>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-[#00ff9d]" />
                <div>
                  <span className="text-[10px] uppercase font-bold text-neutral-500 block">Attachment</span>
                  <span className="text-xs text-neutral-200 truncate">{item.attachment_name || 'None'}</span>
                </div>
              </div>

              {/* Download Button for Sanitized PDF / Document */}
              <div className="flex items-center justify-between col-span-2 sm:col-span-4 bg-neutral-900/80 p-3 rounded-lg border border-[#00ff9d]/30 mt-1">
                <div className="flex items-center gap-2">
                  <FileText className="w-4 h-4 text-[#00ff9d]" />
                  <div>
                    <span className="text-[10px] uppercase font-bold text-neutral-400 block">Sanitized Document File</span>
                    <span className="text-xs font-bold text-white">{item.attachment_name || 'Sanitized_Document.pdf'}</span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={() => downloadSanitizedFile(item.attachment_name || 'sanitized_document.pdf', item.processed_prompt)}
                  className="px-3.5 py-1.5 bg-[#00ff9d] hover:bg-[#00e68d] text-black font-bold text-xs rounded font-mono uppercase tracking-wider flex items-center gap-2 shadow-[0_0_15px_rgba(0,255,157,0.25)] cursor-pointer transition-colors"
                  title="Download updated sanitized file"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Updated PDF / File</span>
                </button>
              </div>
            </div>

            {/* Detected Entities Breakdown */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-400 font-mono mb-2">
                Extracted Entities ({item.entities_found.length})
              </h4>
              <div className="bg-neutral-950 p-3 rounded-lg border border-neutral-800 space-y-2 font-mono">
                {item.entities_found.length > 0 ? (
                  item.entities_found.map((ent, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-2 rounded bg-neutral-900 border border-neutral-800 text-xs"
                    >
                      <div className="flex items-center gap-2.5">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-neutral-800 text-[#00ff9d] border border-neutral-700">
                          {ent.type}
                        </span>
                        <span className="text-white font-medium">{ent.value}</span>
                      </div>
                      <span className="text-[10px] text-neutral-500">
                        Span: [{ent.span[0]}, {ent.span[1]}]
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-neutral-500 italic p-1">No sensitive entities matched.</p>
                )}
              </div>
            </div>

            {/* Side-by-Side Prompt Comparison */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <div className="flex items-center justify-between mb-1.5 font-mono">
                  <h4 className="text-xs font-bold uppercase tracking-wider text-neutral-400">
                    Original Prompt
                  </h4>
                  <button
                    onClick={() => handleCopy(item.original_prompt)}
                    className="text-[10px] text-neutral-400 hover:text-white flex items-center gap-1"
                  >
                    {copied ? <Check className="w-3 h-3 text-[#00ff9d]" /> : <Copy className="w-3 h-3" />}
                    <span>Copy</span>
                  </button>
                </div>
                <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 font-mono text-xs text-neutral-300 leading-relaxed min-h-[100px] whitespace-pre-wrap">
                  {item.original_prompt}
                </div>
              </div>

              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-[#00ff9d] font-mono mb-1.5">
                  Sanitized Outbound Prompt
                </h4>
                <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 font-mono text-xs text-[#00ff9d] leading-relaxed min-h-[100px] whitespace-pre-wrap">
                  {item.processed_prompt}
                </div>
              </div>
            </div>

            {/* Sanitized LLM Output */}
            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#00ff9d] font-mono mb-1.5 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-[#00ff9d]" />
                <span>Sanitized LLM Output</span>
              </h4>
              <div className="p-3 rounded-lg bg-neutral-950 border border-neutral-800 text-xs text-neutral-200 leading-relaxed font-sans whitespace-pre-wrap">
                {item.model_response}
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
};

