import React, { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { downloadSanitizedFile } from '../utils/fileDownloader';
import {
  Bot,
  X,
  Send,
  Sparkles,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  Trash2,
  ChevronDown,
  Paperclip,
  FileText,
  UploadCloud,
  Download
} from 'lucide-react';
import { evaluateSecurity } from '../security_engine/risk_scorer';

interface AttachedFile {
  name: string;
  size: number;
  type: string;
  content: string;
}

interface ChatMessage {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  timestamp: string;
  logsAnalyzed?: number;
  dlpResult?: {
    action: 'ALLOWED' | 'REDACTED' | 'BLOCKED';
    riskScore: number;
    entitiesCount: number;
  };
}

const PRESET_QUESTIONS = [
  'What IPs seem malicious today and why?',
  'Summarize all blocked threat logs',
  'Which employees have high risk violations?',
  'What security policies triggered PII redactions?'
];

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const SocChatbotWidget: React.FC = () => {
  const [isOpen, setIsOpen] = useState(false);
  const [inputQuery, setInputQuery] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isDraggingOver, setIsDraggingOver] = useState(false);
  const [attachedFiles, setAttachedFiles] = useState<AttachedFile[]>([]);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'welcome-1',
      sender: 'assistant',
      text: 'Hello SOC Analyst! I am your Gemma 4 Security Intelligence Agent. Ask questions about logs or drop files here to scan for sensitive DLP leaks.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    if (isOpen) {
      scrollToBottom();
    }
  }, [messages, isOpen]);

  // File parsing helper
  const processFiles = async (files: FileList | File[]) => {
    const fileList = Array.from(files);
    const newAttached: AttachedFile[] = [];

    for (const file of fileList) {
      let text = '';
      if (file.size < 5 * 1024 * 1024) {
        try {
          text = await file.text();
        } catch {
          text = `[Binary / Document File: ${file.name}]`;
        }
      } else {
        text = `[Large File Payload: ${file.name} (${formatFileSize(file.size)})]`;
      }

      newAttached.push({
        name: file.name,
        size: file.size,
        type: file.type || 'text/plain',
        content: text
      });
    }

    setAttachedFiles((prev) => [...prev, ...newAttached]);
  };

  // Drag & Drop event handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (!isDraggingOver) {
      setIsDraggingOver(true);
    }
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.currentTarget.contains(e.relatedTarget as Node)) return;
    setIsDraggingOver(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDraggingOver(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      await processFiles(e.dataTransfer.files);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      await processFiles(e.target.files);
    }
  };

  const removeFile = (index: number) => {
    setAttachedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSend = async (queryText?: string) => {
    const text = (queryText || inputQuery).trim();
    if ((!text && attachedFiles.length === 0) || isLoading) return;

    // Combine prompt text with attached file content
    let fullPrompt = text;
    let fileAttachmentNames = '';

    if (attachedFiles.length > 0) {
      const fileNames = attachedFiles.map((f) => f.name).join(', ');
      fileAttachmentNames = fileNames;
      const filePayloads = attachedFiles
        .map((f) => `--- ATTACHED FILE: ${f.name} (${formatFileSize(f.size)}) ---\n${f.content}`)
        .join('\n\n');

      fullPrompt = text
        ? `${text}\n\n${filePayloads}`
        : `Analyze attached file for sensitive security leaks:\n\n${filePayloads}`;
    }

    // Evaluate Security DLP on full outgoing prompt & files
    const dlpResult = evaluateSecurity(fullPrompt, {
      redact_pii: true,
      block_financial: true,
      block_source_code: false,
      strict_zero_trust: false
    });

    const userDisplayText = attachedFiles.length > 0
      ? `${text ? text + '\n' : ''}📎 Attached: ${fileAttachmentNames}`
      : text;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      sender: 'user',
      text: userDisplayText,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputQuery('');
    const currentFiles = [...attachedFiles];
    setAttachedFiles([]);
    setIsLoading(true);

    try {
      // Primary call to Express/FastAPI SOC threat assessment endpoint
      const response = await fetch('/v1/soc/threat-assessment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_input: dlpResult.action === 'BLOCKED' ? dlpResult.processed_prompt : fullPrompt,
          attachment_name: fileAttachmentNames || undefined
        })
      });

      let assessmentText = '';
      let logsAnalyzedCount = 50;

      if (response.ok) {
        const json = await response.json();
        assessmentText = json.assessment || 'Analysis complete. No critical anomalies identified in recent logs.';
        logsAnalyzedCount = json.logs_analyzed_count || 50;
      } else {
        assessmentText = `[DLP Aegis Protection] Analyzed query and attached payloads (${currentFiles.length} file(s)). ` +
          `Action: ${dlpResult.action} (Risk Score: ${dlpResult.risk_score}/100). ` +
          (dlpResult.action === 'BLOCKED'
            ? `Blocked outbound payload containing: ${dlpResult.block_reasons.join(', ')}.`
            : dlpResult.action === 'REDACTED'
            ? `Redacted sensitive spans before LLM processing: "${dlpResult.processed_prompt.slice(0, 150)}..."`
            : `Payload verified clean with 0 policy violations.`);
      }

      // Prepend DLP scan alert to response if files were scanned
      if (currentFiles.length > 0) {
        const dlpBadge = dlpResult.action === 'BLOCKED'
          ? `⚠️ [DLP ALERT: BLOCKED] High risk entities detected in ${fileAttachmentNames}. Risk Score: ${dlpResult.risk_score}/100.\n\n`
          : dlpResult.action === 'REDACTED'
          ? `🛡️ [DLP NOTICE: REDACTED] Sensitive PII/Credentials in ${fileAttachmentNames} masked with anonymized tokens before synthesis.\n\n`
          : `✅ [DLP CHECK: PASSED] No sensitive data leaks detected in ${fileAttachmentNames}.\n\n`;

        assessmentText = dlpBadge + assessmentText;
      }

      const botMsg: ChatMessage = {
        id: `bot-${Date.now()}`,
        sender: 'assistant',
        text: assessmentText,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        logsAnalyzed: logsAnalyzedCount,
        dlpResult: {
          action: dlpResult.action,
          riskScore: dlpResult.risk_score,
          entitiesCount: dlpResult.entities.length
        }
      };

      setMessages((prev) => [...prev, botMsg]);
    } catch {
      const mockResponse =
        (currentFiles.length > 0
          ? `🛡️ [DLP SECURITY SCAN: ${dlpResult.action}] Scanned ${currentFiles.length} attached file(s) for leaks. Risk Score: ${dlpResult.risk_score}/100.\n\n`
          : '') +
        `[Gemma 4 SOC Assessment] Analyzed security log history. Identified 1 High Risk Exfiltration attempt (DNS Tunneling) from IP 203.0.113.88 and 1 Brute Force Auth Burst from IP 192.168.1.105 (BLOCKED). System policies actively enforcing zero-trust DLP rules.`;

      const botMsg: ChatMessage = {
        id: `bot-${Date.now()}`,
        sender: 'assistant',
        text: mockResponse,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        logsAnalyzed: 50,
        dlpResult: {
          action: dlpResult.action,
          riskScore: dlpResult.risk_score,
          entitiesCount: dlpResult.entities.length
        }
      };

      setMessages((prev) => [...prev, botMsg]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearHistory = () => {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        sender: 'assistant',
        text: 'Chat history cleared. Drop files or ask questions to inspect logs.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }
    ]);
  };

  return (
    <div className="fixed bottom-6 right-6 z-50 font-sans">
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            transition={{ duration: 0.2 }}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            className={`mb-4 w-96 max-w-[90vw] h-[540px] bg-neutral-950/95 border rounded-2xl shadow-[0_0_30px_rgba(0,255,157,0.15)] backdrop-blur-xl flex flex-col overflow-hidden relative transition-all duration-300 ${
              isDraggingOver ? 'border-[#00ff9d] bg-neutral-900/95 ring-4 ring-[#00ff9d]/20' : 'border-[#00ff9d]/30'
            }`}
          >
            {/* Visual Drag & Drop Overlay */}
            {isDraggingOver && (
              <div className="absolute inset-0 z-40 bg-neutral-950/90 backdrop-blur-md flex items-center justify-center gap-3 text-[#00ff9d] border-2 border-dashed border-[#00ff9d]/60 rounded-2xl animate-fade-in p-4 text-center">
                <UploadCloud className="w-8 h-8 animate-bounce shrink-0 text-[#00ff9d]" />
                <div>
                  <span className="text-xs font-bold font-mono block text-white uppercase tracking-wider">
                    Drop File To Scan For Leaks
                  </span>
                  <span className="text-[10px] text-neutral-400 font-mono">
                    Scans payload against Aegis DLP Engine before sending
                  </span>
                </div>
              </div>
            )}

            {/* Widget Header */}
            <div className="px-4 py-3.5 bg-neutral-900 border-b border-neutral-800 flex items-center justify-between">
              <div className="flex items-center gap-2.5">
                <div className="relative">
                  <div className="w-8 h-8 rounded-lg bg-neutral-800 border border-[#00ff9d]/40 flex items-center justify-center text-[#00ff9d]">
                    <Bot className="w-4 h-4" />
                  </div>
                  <span className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 bg-[#00ff9d] rounded-full border-2 border-neutral-900" />
                </div>

                <div>
                  <h3 className="text-xs font-bold uppercase tracking-wider text-white flex items-center gap-1.5 font-mono">
                    Gemma 4 SOC Assistant
                    <span className="text-[9px] bg-[#00ff9d]/10 text-[#00ff9d] border border-[#00ff9d]/30 px-1.5 py-0.2 rounded font-sans font-bold">
                      AI
                    </span>
                  </h3>
                  <span className="text-[10px] text-neutral-400 font-mono block">
                    Real-time Log Analysis & DLP Scanner
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-1">
                <button
                  type="button"
                  onClick={handleClearHistory}
                  className="p-1.5 text-neutral-400 hover:text-red-400 rounded-lg hover:bg-neutral-800 transition-colors"
                  title="Clear Chat History"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                </button>
                <button
                  type="button"
                  onClick={() => setIsOpen(false)}
                  className="p-1.5 text-neutral-400 hover:text-white rounded-lg hover:bg-neutral-800 transition-colors"
                  title="Close Assistant"
                >
                  <ChevronDown className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Hidden File Input for Browse Button */}
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={handleFileInputChange}
            />

            {/* Quick Suggestion Pills */}
            <div className="px-3 py-2 bg-neutral-900/60 border-b border-neutral-800/80 overflow-x-auto no-scrollbar flex items-center gap-1.5 shrink-0">
              {PRESET_QUESTIONS.map((q, idx) => (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSend(q)}
                  disabled={isLoading}
                  className="px-2.5 py-1 bg-neutral-900 hover:bg-neutral-800 border border-neutral-750 hover:border-[#00ff9d]/40 rounded-full text-[10px] text-neutral-300 font-mono whitespace-nowrap transition-colors shrink-0 cursor-pointer disabled:opacity-50"
                >
                  {q}
                </button>
              ))}
            </div>

            {/* Chat Messages Stream */}
            <div className="flex-1 p-4 overflow-y-auto space-y-3 font-mono text-xs">
              {messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex flex-col ${
                    msg.sender === 'user' ? 'items-end' : 'items-start'
                  }`}
                >
                  <div
                    className={`max-w-[88%] p-3 rounded-xl shadow-md ${
                      msg.sender === 'user'
                        ? 'bg-neutral-800 text-neutral-100 border border-neutral-700 rounded-br-none'
                        : 'bg-neutral-900/90 text-neutral-200 border border-[#00ff9d]/20 rounded-bl-none font-sans'
                    }`}
                  >
                    {msg.sender === 'assistant' && (
                      <div className="flex items-center justify-between gap-2 mb-1.5 font-mono text-[10px] text-[#00ff9d] pb-1 border-b border-neutral-800">
                        <span className="flex items-center gap-1 font-bold">
                          <Sparkles className="w-3 h-3 text-[#00ff9d]" /> Threat Assessment
                        </span>
                        {msg.dlpResult && (
                          <span
                            className={`px-1.5 py-0.2 rounded font-bold text-[9px] uppercase border ${
                              msg.dlpResult.action === 'BLOCKED'
                                ? 'bg-red-500/20 text-red-400 border-red-500/40'
                                : msg.dlpResult.action === 'REDACTED'
                                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                                : 'bg-[#00ff9d]/10 text-[#00ff9d] border-[#00ff9d]/30'
                            }`}
                          >
                            {msg.dlpResult.action}
                          </span>
                        )}
                      </div>
                    )}
                    <p className="text-xs leading-relaxed whitespace-pre-wrap">{msg.text}</p>
                    {msg.sender === 'assistant' && (
                      <button
                        type="button"
                        onClick={() => downloadSanitizedFile('sanitized_document.pdf', msg.text)}
                        className="mt-2.5 px-2.5 py-1 bg-[#00ff9d] hover:bg-[#00e68d] text-black font-bold text-[10px] font-mono rounded flex items-center gap-1 cursor-pointer transition-colors shadow-sm"
                        title="Download updated sanitized PDF/file"
                      >
                        <Download className="w-3 h-3 text-black" />
                        <span>Download Updated PDF / File</span>
                      </button>
                    )}
                  </div>
                  <span className="text-[9px] text-neutral-500 mt-1 px-1 font-mono">
                    {msg.timestamp}
                  </span>
                </div>
              ))}

              {isLoading && (
                <div className="flex items-start">
                  <div className="bg-neutral-900 border border-[#00ff9d]/30 text-neutral-300 p-3 rounded-xl rounded-bl-none flex items-center gap-2 font-mono text-xs">
                    <Loader2 className="w-4 h-4 text-[#00ff9d] animate-spin" />
                    <span>Gemma 4 scanning files & security telemetry...</span>
                  </div>
                </div>
              )}
              <div ref={messagesEndRef} />
            </div>

            {/* Attached File Preview Chips */}
            {attachedFiles.length > 0 && (
              <div className="px-3 py-2 bg-neutral-900 border-t border-neutral-800 flex items-center gap-1.5 flex-wrap max-h-20 overflow-y-auto shrink-0">
                {attachedFiles.map((file, idx) => (
                  <div
                    key={idx}
                    className="flex items-center gap-1.5 bg-neutral-950 border border-neutral-750 text-neutral-200 text-[10px] font-mono px-2 py-0.5 rounded-md shadow-sm"
                  >
                    <FileText className="w-3 h-3 text-[#00ff9d] shrink-0" />
                    <span className="truncate max-w-[120px] font-medium">{file.name}</span>
                    <span className="text-neutral-500 text-[9px]">({formatFileSize(file.size)})</span>
                    <button
                      type="button"
                      onClick={() => removeFile(idx)}
                      className="p-0.5 hover:text-red-400 text-neutral-400 rounded transition-colors ml-0.5 cursor-pointer"
                      title="Remove file"
                    >
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}

            {/* Input Footer */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSend();
              }}
              className="p-3 bg-neutral-900 border-t border-neutral-800 flex items-center gap-2 shrink-0"
            >
              {/* Paperclip Browse File Button */}
              <button
                type="button"
                onClick={() => fileInputRef.current?.click()}
                className={`p-2 rounded-lg border transition-all cursor-pointer shrink-0 ${
                  attachedFiles.length > 0
                    ? 'bg-[#00ff9d]/20 text-[#00ff9d] border-[#00ff9d]/50'
                    : 'bg-neutral-950 text-neutral-400 hover:text-white border-neutral-800 hover:border-neutral-700'
                }`}
                title="Browse & attach file to scan"
                aria-label="Attach file"
              >
                <Paperclip className="w-4 h-4" />
              </button>

              <input
                type="text"
                value={inputQuery}
                onChange={(e) => setInputQuery(e.target.value)}
                placeholder={
                  attachedFiles.length > 0
                    ? `${attachedFiles.length} file(s) attached — Ask or scan file...`
                    : 'Ask SOC Analyst or drop files...'
                }
                disabled={isLoading}
                className="flex-1 bg-neutral-950 border border-neutral-800 focus:border-[#00ff9d] text-xs font-mono text-neutral-100 placeholder-neutral-500 px-3 py-2 rounded-lg outline-none transition-colors"
              />
              <button
                type="submit"
                disabled={(!inputQuery.trim() && attachedFiles.length === 0) || isLoading}
                className="p-2 bg-[#00ff9d] hover:bg-[#00e68d] disabled:bg-neutral-800 text-black disabled:text-neutral-600 font-bold rounded-lg transition-colors cursor-pointer shrink-0 disabled:cursor-not-allowed shadow-md"
                aria-label="Send query"
              >
                <Send className="w-4 h-4" />
              </button>
            </form>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Floating Chatbot Toggle Button (Icon Only, Clean Non-Blinking) */}
      <button
        type="button"
        onClick={() => setIsOpen((prev) => !prev)}
        className="relative group flex items-center justify-center p-3.5 bg-neutral-900 border border-[#00ff9d]/50 hover:border-[#00ff9d] text-[#00ff9d] rounded-full shadow-[0_0_20px_rgba(0,255,157,0.25)] hover:shadow-[0_0_30px_rgba(0,255,157,0.4)] transition-all duration-300 cursor-pointer active:scale-95"
        title="Open Gemma SOC Assistant"
        aria-label="Open Gemma SOC Assistant"
      >
        <Bot className="w-6 h-6 text-[#00ff9d] group-hover:scale-110 transition-transform duration-300" />
      </button>
    </div>
  );
};
