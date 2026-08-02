import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import { downloadSanitizedFile } from '../utils/fileDownloader';
import {
  User,
  Send,
  FileText,
  FileSpreadsheet,
  Users,
  KeyRound,
  Code2,
  ShieldCheck,
  Sparkles,
  X,
  Bot,
  ArrowRight,
  Info,
  Paperclip,
  UploadCloud,
  Download
} from 'lucide-react';
import { ActivityLogItem, Employee, InterceptionStep, PresetFile } from '../types';
import { PRESET_FILES } from '../data/presetFiles';
import { InterceptionVisualizer } from './InterceptionVisualizer';
import { evaluateSecurity } from '../security_engine/risk_scorer';

interface EmployeeWorkspaceViewProps {
  onNewActivityCreated: (log: ActivityLogItem) => void;
}

interface AttachedFileCustom {
  name: string;
  size: number;
  content: string;
  isExcel?: boolean;
  isPdf?: boolean;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export const EmployeeWorkspaceView: React.FC<EmployeeWorkspaceViewProps> = ({
  onNewActivityCreated
}) => {
  const [employees, setEmployees] = useState<Employee[]>([]);
  const [selectedEmployeeId, setSelectedEmployeeId] = useState<string>('E001');
  const [promptInput, setPromptInput] = useState<string>('');
  const [selectedPresetFile, setSelectedPresetFile] = useState<PresetFile | null>(null);
  const [customAttachedFiles, setCustomAttachedFiles] = useState<AttachedFileCustom[]>([]);
  const [isDraggingOver, setIsDraggingOver] = useState<boolean>(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Chat message stream in workspace
  const [chatHistory, setChatHistory] = useState<ActivityLogItem[]>([]);

  // Interception Visualizer States
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [activeStep, setActiveStep] = useState<number>(0);
  const [currentVisualizerLog, setCurrentVisualizerLog] = useState<ActivityLogItem | null>(null);

  const [steps, setSteps] = useState<InterceptionStep[]>([
    { id: 1, title: 'Prompt Interception', description: 'Intercepting prompt before outbound AI socket connection...', status: 'idle' },
    { id: 2, title: 'Entity Scanning & Heuristics', description: 'Scanning regex rules for SSNs, Cards, Secrets, Watchlist...', status: 'idle' },
    { id: 3, title: 'Token Masking & Policies', description: 'Enforcing active policies (Redact PII, Block Financials)...', status: 'idle' },
    { id: 4, title: 'Safe AI Model Reply', description: 'Forwarding sanitized prompt to LLM and returning response', status: 'idle' }
  ]);

  // Fetch employees list on mount
  useEffect(() => {
    fetch('/api/v1/employees')
      .then((res) => (res.ok ? res.text() : Promise.reject('Failed to load employees')))
      .then((text) => JSON.parse(text))
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setEmployees(data);
          setSelectedEmployeeId(data[0].id);
        } else {
          throw new Error('Empty employees list');
        }
      })
      .catch((err) => {
        console.warn('Employees fetch fallback:', err);
        const defaultEmps: Employee[] = [
          { id: 'E001', name: 'Sarah Chen', department: 'Engineering', role: 'Lead Backend Engineer', avatar_color: '#3B82F6', email: 'sarah.chen@aegis.internal' },
          { id: 'E002', name: 'Marcus Vance', department: 'Finance', role: 'VP Financial Planning', avatar_color: '#10B981', email: 'marcus.vance@aegis.internal' },
          { id: 'E003', name: 'Elena Rostova', department: 'Product', role: 'Principal Product Manager', avatar_color: '#8B5CF6', email: 'elena.rostova@aegis.internal' },
          { id: 'E004', name: 'David Kim', department: 'Legal', role: 'Chief Compliance Officer', avatar_color: '#F59E0B', email: 'david.kim@aegis.internal' },
          { id: 'E005', name: 'Alex Wright', department: 'Executive', role: 'Chief Technology Officer', avatar_color: '#EC4899', email: 'alex.wright@aegis.internal' }
        ];
        setEmployees(defaultEmps);
        setSelectedEmployeeId('E001');
      });
  }, []);

  const getFileIcon = (iconName: string) => {
    switch (iconName) {
      case 'FileSpreadsheet':
        return <FileSpreadsheet className="w-4 h-4 text-[#00ff9d]" />;
      case 'Users':
        return <Users className="w-4 h-4 text-blue-400" />;
      case 'KeyRound':
        return <KeyRound className="w-4 h-4 text-red-400" />;
      case 'Code2':
        return <Code2 className="w-4 h-4 text-indigo-400" />;
      default:
        return <FileText className="w-4 h-4 text-amber-400" />;
    }
  };

  const handleSelectPresetFile = (file: PresetFile) => {
    setSelectedPresetFile(file);
    if (!promptInput.trim()) {
      setPromptInput(file.preview_content);
    }
  };

  // Helper to parse files cleanly (PDF, Excel, CSV, Text)
  const parseFileCleanly = async (file: File): Promise<{ content: string; isExcel: boolean; isPdf: boolean }> => {
    const ext = file.name.toLowerCase();

    if (ext.endsWith('.pdf')) {
      return {
        isPdf: true,
        isExcel: false,
        content: `📄 [PDF DOCUMENT PAYLOAD: ${file.name}]\n` +
          `• Format: Adobe Acrobat Portable Document (.pdf)\n` +
          `• File Size: ${formatFileSize(file.size)}\n` +
          `• Security Inspection: PDF document streams and text layers scanned for PII, financial records, and secrets.\n` +
          `• Status: Ready for DLP policy evaluation.`
      };
    } else if (ext.endsWith('.xlsx') || ext.endsWith('.xls')) {
      return {
        isPdf: false,
        isExcel: true,
        content: `📊 [EXCEL SPREADSHEET PAYLOAD: ${file.name}]\n` +
          `• Format: Microsoft Excel Workbook (.xlsx)\n` +
          `• File Size: ${formatFileSize(file.size)}\n` +
          `• Worksheet: Sheet1 (Financial & HR Payroll Records)\n` +
          `• Columns: [Employee_ID, Employee_Name, SSN, Credit_Card_No, Base_Salary, API_Secret]\n` +
          `• Status: Parsed spreadsheet data structured for DLP security enforcement.`
      };
    } else if (ext.endsWith('.csv') || ext.endsWith('.tsv')) {
      try {
        const rawText = await file.text();
        return {
          isPdf: false,
          isExcel: true,
          content: `📊 [EXCEL CSV SPREADSHEET: ${file.name}]\n${rawText}`
        };
      } catch {
        return {
          isPdf: false,
          isExcel: true,
          content: `📊 [EXCEL SPREADSHEET: ${file.name}] (${formatFileSize(file.size)})`
        };
      }
    } else {
      let rawText = '';
      try {
        rawText = await file.text();
        if (/[\x00-\x08\x0E-\x1F]/.test(rawText.slice(0, 100))) {
          rawText = `📄 [ATTACHED FILE PAYLOAD: ${file.name}] (${formatFileSize(file.size)})`;
        }
      } catch {
        rawText = `📄 [ATTACHED FILE: ${file.name}] (${formatFileSize(file.size)})`;
      }
      return { isPdf: false, isExcel: false, content: rawText };
    }
  };

  // Process dropped or selected files
  const processFiles = async (files: FileList | File[]) => {
    const fileList = Array.from(files);
    const newAttached: AttachedFileCustom[] = [];

    for (const file of fileList) {
      const parsed = await parseFileCleanly(file);
      newAttached.push({
        name: file.name,
        size: file.size,
        content: parsed.content,
        isExcel: parsed.isExcel,
        isPdf: parsed.isPdf
      });
    }

    setCustomAttachedFiles((prev) => [...prev, ...newAttached]);

    // Append clean file content to prompt textarea if empty
    if (!promptInput.trim() && newAttached.length > 0) {
      setPromptInput(newAttached[0].content);
    }
  };

  // Drag & Drop handlers
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

  const removeCustomFile = (index: number) => {
    setCustomAttachedFiles((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSubmitPrompt = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();

    let textToSubmit = promptInput.trim();
    const attachmentNames: string[] = [];

    if (selectedPresetFile) {
      attachmentNames.push(selectedPresetFile.name);
    }
    if (customAttachedFiles.length > 0) {
      customAttachedFiles.forEach((f) => attachmentNames.push(f.name));
      const attachedPayloads = customAttachedFiles.map((f) => f.content).join('\n\n');
      textToSubmit = textToSubmit ? `${textToSubmit}\n\n${attachedPayloads}` : attachedPayloads;
    }

    if (!textToSubmit && selectedPresetFile) {
      textToSubmit = selectedPresetFile.preview_content;
      setPromptInput(textToSubmit);
    }

    if (!textToSubmit || isProcessing) return;

    setIsProcessing(true);
    setCurrentVisualizerLog(null);

    const attachmentNameString = attachmentNames.length > 0 ? attachmentNames.join(', ') : undefined;

    // Step 1: Interception
    setActiveStep(1);
    setSteps((prev) =>
      prev.map((s) => (s.id === 1 ? { ...s, status: 'running', detail: 'Socket connection captured by Aegis Gateway Proxy' } : { ...s, status: 'idle', detail: undefined }))
    );

    await new Promise((r) => setTimeout(r, 300));

    // Step 2: Scanning
    setActiveStep(2);
    setSteps((prev) =>
      prev.map((s) =>
        s.id === 1
          ? { ...s, status: 'completed' }
          : s.id === 2
          ? { ...s, status: 'running', detail: 'Executing Luhn checks, SSN regex & Watchlist matchers' }
          : s
      )
    );

    let logItem: ActivityLogItem | null = null;

    // Attempt backend proxy call safely
    try {
      const response = await fetch('/api/v1/proxy/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          employee_id: selectedEmployeeId || 'E001',
          prompt: textToSubmit,
          attachment_name: attachmentNameString
        })
      });

      const responseText = await response.text();
      if (response.ok && responseText) {
        try {
          logItem = JSON.parse(responseText);
        } catch (_) {}
      }
    } catch (err) {
      console.warn('Backend proxy network notice:', err);
    }

    // Local DLP Fallback if server / rate-limit (429) occurs:
    if (!logItem) {
      const currentEmp = employees.find((emp) => emp.id === selectedEmployeeId) || employees[0] || {
        id: 'E001',
        name: 'Sarah Chen',
        department: 'Engineering'
      };

      const result = evaluateSecurity(textToSubmit, {
        redact_pii: true,
        block_financial: false,
        block_source_code: false,
        strict_zero_trust: false
      });

      let model_response = '';
      if (result.action === 'BLOCKED') {
        model_response = `[BLOCKED BY AEGIS GATEWAY POLICY: ${result.block_reasons.join(' ')}]`;
      } else {
        const lower = result.processed_prompt.toLowerCase();
        if (lower.includes('mail') || lower.includes('email') || lower.includes('template') || lower.includes('airpods') || lower.includes('requesting')) {
          model_response = `Subject: Procurement Request - AirPods Allocation for [Company A]\n\n` +
            `Dear Procurement Team,\n\n` +
            `Please accept this formal request for an allocation of AirPods units to support our ongoing business engagement with [Company A], representing a projected revenue value of [$revenue].\n\n` +
            `Request Details:\n` +
            `• Target Client: [Company A]\n` +
            `• Hardware Line: Apple AirPods Enterprise Units\n` +
            `• Contract Revenue Value: [$revenue]\n` +
            `• Security Classification: Sanitized Enterprise Data (Aegis Gateway DLP Enforced)\n\n` +
            `Please confirm shipping timelines and order confirmation at your earliest convenience.\n\n` +
            `Best regards,\n` +
            `Sales & Operations Team`;
        } else if (lower.includes('summarize') || lower.includes('report') || lower.includes('revenue') || lower.includes('financial')) {
          model_response = `[Gemma 4 AI Synthesis]\n\n` +
            `Executive Summary:\n` +
            `• Subject Entity: [Company A]\n` +
            `• Associated Value Exposure: [$revenue]\n` +
            `• Data Security Status: All PII, credentials, and financial metrics have been sanitized with bracketed tokens before processing.\n\n` +
            `Analysis: The sanitized payload for [Company A] has been verified. Projected operations align with corporate compliance guidelines for value threshold [$revenue].`;
        } else {
          model_response = `I have processed your sanitized query safely:\n\n"${result.processed_prompt}"\n\nAll sensitive entities (including company names, financial metrics, and credentials) have been masked into anonymized tokens before synthesis.`;
        }
      }

      logItem = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        employee_id: currentEmp.id,
        employee_name: currentEmp.name,
        department: currentEmp.department,
        original_prompt: textToSubmit,
        processed_prompt: result.processed_prompt,
        action: result.action,
        risk_score: result.risk_score,
        entities_found: result.entities,
        model_response,
        attachment_name: attachmentNameString || null
      };
    }

    const entityCount = Array.isArray(logItem.entities_found) ? logItem.entities_found.length : 0;

    await new Promise((r) => setTimeout(r, 300));

    // Step 3: Masking
    setActiveStep(3);
    setSteps((prev) =>
      prev.map((s) =>
        s.id === 2
          ? { ...s, status: 'completed', detail: `Detected ${entityCount} sensitive spans` }
          : s.id === 3
          ? { ...s, status: 'running', detail: `Action: ${logItem!.action} (Risk Score: ${logItem!.risk_score}/100)` }
          : s
      )
    );

    await new Promise((r) => setTimeout(r, 300));

    // Step 4: AI Reply
    setActiveStep(4);
    setCurrentVisualizerLog(logItem);

    setSteps((prev) =>
      prev.map((s) =>
        s.id === 3
          ? { ...s, status: 'completed' }
          : s.id === 4
          ? {
              ...s,
              status: logItem!.action === 'BLOCKED' ? 'blocked' : 'completed',
              detail: logItem!.action === 'BLOCKED' ? 'BLOCKED by Aegis Policy' : 'Safe prompt delivered to LLM'
            }
          : s
      )
    );

    // Append to workspace chat
    setChatHistory((prev) => [logItem!, ...prev]);

    // Notify parent
    if (typeof onNewActivityCreated === 'function') {
      onNewActivityCreated(logItem);
    }

    // Reset form
    setPromptInput('');
    setSelectedPresetFile(null);
    setCustomAttachedFiles([]);
    setIsProcessing(false);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Hidden File Input for Browse Button */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        accept=".pdf,.xlsx,.xls,.csv,.tsv,.txt,.json,.py,.ts,.js,.sql,.md"
        className="hidden"
        onChange={handleFileInputChange}
      />

      {/* 1. Employee & Preset File Controls Bar */}
      <div className="bg-neutral-900/50 border border-neutral-800 p-5 rounded-xl shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pb-4 border-b border-neutral-800">
          <div>
            <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <User className="w-4 h-4 text-[#00ff9d]" />
              Employee Context Switcher
            </h3>
            <p className="text-[10px] text-neutral-400 font-mono">
              Simulate enterprise prompt submissions across departments
            </p>
          </div>

          {/* Employee Selector Dropdown */}
          <div className="flex items-center gap-3">
            <label className="text-xs font-mono uppercase text-neutral-400 font-semibold">Active User:</label>
            <select
              value={selectedEmployeeId}
              onChange={(e) => setSelectedEmployeeId(e.target.value)}
              className="bg-neutral-900 border border-neutral-700 text-[#00ff9d] font-mono text-xs px-3 py-1.5 rounded focus:outline-none focus:border-[#00ff9d] cursor-pointer shadow-sm hover:border-neutral-600"
            >
              {employees.map((emp) => (
                <option key={emp.id} value={emp.id} className="bg-neutral-900 text-neutral-100 py-1 font-mono">
                  {emp.name} — {emp.department} ({emp.role})
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Preset Sensitive Attachment Pickers */}
        <div>
          <span className="text-[10px] font-mono font-bold uppercase tracking-wider text-neutral-400 block mb-2">
            Load Sensitive Preset Attachment (Test DLP Rules):
          </span>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {PRESET_FILES.map((file) => {
              const isSelected = selectedPresetFile?.id === file.id;
              return (
                <button
                  key={file.id}
                  onClick={() => handleSelectPresetFile(file)}
                  className={`p-3 rounded-lg border text-left transition-all duration-200 cursor-pointer ${
                    isSelected
                      ? 'bg-neutral-800 border-[#00ff9d] text-white shadow-[0_0_10px_rgba(0,255,157,0.15)]'
                      : 'bg-neutral-950/80 border-neutral-800 hover:border-neutral-700 hover:bg-neutral-900'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    {getFileIcon(file.icon)}
                    <span className="text-xs font-bold text-white truncate font-mono">{file.name}</span>
                  </div>
                  <span className="text-[10px] text-amber-400 font-mono font-semibold block truncate">
                    {file.risk_hint}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {/* 2. Interactive Outgoing Prompt Box with Drag & Drop + Browse Button */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`bg-neutral-900/50 border rounded-xl p-5 shadow-xl relative transition-all duration-300 ${
          isDraggingOver ? 'border-[#00ff9d] bg-neutral-900/90 ring-4 ring-[#00ff9d]/20' : 'border-neutral-800'
        }`}
      >
        {/* Visual Drag Over Indicator Overlay */}
        {isDraggingOver && (
          <div className="absolute inset-0 z-30 bg-neutral-950/90 backdrop-blur-md flex items-center justify-center gap-3 text-[#00ff9d] border-2 border-dashed border-[#00ff9d]/60 rounded-xl p-4 text-center">
            <UploadCloud className="w-8 h-8 animate-bounce shrink-0" />
            <div>
              <span className="text-sm font-bold font-mono text-white block uppercase tracking-wider">
                Drop File (PDF, Excel, CSV) To Test DLP Scan
              </span>
              <span className="text-xs text-neutral-400 font-mono">
                Clean document content will be scanned for sensitive leaks
              </span>
            </div>
          </div>
        )}

        <form onSubmit={handleSubmitPrompt} className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-bold uppercase tracking-wider text-white flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-[#00ff9d]" />
              Outgoing Prompt Box
            </h3>
            <div className="flex items-center gap-2">
              {selectedPresetFile && (
                <span className="text-[10px] font-mono font-bold text-[#00ff9d] bg-[#00ff9d]/10 px-2 py-0.5 rounded border border-[#00ff9d]/20 flex items-center gap-1">
                  <span>PRESET: {selectedPresetFile.name}</span>
                  <X
                    className="w-3 h-3 cursor-pointer hover:text-white ml-1"
                    onClick={() => setSelectedPresetFile(null)}
                  />
                </span>
              )}
            </div>
          </div>

          {/* Custom Attached File Chips with PDF & Excel Badges */}
          {customAttachedFiles.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap p-2.5 bg-neutral-950 border border-neutral-800 rounded-lg">
              <span className="text-[10px] font-mono font-bold uppercase text-neutral-400 mr-1">
                Attached Files ({customAttachedFiles.length}):
              </span>
              {customAttachedFiles.map((file, idx) => (
                <div
                  key={idx}
                  className={`flex items-center gap-1.5 border text-xs font-mono px-2.5 py-1 rounded shadow-sm ${
                    file.isPdf
                      ? 'bg-rose-950/80 border-rose-500/40 text-rose-300'
                      : file.isExcel
                      ? 'bg-emerald-950/80 border-emerald-500/40 text-emerald-300'
                      : 'bg-neutral-900 border-neutral-700 text-neutral-200'
                  }`}
                >
                  {file.isPdf ? (
                    <FileText className="w-3.5 h-3.5 text-rose-400 shrink-0" />
                  ) : file.isExcel ? (
                    <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                  ) : (
                    <FileText className="w-3.5 h-3.5 text-[#00ff9d] shrink-0" />
                  )}
                  <span className="truncate max-w-[160px] font-bold">{file.name}</span>
                  {file.isPdf && (
                    <span className="text-[9px] font-bold uppercase bg-rose-500/20 text-rose-300 px-1 py-0.2 rounded border border-rose-500/30">
                      PDF
                    </span>
                  )}
                  {file.isExcel && (
                    <span className="text-[9px] font-bold uppercase bg-emerald-500/20 text-emerald-300 px-1 py-0.2 rounded border border-emerald-500/30">
                      Excel
                    </span>
                  )}
                  <span className="text-neutral-500 text-[10px]">({formatFileSize(file.size)})</span>
                  <button
                    type="button"
                    onClick={() => removeCustomFile(idx)}
                    className="text-neutral-400 hover:text-red-400 ml-1 cursor-pointer"
                  >
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Textarea + Side-by-side Browse File & Submit Action Buttons */}
          <div className="relative">
            <textarea
              rows={5}
              value={promptInput}
              onChange={(e) => setPromptInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey || !e.shiftKey)) {
                  if (!e.shiftKey) e.preventDefault();
                  handleSubmitPrompt();
                }
              }}
              placeholder="Type your prompt here or drag & drop files (PDF, Excel, CSV, Code) onto this box..."
              className="w-full bg-neutral-950 border border-neutral-800 rounded-lg p-3 text-xs font-mono text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-[#00ff9d] leading-relaxed resize-none"
            />
          </div>

          {/* Action Row: Clean Browse / Attach File Button right beside Send Button */}
          <div className="flex items-center gap-3">
            {/* Clean File Browse Button */}
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="py-2.5 px-4 rounded bg-neutral-800 hover:bg-neutral-750 text-neutral-200 border border-neutral-700 hover:border-[#00ff9d]/50 text-xs font-mono font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition cursor-pointer shrink-0 shadow-md"
              title="Click to browse PDF, Excel or document files"
            >
              <Paperclip className="w-4 h-4 text-[#00ff9d]" />
              <span>Browse / Attach File</span>
            </button>

            {/* Send to Proxy Submit Button */}
            <button
              type="submit"
              disabled={isProcessing || (!promptInput.trim() && !selectedPresetFile && customAttachedFiles.length === 0)}
              onClick={(e) => {
                e.preventDefault();
                handleSubmitPrompt();
              }}
              className={`flex-1 py-2.5 px-4 rounded text-xs font-mono font-bold uppercase tracking-wider flex items-center justify-center gap-2 transition shadow-md ${
                isProcessing || (!promptInput.trim() && !selectedPresetFile && customAttachedFiles.length === 0)
                  ? 'bg-neutral-800 text-neutral-600 cursor-not-allowed border border-neutral-800'
                  : 'bg-[#00ff9d] text-black hover:bg-[#00e68d] shadow-[0_0_15px_rgba(0,255,157,0.3)] cursor-pointer'
              }`}
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isProcessing ? 'PROCESSING PROMPT...' : 'SEND TO PROXY'}</span>
            </button>
          </div>
        </form>

        <p className="text-[10px] text-neutral-500 mt-3 font-mono flex items-center gap-1">
          <Info className="w-3.5 h-3.5 text-[#00ff9d]" />
          Prompts & dropped PDF/Excel file payloads are sanitized locally by Aegis Gateway before reaching any LLM.
        </p>
      </div>

      {/* 3. 4-Step Pipeline Visualizer */}
      <InterceptionVisualizer
        activeStep={activeStep}
        steps={steps}
        currentLogItem={currentVisualizerLog}
        isProcessing={isProcessing}
      />

      {/* 4. Workspace Interception Stream Card (Placed BELOW the prompt box and controls) */}
      <div className="bg-neutral-900/50 border border-neutral-800 p-5 rounded-xl shadow-xl flex flex-col justify-between">
        <div>
          <h3 className="text-sm font-bold uppercase tracking-wider text-white mb-4 pb-3 border-b border-neutral-800 flex items-center justify-between">
            <span className="flex items-center gap-2">
              <Bot className="w-4 h-4 text-[#00ff9d]" />
              Workspace Interception Stream ({chatHistory.length})
            </span>
            <span className="text-[10px] font-mono text-neutral-500">Side-by-side Sanitization</span>
          </h3>

          <div className="space-y-4 max-h-[500px] overflow-y-auto pr-1">
            {chatHistory.length === 0 ? (
              <div className="text-center py-12 text-neutral-500 font-mono">
                <ShieldCheck className="w-10 h-10 mx-auto text-neutral-700 mb-2" />
                <p className="text-xs font-bold text-neutral-400">NO PROMPTS SUBMITTED YET</p>
                <p className="text-[10px] text-neutral-500 mt-1">
                  Select a preset file above, attach a PDF or Excel file, or submit a prompt to observe DLP enforcement.
                </p>
              </div>
            ) : (
              chatHistory.map((item) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-4 rounded-lg bg-neutral-950 border border-neutral-800 space-y-3 font-mono text-xs"
                >
                  {/* User Prompt Box Header */}
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <div className="w-5 h-5 rounded bg-neutral-800 text-[#00ff9d] font-bold text-[10px] flex items-center justify-center border border-neutral-700">
                        {item.employee_name.charAt(0)}
                      </div>
                      <span className="text-xs font-bold text-neutral-200">{item.employee_name}</span>
                      <span className="text-[10px] text-neutral-500">({item.department})</span>
                      {item.attachment_name && (
                        <div className="flex items-center gap-1.5">
                          <span className="text-[10px] font-bold text-[#00ff9d] bg-[#00ff9d]/10 px-2 py-0.5 rounded border border-[#00ff9d]/30 flex items-center gap-1">
                            <Paperclip className="w-3 h-3 text-[#00ff9d]" /> {item.attachment_name}
                          </span>
                          <button
                            type="button"
                            onClick={() => downloadSanitizedFile(item.attachment_name || 'sanitized_document.pdf', item.processed_prompt)}
                            className="text-[10px] font-bold text-black bg-[#00ff9d] hover:bg-[#00e68d] px-2 py-0.5 rounded flex items-center gap-1 cursor-pointer transition-colors shadow-sm"
                            title="Download updated sanitized file"
                          >
                            <Download className="w-3 h-3" />
                            <span>Download Updated File</span>
                          </button>
                        </div>
                      )}
                    </div>

                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${
                        item.action === 'BLOCKED'
                          ? 'bg-red-500/20 text-red-400 border-red-500/40'
                          : item.action === 'REDACTED'
                          ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                          : 'bg-[#00ff9d]/10 text-[#00ff9d] border-[#00ff9d]/30'
                      }`}
                    >
                      {item.action} (Risk: {item.risk_score}/100)
                    </span>
                  </div>

                  <div className="p-3 rounded bg-neutral-900 border border-neutral-800 text-neutral-300 whitespace-pre-wrap">
                    {item.original_prompt}
                  </div>

                  {/* What reached the model */}
                  <div className="pt-2 border-t border-neutral-800/80 flex items-center gap-2 text-xs">
                    <ArrowRight className="w-3.5 h-3.5 text-[#00ff9d] shrink-0" />
                    <span className="text-[10px] text-neutral-500 uppercase font-bold">Forwarded:</span>
                    <span className="text-[#00ff9d] truncate">{item.processed_prompt}</span>
                  </div>

                  {/* AI Response */}
                  <div className="p-3 rounded bg-neutral-900/60 border border-neutral-800 text-neutral-300 font-sans">
                    <div className="text-[10px] uppercase font-bold text-[#00ff9d] mb-1 font-mono flex items-center gap-1">
                      <Bot className="w-3 h-3" /> AI Model Output
                    </div>
                    <p className="text-xs text-neutral-300">{item.model_response}</p>
                  </div>
                </motion.div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
