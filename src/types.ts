export type EntityType =
  | 'EMAIL'
  | 'PHONE'
  | 'US_SSN'
  | 'CREDIT_CARD'
  | 'API_KEY_SECRET'
  | 'FINANCIAL_VALUE'
  | 'CLIENT_WATCHLIST'
  | 'SOURCE_CODE_INDICATOR';

export interface EntityMatch {
  type: EntityType;
  value: string;
  span: [number, number];
  confidence: number;
  description?: string;
}

export type PolicyAction = 'ALLOWED' | 'REDACTED' | 'BLOCKED';

export interface SecurityAnalysisResult {
  original_prompt: string;
  processed_prompt: string;
  action: PolicyAction;
  risk_score: number; // 0 to 100
  entities: EntityMatch[];
  matched_policies: string[];
  block_reasons: string[];
}

export interface Employee {
  id: string;
  name: string;
  department: string;
  role: string;
  avatar_color: string;
  email: string;
}

export interface PolicySetting {
  key: string;
  label: string;
  description: string;
  enabled: boolean;
  category: 'pii' | 'compliance' | 'security' | 'zero_trust';
  updated_at?: string;
}

export interface ActivityLogItem {
  id: number;
  timestamp: string;
  employee_id: string;
  employee_name: string;
  department: string;
  original_prompt: string;
  processed_prompt: string;
  action: PolicyAction;
  risk_score: number;
  entities_found: EntityMatch[];
  model_response: string;
  attachment_name?: string;
}

export interface DashboardKPIs {
  total_intercepted: number;
  threats_blocked: number;
  pii_redacted: number;
  average_risk_score: number;
  threat_trend: { time: string; intercepted: number; blocked: number; redacted: number }[];
  entity_breakdown: { type: string; count: number; color: string }[];
  risk_distribution: { level: string; count: number; color: string }[];
}

export interface PresetFile {
  id: string;
  name: string;
  type: string;
  size: string;
  preview_content: string;
  risk_hint: string;
  icon: string;
}

export type VisualizerStepStatus = 'idle' | 'running' | 'completed' | 'blocked';

export interface InterceptionStep {
  id: number;
  title: string;
  description: string;
  status: VisualizerStepStatus;
  detail?: string;
}
