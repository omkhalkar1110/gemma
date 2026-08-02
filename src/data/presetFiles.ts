import { PresetFile } from '../types';

export const PRESET_FILES: PresetFile[] = [
  {
    id: 'p1',
    name: 'Q3_Revenue_Apple.pdf',
    type: 'Financial Report',
    size: '1.2 MB',
    preview_content:
      'CONFIDENTIAL REPORT: Summarize Q3 revenue report for Apple: Total quarterly revenue reached $45 million with an EBITDA margin of 28% and projected Q4 earnings of $60M.',
    risk_hint: 'Contains Financial Exposure ($45M) & Client Watchlist (Apple)',
    icon: 'FileSpreadsheet'
  },
  {
    id: 'p2',
    name: 'customer_export.csv',
    type: 'Customer PII Data',
    size: '480 KB',
    preview_content:
      'Customer PII export: Process refund for credit card 4532-0158-9231-8841 belonging to customer SSN 123-45-6789 (Email: marcus.vance@company.com, Phone: 415-555-0199).',
    risk_hint: 'Contains Credit Card (Luhn verified), SSN, Email, Phone',
    icon: 'Users'
  },
  {
    id: 'p3',
    name: 'internal_api_keys.txt',
    type: 'Secret Credentials',
    size: '12 KB',
    preview_content:
      'Production Credentials: OpenAI_Key = sk-proj-9481726354189201928374, AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE, DB_PASS = Pssw0rd!2026. Convert into terraform secrets vault format.',
    risk_hint: 'Contains API Keys, AWS Secret Keys, Database Passwords',
    icon: 'KeyRound'
  },
  {
    id: 'p4',
    name: 'auth_service.py',
    type: 'Source Code',
    size: '45 KB',
    preview_content:
      'import os\nfrom jwt import encode\n\nconst SECRET_KEY = "sk-proj-9481726354189201928374"\n\ndef verify_token(token):\n    return eval(SECRET_KEY)\n\n# Refactor function verify_token(token) for security compliance.',
    risk_hint: 'Contains Source Code Constructs & Hardcoded API Key',
    icon: 'Code2'
  }
];
