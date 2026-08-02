import { EntityMatch, EntityType } from '../types';

// Client Watchlist terms
export const DEFAULT_WATCHLIST = [
  'Apple',
  'Project Titan',
  'Northwind Corp',
  'Apex Capital',
  'Sovereign AI',
  'Project Shield'
];

/**
 * Validates a card number using Luhn algorithm
 */
export function validateLuhn(cardNumber: string): boolean {
  const cleanNum = cardNumber.replace(/\D/g, '');
  if (cleanNum.length < 13 || cleanNum.length > 19) return false;

  let sum = 0;
  let shouldDouble = false;

  for (let i = cleanNum.length - 1; i >= 0; i--) {
    let digit = parseInt(cleanNum.charAt(i), 10);

    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }

    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

/**
 * Scans a text string for sensitive entity spans using regex and heuristics.
 */
export function analyzePrompt(
  text: string,
  customWatchlist: string[] = DEFAULT_WATCHLIST
): EntityMatch[] {
  const matches: EntityMatch[] = [];

  // Helper to push non-overlapping match
  const addMatch = (type: EntityType, value: string, index: number, description?: string) => {
    const span: [number, number] = [index, index + value.length];
    // Check if overlaps with existing higher priority match
    const exists = matches.some(
      (m) =>
        (span[0] >= m.span[0] && span[0] < m.span[1]) ||
        (span[1] > m.span[0] && span[1] <= m.span[1])
    );
    if (!exists) {
      matches.push({
        type,
        value,
        span,
        confidence: 0.95,
        description: description || `Detected ${type}`
      });
    }
  };

  // 1. CREDIT_CARD (Luhn check)
  const cardRegex = /\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|6(?:011|5\d\d)\d{12}|3[47]\d{13}|3(?:0[0-5]|[68]\d)\d{11}|(?:2131|1800|35\d{3})\d{11}|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b/g;
  let cardMatch: RegExpExecArray | null;
  while ((cardMatch = cardRegex.exec(text)) !== null) {
    if (validateLuhn(cardMatch[0])) {
      addMatch('CREDIT_CARD', cardMatch[0], cardMatch.index, 'Valid Credit Card Number (Luhn verified)');
    }
  }

  // 2. US_SSN
  const ssnRegex = /\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
  let ssnMatch: RegExpExecArray | null;
  while ((ssnMatch = ssnRegex.exec(text)) !== null) {
    addMatch('US_SSN', ssnMatch[0], ssnMatch.index, 'US Social Security Number');
  }

  // 3. API_KEY_SECRET
  const apiKeyPatterns = [
    /sk-(?:proj-)?[a-zA-Z0-9_-]{20,}/g,
    /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
    /\bgh[pousr]_[a-zA-Z0-9]{36}\b/g,
    /-----BEGIN (?:RSA )?PRIVATE KEY-----/g,
    /(?:api_key|secret_key|private_key|auth_token|bearer)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{16,})["']?/gi
  ];

  for (const pattern of apiKeyPatterns) {
    let keyMatch: RegExpExecArray | null;
    while ((keyMatch = pattern.exec(text)) !== null) {
      addMatch('API_KEY_SECRET', keyMatch[0], keyMatch.index, 'API Key or Secret Credential');
    }
  }

  // 4. EMAIL
  const emailRegex = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  let emailMatch: RegExpExecArray | null;
  while ((emailMatch = emailRegex.exec(text)) !== null) {
    addMatch('EMAIL', emailMatch[0], emailMatch.index, 'Personal or Corporate Email Address');
  }

  // 5. PHONE
  const phoneRegex = /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g;
  let phoneMatch: RegExpExecArray | null;
  while ((phoneMatch = phoneRegex.exec(text)) !== null) {
    addMatch('PHONE', phoneMatch[0], phoneMatch.index, 'Phone Number');
  }

  // 6. FINANCIAL_VALUE
  const financialRegex = /\b(?:\$|€|£|USD\s?|EUR\s?)\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s?(?:million|billion|M|B|k|K))?\b|\b\d+(?:\.\d+)?\s?(?:million|billion|M|B|k|K)\s?(?:USD|EUR|dollars)?\b/gi;
  let finMatch: RegExpExecArray | null;
  while ((finMatch = financialRegex.exec(text)) !== null) {
    addMatch('FINANCIAL_VALUE', finMatch[0], finMatch.index, 'Financial Amount / Valuation Exposure');
  }

  // 7. CLIENT_WATCHLIST
  for (const client of customWatchlist) {
    const escaped = client.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const clientRegex = new RegExp(`\\b${escaped}\\b`, 'gi');
    let clientMatch: RegExpExecArray | null;
    while ((clientMatch = clientRegex.exec(text)) !== null) {
      addMatch('CLIENT_WATCHLIST', clientMatch[0], clientMatch.index, `Protected Client/Project: ${client}`);
    }
  }

  // 8. SOURCE_CODE_INDICATOR
  const sourceCodePatterns = [
    /\b(?:import|export)\s+[\s\S]*?\s+from\s+["'].*?["']/g,
    /\b(?:function|const|let|var|class|def|async\s+function)\s+[a-zA-Z0-9_]+\s*\(.*?\)/g,
    /\bSELECT\s+.*?\s+FROM\s+[a-zA-Z0-9_]+/gi,
    /process\.env\.[A-zA-Z0-9_]+/g,
    /eval\(.*?\)/g,
    /<script[\s\S]*?>[\s\S]*?<\/script>/gi
  ];

  for (const pattern of sourceCodePatterns) {
    let codeMatch: RegExpExecArray | null;
    while ((codeMatch = pattern.exec(text)) !== null) {
      addMatch('SOURCE_CODE_INDICATOR', codeMatch[0], codeMatch.index, 'Source Code / Internal Logic Construct');
    }
  }

  // 9. CONFIDENTIAL_ENTERPRISE_DOC (Sensitive Company Files / Payroll / Financial Spreadsheets)
  const confidentialDocPatterns = [
    /\b(?:CONFIDENTIAL|RESTRICTED|PROPRIETARY|INTERNAL USE ONLY|COMPANY CONFIDENTIAL|CLASSIFIED|SECRET)\b/gi,
    /\b(?:PAYROLL|SALARY|COMPENSATION|BONUS|TAX RETURN|BALANCE SHEET|PROFIT AND LOSS|P&L|REVENUE|FINANCIAL REPORT)\b/gi,
    /EXCEL SPREADSHEET PAYLOAD|EXCEL CSV SPREADSHEET|PDF DOCUMENT PAYLOAD/gi
  ];

  for (const pattern of confidentialDocPatterns) {
    let docMatch: RegExpExecArray | null;
    while ((docMatch = pattern.exec(text)) !== null) {
      addMatch('FINANCIAL_VALUE', docMatch[0], docMatch.index, 'Sensitive Corporate Financial / Confidential Document Payload');
    }
  }

  // Sort by index ascending
  return matches.sort((a, b) => a.span[0] - b.span[0]);
}
