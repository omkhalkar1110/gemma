import { EntityMatch, PolicyAction, SecurityAnalysisResult } from '../types';
import { analyzePrompt } from './analyzer';
import { anonymizePrompt } from './anonymizer';

export interface PolicyState {
  redact_pii: boolean;
  block_financial: boolean;
  block_source_code: boolean;
  strict_zero_trust: boolean;
}

/**
 * Calculates a 0-100 risk score and enforces policy actions.
 */
export function evaluateSecurity(
  originalPrompt: string,
  policies: PolicyState,
  customWatchlist?: string[]
): SecurityAnalysisResult {
  const entities: EntityMatch[] = analyzePrompt(originalPrompt, customWatchlist);

  let rawScore = 0;
  const blockReasons: string[] = [];
  const matchedPolicies: string[] = [];

  let hasFinancial = false;
  let hasSourceCode = false;
  let hasSecretsOrSsn = false;

  for (const entity of entities) {
    switch (entity.type) {
      case 'API_KEY_SECRET':
        rawScore += 35;
        hasSecretsOrSsn = true;
        break;
      case 'US_SSN':
        rawScore += 30;
        hasSecretsOrSsn = true;
        break;
      case 'CREDIT_CARD':
        rawScore += 30;
        hasSecretsOrSsn = true;
        break;
      case 'FINANCIAL_VALUE':
        rawScore += 25;
        hasFinancial = true;
        break;
      case 'CLIENT_WATCHLIST':
        rawScore += 20;
        break;
      case 'SOURCE_CODE_INDICATOR':
        rawScore += 15;
        hasSourceCode = true;
        break;
      case 'EMAIL':
        rawScore += 10;
        break;
      case 'PHONE':
        rawScore += 10;
        break;
    }
  }

  const riskScore = Math.min(100, rawScore);

  // Determine policy action
  let action: PolicyAction = 'ALLOWED';

  // Check blocking conditions
  if (policies.block_financial && hasFinancial) {
    action = 'BLOCKED';
    blockReasons.push('Contains prohibited financial values or revenue exposure.');
    matchedPolicies.push('block_financial');
  }

  if (policies.block_source_code && hasSourceCode) {
    action = 'BLOCKED';
    blockReasons.push('Contains proprietary source code or system constructs.');
    matchedPolicies.push('block_source_code');
  }

  if (policies.strict_zero_trust && (riskScore >= 30 || hasSecretsOrSsn)) {
    action = 'BLOCKED';
    blockReasons.push('Strict Zero-Trust policy violated (risk score >= 30 or sensitive credentials).');
    matchedPolicies.push('strict_zero_trust');
  }

  if (riskScore >= 75 && action !== 'BLOCKED') {
    action = 'BLOCKED';
    blockReasons.push('Overall risk score exceeded maximum threshold (75/100).');
    matchedPolicies.push('max_risk_threshold');
  }

  // If not blocked, check if redacted
  if (action !== 'BLOCKED' && entities.length > 0) {
    if (policies.redact_pii) {
      action = 'REDACTED';
      matchedPolicies.push('redact_pii');
    }
  }

  // Always produce the refined/anonymized version for processedPrompt
  let processedPrompt = anonymizePrompt(originalPrompt, entities, true);

  return {
    original_prompt: originalPrompt,
    processed_prompt: processedPrompt,
    action,
    risk_score: riskScore,
    entities,
    matched_policies: matchedPolicies,
    block_reasons: blockReasons
  };
}
