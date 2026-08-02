import { EntityMatch, EntityType } from '../types';

/**
 * Maps entity types to bracketed replacement tokens.
 */
export function getTokenForType(type: EntityType, value?: string): string {
  switch (type) {
    case 'EMAIL':
      return '[EMAIL_REDACTED]';
    case 'PHONE':
      return '[PHONE_REDACTED]';
    case 'US_SSN':
      return '[SSN_REDACTED]';
    case 'CREDIT_CARD':
      return '[CARD_REDACTED]';
    case 'API_KEY_SECRET':
      return '[SECRET_KEY]';
    case 'FINANCIAL_VALUE':
      return '[$revenue]';
    case 'CLIENT_WATCHLIST':
      return '[Company A]';
    case 'SOURCE_CODE_INDICATOR':
      return '[SOURCE_CODE_REDACTED]';
    default:
      return '[REDACTED]';
  }
}

/**
 * Anonymizes prompt text by masking entity spans right-to-left.
 * If redactPii is false, PII entities (EMAIL, PHONE, US_SSN, CREDIT_CARD) are preserved.
 */
export function anonymizePrompt(
  text: string,
  entities: EntityMatch[],
  redactPii: boolean = true
): string {
  if (!entities || entities.length === 0) return text;

  // Filter entities if PII redaction is disabled
  const piiTypes: EntityType[] = ['EMAIL', 'PHONE', 'US_SSN', 'CREDIT_CARD'];
  const activeEntities = entities.filter((e) => {
    if (!redactPii && piiTypes.includes(e.type)) {
      return false;
    }
    return true;
  });

  if (activeEntities.length === 0) return text;

  // Sort right-to-left (descending by start index)
  const sorted = [...activeEntities].sort((a, b) => b.span[0] - a.span[0]);

  let result = text;
  for (const entity of sorted) {
    const [start, end] = entity.span;
    const replacement = getTokenForType(entity.type, entity.value);
    result = result.substring(0, start) + replacement + result.substring(end);
  }

  return result;
}
