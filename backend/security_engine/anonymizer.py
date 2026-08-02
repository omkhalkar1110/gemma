from typing import List, Dict, Any

TOKEN_MAP = {
    "EMAIL": "[EMAIL_REDACTED]",
    "PHONE": "[PHONE_REDACTED]",
    "US_SSN": "[SSN_REDACTED]",
    "CREDIT_CARD": "[CARD_REDACTED]",
    "API_KEY_SECRET": "[SECRET_KEY]",
    "FINANCIAL_VALUE": "[FINANCIAL_VAL]",
    "CLIENT_WATCHLIST": "[CLIENT_A]",
    "SOURCE_CODE_INDICATOR": "[SOURCE_CODE_REDACTED]"
}

def anonymize_prompt(text: str, entities: List[Dict[str, Any]], redact_pii: bool = True) -> str:
    if not entities:
        return text

    pii_types = {"EMAIL", "PHONE", "US_SSN", "CREDIT_CARD"}
    active_entities = [
        e for e in entities
        if redact_pii or e["type"] not in pii_types
    ]

    if not active_entities:
        return text

    # Sort right to left by span start index
    sorted_entities = sorted(active_entities, key=lambda x: x["span"][0], reverse=True)

    result = text
    for entity in sorted_entities:
        start, end = entity["span"]
        replacement = TOKEN_MAP.get(entity["type"], "[REDACTED]")
        result = result[:start] + replacement + result[end:]

    return result
