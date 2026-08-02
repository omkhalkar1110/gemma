import re
from typing import List, Dict, Any, Tuple

DEFAULT_WATCHLIST = ["Apple", "Project Titan", "Northwind Corp", "Apex Capital", "Sovereign AI"]

def validate_luhn(card_number: str) -> bool:
    clean_num = re.sub(r'\D', '', card_number)
    if len(clean_num) < 13 or len(clean_num) > 19:
        return False
    total = 0
    reverse_digits = clean_num[::-1]
    for i, char in enumerate(reverse_digits):
        n = int(char)
        if i % 2 == 1:
            n = n * 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0

def analyze_prompt(text: str, custom_watchlist: List[str] = None) -> List[Dict[str, Any]]:
    if custom_watchlist is None:
        custom_watchlist = DEFAULT_WATCHLIST

    matches = []

    def add_match(entity_type: str, value: str, span: Tuple[int, int], description: str = ""):
        # Avoid overlapping span
        for existing in matches:
            ex_span = existing["span"]
            if (span[0] >= ex_span[0] and span[0] < ex_span[1]) or (span[1] > ex_span[0] and span[1] <= ex_span[1]):
                return
        matches.append({
            "type": entity_type,
            "value": value,
            "span": [span[0], span[1]],
            "confidence": 0.95,
            "description": description or f"Detected {entity_type}"
        })

    # 1. CREDIT_CARD
    card_regex = re.compile(r'\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|6(?:011|5\d\d)\d{12}|3[47]\d{13}|\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4})\b')
    for m in card_regex.finditer(text):
        if validate_luhn(m.group(0)):
            add_match("CREDIT_CARD", m.group(0), m.span(), "Luhn verified credit card")

    # 2. US_SSN
    ssn_regex = re.compile(r'\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b')
    for m in ssn_regex.finditer(text):
        add_match("US_SSN", m.group(0), m.span(), "US Social Security Number")

    # 3. API_KEY_SECRET
    key_patterns = [
        re.compile(r'sk-(?:proj-)?[a-zA-Z0-9_-]{20,}'),
        re.compile(r'\b(?:AKIA|ASIA)[0-9A-Z]{16}\b'),
        re.compile(r'\bgh[pousr]_[a-zA-Z0-9]{36}\b'),
        re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----'),
        re.compile(r'(?:api_key|secret_key|private_key|auth_token|bearer)\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{16,})["\']?', re.IGNORECASE)
    ]
    for pattern in key_patterns:
        for m in pattern.finditer(text):
            add_match("API_KEY_SECRET", m.group(0), m.span(), "API Key or Secret Token")

    # 4. EMAIL
    email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
    for m in email_regex.finditer(text):
        add_match("EMAIL", m.group(0), m.span(), "Personal or Corporate Email Address")

    # 5. PHONE
    phone_regex = re.compile(r'\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
    for m in phone_regex.finditer(text):
        add_match("PHONE", m.group(0), m.span(), "Phone Number")

    # 6. FINANCIAL_VALUE
    fin_regex = re.compile(r'\b(?:\$|€|£|USD\s?|EUR\s?)\d{1,3}(?:,\d{3})*(?:\.\d+)?(?:\s?(?:million|billion|M|B|k|K))?\b|\b\d+(?:\.\d+)?\s?(?:million|billion|M|B|k|K)\s?(?:USD|EUR|dollars)?\b', re.IGNORECASE)
    for m in fin_regex.finditer(text):
        add_match("FINANCIAL_VALUE", m.group(0), m.span(), "Financial Amount or Valuation Exposure")

    # 7. CLIENT_WATCHLIST
    for client in custom_watchlist:
        escaped = re.escape(client)
        client_regex = re.compile(r'\b' + escaped + r'\b', re.IGNORECASE)
        for m in client_regex.finditer(text):
            add_match("CLIENT_WATCHLIST", m.group(0), m.span(), f"Watchlist Client: {client}")

    # 8. SOURCE_CODE_INDICATOR
    code_patterns = [
        re.compile(r'\b(?:import|export)\s+[\s\S]*?\s+from\s+["\'].*?["\']'),
        re.compile(r'\b(?:function|const|let|var|class|def|async\s+function)\s+[a-zA-Z0-9_]+\s*\(.*?\)'),
        re.compile(r'\bSELECT\s+.*?\s+FROM\s+[a-zA-Z0-9_]+', re.IGNORECASE),
        re.compile(r'process\.env\.[A-zA-Z0-9_]+'),
        re.compile(r'eval\(.*?\)'),
        re.compile(r'<script[\s\S]*?>[\s\S]*?<\/script>', re.IGNORECASE)
    ]
    for pattern in code_patterns:
        for m in pattern.finditer(text):
            add_match("SOURCE_CODE_INDICATOR", m.group(0), m.span(), "Source Code Construct")

    matches.sort(key=lambda x: x["span"][0])
    return matches
