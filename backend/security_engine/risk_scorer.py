from typing import List, Dict, Any
from .analyzer import analyze_prompt
from .anonymizer import anonymize_prompt

def evaluate_security(original_prompt: str, policies: Dict[str, bool], custom_watchlist: List[str] = None) -> Dict[str, Any]:
    entities = analyze_prompt(original_prompt, custom_watchlist)

    raw_score = 0
    block_reasons = []
    matched_policies = []

    has_financial = False
    has_source_code = False
    has_secrets_or_ssn = False

    for entity in entities:
        t = entity["type"]
        if t == "API_KEY_SECRET":
            raw_score += 35
            has_secrets_or_ssn = True
        elif t == "US_SSN":
            raw_score += 30
            has_secrets_or_ssn = True
        elif t == "CREDIT_CARD":
            raw_score += 30
            has_secrets_or_ssn = True
        elif t == "FINANCIAL_VALUE":
            raw_score += 25
            has_financial = True
        elif t == "CLIENT_WATCHLIST":
            raw_score += 20
        elif t == "SOURCE_CODE_INDICATOR":
            raw_score += 15
            has_source_code = True
        elif t in ("EMAIL", "PHONE"):
            raw_score += 10

    risk_score = min(100, raw_score)
    action = "ALLOWED"

    if policies.get("block_financial", False) and has_financial:
        action = "BLOCKED"
        block_reasons.append("Contains prohibited financial values or revenue exposure.")
        matched_policies.append("block_financial")

    if policies.get("block_source_code", False) and has_source_code:
        action = "BLOCKED"
        block_reasons.append("Contains proprietary source code or system constructs.")
        matched_policies.append("block_source_code")

    if policies.get("strict_zero_trust", False) and (risk_score >= 30 or has_secrets_or_ssn):
        action = "BLOCKED"
        block_reasons.append("Strict Zero-Trust policy violated (risk score >= 30 or sensitive credentials).")
        matched_policies.append("strict_zero_trust")

    if risk_score >= 75 and action != "BLOCKED":
        action = "BLOCKED"
        block_reasons.append("Overall risk score exceeded maximum threshold (75/100).")
        matched_policies.append("max_risk_threshold")

    if action != "BLOCKED" and entities:
        if policies.get("redact_pii", True):
            action = "REDACTED"
            matched_policies.append("redact_pii")

    processed_prompt = original_prompt
    if action == "BLOCKED":
        processed_prompt = f"[PROMPT BLOCKED BY AEGIS GATEWAY POLICY: {' '.join(block_reasons)}]"
    elif action == "REDACTED":
        processed_prompt = anonymize_prompt(original_prompt, entities, policies.get("redact_pii", True))

    return {
        "original_prompt": original_prompt,
        "processed_prompt": processed_prompt,
        "action": action,
        "risk_score": risk_score,
        "entities": entities,
        "matched_policies": matched_policies,
        "block_reasons": block_reasons
    }
