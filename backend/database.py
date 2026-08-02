import sqlite3
import json
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "aegis.db")

SEED_EMPLOYEES = [
    {"id": "E001", "name": "Sarah Chen", "department": "Engineering", "role": "Lead Backend Engineer", "avatar_color": "#3B82F6", "email": "sarah.chen@aegis.internal"},
    {"id": "E002", "name": "Marcus Vance", "department": "Finance", "role": "VP Financial Planning", "avatar_color": "#10B981", "email": "marcus.vance@aegis.internal"},
    {"id": "E003", "name": "Elena Rostova", "department": "Product", "role": "Principal Product Manager", "avatar_color": "#8B5CF6", "email": "elena.rostova@aegis.internal"},
    {"id": "E004", "name": "David Kim", "department": "Legal", "role": "Chief Compliance Officer", "avatar_color": "#F59E0B", "email": "david.kim@aegis.internal"},
    {"id": "E005", "name": "Alex Wright", "department": "Executive", "role": "Chief Technology Officer", "avatar_color": "#EC4899", "email": "alex.wright@aegis.internal"}
]

SEED_POLICIES = [
    {"key": "redact_pii", "label": "Redact PII & Secrets", "description": "Automatically mask email, phone, SSN, credit cards, and API keys with bracketed tokens.", "enabled": 1, "category": "pii"},
    {"key": "block_financial", "label": "Block Financial Exposure", "description": "Strictly block prompts containing revenue figures, market valuations, and financial forecasts.", "enabled": 1, "category": "compliance"},
    {"key": "block_source_code", "label": "Block Source Code Leaks", "description": "Prevent sending proprietary source code, credentials, and internal API logic to public LLMs.", "enabled": 0, "category": "security"},
    {"key": "strict_zero_trust", "label": "Strict Zero-Trust Mode", "description": "Enforce zero-trust blocking on any prompt exceeding a risk score threshold of 30.", "enabled": 0, "category": "zero_trust"}
]

SEED_LOGS = [
    {
        "employee_id": "E001",
        "employee_name": "Sarah Chen",
        "department": "Engineering",
        "original_prompt": "Debug this auth helper: const key = 'sk-proj-9481726354189201928374'; function verify() { return eval(key); }",
        "processed_prompt": "Debug this auth helper: const key = '[SECRET_KEY]'; function verify() { return [SOURCE_CODE_REDACTED]; }",
        "action": "REDACTED",
        "risk_score": 50,
        "entities_found": json.dumps([
            {"type": "API_KEY_SECRET", "value": "sk-proj-9481726354189201928374", "span": [23, 53], "confidence": 0.95},
            {"type": "SOURCE_CODE_INDICATOR", "value": "function verify() { return eval(key); }", "span": [55, 94], "confidence": 0.95}
        ]),
        "model_response": "I see the authentication helper script. The API key has been redacted to [SECRET_KEY]. Make sure to store credentials in environment variables rather than hardcoding.",
        "attachment_name": "auth_service.py",
        "minutes_ago": 12
    },
    {
        "employee_id": "E002",
        "employee_name": "Marcus Vance",
        "department": "Finance",
        "original_prompt": "Summarize Q3 revenue report for Apple: Total quarterly revenue reached $45 million with an EBITDA margin of 28%.",
        "processed_prompt": "[PROMPT BLOCKED BY AEGIS GATEWAY POLICY: Contains prohibited financial values or revenue exposure.]",
        "action": "BLOCKED",
        "risk_score": 70,
        "entities_found": json.dumps([
            {"type": "CLIENT_WATCHLIST", "value": "Apple", "span": [36, 41], "confidence": 0.95},
            {"type": "FINANCIAL_VALUE", "value": "$45 million", "span": [68, 79], "confidence": 0.95}
        ]),
        "model_response": "[BLOCKED BY AEGIS GATEWAY POLICY: Prompt contained prohibited financial exposure ($45 million) for client Apple]",
        "attachment_name": "Q3_Revenue_Apple.pdf",
        "minutes_ago": 28
    },
    {
        "employee_id": "E003",
        "employee_name": "Elena Rostova",
        "department": "Product",
        "original_prompt": "Draft customer launch email for Project Titan features. Contact elena.rostova@aegis.internal or call 415-555-0199.",
        "processed_prompt": "Draft customer launch email for [CLIENT_A] features. Contact [EMAIL_REDACTED] or call [PHONE_REDACTED].",
        "action": "REDACTED",
        "risk_score": 40,
        "entities_found": json.dumps([
            {"type": "CLIENT_WATCHLIST", "value": "Project Titan", "span": [33, 46], "confidence": 0.95},
            {"type": "EMAIL", "value": "elena.rostova@aegis.internal", "span": [65, 93], "confidence": 0.95},
            {"type": "PHONE", "value": "415-555-0199", "span": [102, 114], "confidence": 0.95}
        ]),
        "model_response": "Subject: Welcome to [CLIENT_A] New Features!\n\nDear Partner,\n\nWe are excited to share new capabilities. For inquiries, reach out to our team at [EMAIL_REDACTED].",
        "attachment_name": None,
        "minutes_ago": 45
    },
    {
        "employee_id": "E004",
        "employee_name": "David Kim",
        "department": "Legal",
        "original_prompt": "Is the privacy policy compliant with CCPA standards regarding data deletion requests?",
        "processed_prompt": "Is the privacy policy compliant with CCPA standards regarding data deletion requests?",
        "action": "ALLOWED",
        "risk_score": 0,
        "entities_found": json.dumps([]),
        "model_response": "Yes, standard CCPA compliance requires providing consumers a clear mechanism to submit verifiable consumer requests for data deletion within 45 days.",
        "attachment_name": None,
        "minutes_ago": 60
    },
    {
        "employee_id": "E002",
        "employee_name": "Marcus Vance",
        "department": "Finance",
        "original_prompt": "Process refund for credit card 4532-0158-9231-8841 belonging to customer SSN 123-45-6789.",
        "processed_prompt": "Process refund for credit card [CARD_REDACTED] belonging to customer SSN [SSN_REDACTED].",
        "action": "REDACTED",
        "risk_score": 60,
        "entities_found": json.dumps([
            {"type": "CREDIT_CARD", "value": "4532-0158-9231-8841", "span": [31, 50], "confidence": 0.95},
            {"type": "US_SSN", "value": "123-45-6789", "span": [76, 87], "confidence": 0.95}
        ]),
        "model_response": "I have processed the refund confirmation template for card [CARD_REDACTED] and account [SSN_REDACTED].",
        "attachment_name": "customer_export.csv",
        "minutes_ago": 95
    },
    {
        "employee_id": "E005",
        "employee_name": "Alex Wright",
        "department": "Executive",
        "original_prompt": "Review architecture overview for Project Shield cloud migration strategy.",
        "processed_prompt": "Review architecture overview for [CLIENT_A] cloud migration strategy.",
        "action": "REDACTED",
        "risk_score": 20,
        "entities_found": json.dumps([
            {"type": "CLIENT_WATCHLIST", "value": "Project Shield", "span": [33, 47], "confidence": 0.95}
        ]),
        "model_response": "The cloud migration strategy for [CLIENT_A] outlines a multi-stage zero-downtime transition to isolated cloud instances.",
        "attachment_name": None,
        "minutes_ago": 120
    },
    {
        "employee_id": "E001",
        "employee_name": "Sarah Chen",
        "department": "Engineering",
        "original_prompt": "AWS_ACCESS_KEY_ID = AKIAIOSFODNN7EXAMPLE. Please convert this into terraform format.",
        "processed_prompt": "AWS_ACCESS_KEY_ID = [SECRET_KEY]. Please convert this into terraform format.",
        "action": "REDACTED",
        "risk_score": 35,
        "entities_found": json.dumps([
            {"type": "API_KEY_SECRET", "value": "AKIAIOSFODNN7EXAMPLE", "span": [20, 40], "confidence": 0.95}
        ]),
        "model_response": "Here is the Terraform variable definition for the AWS access credential using environment secret injection:\n\nvariable \"aws_access_key\" {\n  type = string\n  sensitive = true\n}",
        "attachment_name": "internal_api_keys.txt",
        "minutes_ago": 150
    },
    {
        "employee_id": "E003",
        "employee_name": "Elena Rostova",
        "department": "Product",
        "original_prompt": "Compare agile sprint velocity metrics for the past three engineering cycles.",
        "processed_prompt": "Compare agile sprint velocity metrics for the past three engineering cycles.",
        "action": "ALLOWED",
        "risk_score": 0,
        "entities_found": json.dumps([]),
        "model_response": "Engineering sprint velocity averaged 42 story points per cycle, representing a 12% improvement in throughput over the last quarter.",
        "attachment_name": None,
        "minutes_ago": 180
    },
    {
        "employee_id": "E004",
        "employee_name": "David Kim",
        "department": "Legal",
        "original_prompt": "Review contract terms for Northwind Corp agreement totaling $1.5 million in licensing fees.",
        "processed_prompt": "[PROMPT BLOCKED BY AEGIS GATEWAY POLICY: Contains prohibited financial values or revenue exposure.]",
        "action": "BLOCKED",
        "risk_score": 65,
        "entities_found": json.dumps([
            {"type": "CLIENT_WATCHLIST", "value": "Northwind Corp", "span": [26, 40], "confidence": 0.95},
            {"type": "FINANCIAL_VALUE", "value": "$1.5 million", "span": [60, 72], "confidence": 0.95}
        ]),
        "model_response": "[BLOCKED BY AEGIS GATEWAY POLICY: Prompt contained prohibited financial exposure ($1.5 million) for client Northwind Corp]",
        "attachment_name": None,
        "minutes_ago": 210
    }
]

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS employees (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        department TEXT NOT NULL,
        role TEXT NOT NULL,
        avatar_color TEXT NOT NULL,
        email TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS policies (
        key TEXT PRIMARY KEY,
        label TEXT NOT NULL,
        description TEXT NOT NULL,
        enabled INTEGER NOT NULL,
        category TEXT NOT NULL
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS activity_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        employee_id TEXT NOT NULL,
        employee_name TEXT NOT NULL,
        department TEXT NOT NULL,
        original_prompt TEXT NOT NULL,
        processed_prompt TEXT NOT NULL,
        action TEXT NOT NULL,
        risk_score INTEGER NOT NULL,
        entities_found TEXT NOT NULL,
        model_response TEXT NOT NULL,
        attachment_name TEXT
    )
    """)

    # Seed Employees if empty
    cursor.execute("SELECT COUNT(*) FROM employees")
    if cursor.fetchone()[0] == 0:
        for emp in SEED_EMPLOYEES:
            cursor.execute("INSERT INTO employees VALUES (?, ?, ?, ?, ?, ?)",
                           (emp["id"], emp["name"], emp["department"], emp["role"], emp["avatar_color"], emp["email"]))

    # Seed Policies if empty
    cursor.execute("SELECT COUNT(*) FROM policies")
    if cursor.fetchone()[0] == 0:
        for pol in SEED_POLICIES:
            cursor.execute("INSERT INTO policies VALUES (?, ?, ?, ?, ?)",
                           (pol["key"], pol["label"], pol["description"], pol["enabled"], pol["category"]))

    # Seed Activity Log if empty
    cursor.execute("SELECT COUNT(*) FROM activity_log")
    if cursor.fetchone()[0] == 0:
        now = datetime.utcnow()
        for log in SEED_LOGS:
            ts = (now - timedelta(minutes=log["minutes_ago"])).isoformat() + "Z"
            cursor.execute("""
            INSERT INTO activity_log (timestamp, employee_id, employee_name, department, original_prompt, processed_prompt, action, risk_score, entities_found, model_response, attachment_name)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (ts, log["employee_id"], log["employee_name"], log["department"], log["original_prompt"], log["processed_prompt"], log["action"], log["risk_score"], log["entities_found"], log["model_response"], log["attachment_name"]))

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database aegis.db initialized and seeded.")
