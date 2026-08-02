import json
import sqlite3
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import init_db, DB_PATH
from security_engine.risk_scorer import evaluate_security

app = FastAPI(title="Aegis Gateway DLP Proxy", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                pass

manager = ConnectionManager()

# Pydantic Schemas
class ProxyChatRequest(BaseModel):
    employee_id: str
    prompt: str
    attachment_name: Optional[str] = None

class ThreatAssessmentRequest(BaseModel):
    user_input: str

class PolicyUpdate(BaseModel):
    enabled: bool

@app.post("/api/v1/soc/threat-assessment")
async def soc_threat_assessment(req: ThreatAssessmentRequest):
    try:
        from soc_agent import get_threat_assessment
        assessment = get_threat_assessment(req.user_input)
        return {"ok": True, "assessment": assessment}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("startup")
def startup_event():
    init_db()

def get_policies_dict() -> Dict[str, bool]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT key, enabled FROM policies")
    rows = cursor.fetchall()
    conn.close()
    return {r[0]: bool(r[1]) for r in rows}

@app.post("/api/v1/proxy/chat")
async def proxy_chat(req: ProxyChatRequest):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Get employee details
    cursor.execute("SELECT name, department FROM employees WHERE id = ?", (req.employee_id,))
    emp_row = cursor.fetchone()
    if not emp_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Employee not found")

    employee_name, department = emp_row[0], emp_row[1]

    # Load current policies
    policies = get_policies_dict()

    # Run Security Engine
    result = evaluate_security(req.prompt, policies)

    # Generate Mock AI model response based on action
    if result["action"] == "BLOCKED":
        model_response = f"[BLOCKED BY AEGIS GATEWAY POLICY: {', '.join(result['block_reasons'])}]"
    elif result["action"] == "REDACTED":
        model_response = f"I have processed your request safely using anonymized placeholders: \"{result['processed_prompt']}\". Key insights have been synthesized without exposing sensitive entities."
    else:
        model_response = f"I have analyzed your request: \"{req.prompt}\". All safety parameters passed verification."

    # Save to SQLite
    ts = datetime.utcnow().isoformat() + "Z"
    cursor.execute("""
    INSERT INTO activity_log (timestamp, employee_id, employee_name, department, original_prompt, processed_prompt, action, risk_score, entities_found, model_response, attachment_name)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (ts, req.employee_id, employee_name, department, req.prompt, result["processed_prompt"], result["action"], result["risk_score"], json.dumps(result["entities"]), model_response, req.attachment_name))

    log_id = cursor.lastrowid
    conn.commit()

    # Create log object
    log_item = {
        "id": log_id,
        "timestamp": ts,
        "employee_id": req.employee_id,
        "employee_name": employee_name,
        "department": department,
        "original_prompt": req.prompt,
        "processed_prompt": result["processed_prompt"],
        "action": result["action"],
        "risk_score": result["risk_score"],
        "entities_found": result["entities"],
        "model_response": model_response,
        "attachment_name": req.attachment_name
    }

    conn.close()

    # Broadcast over WebSocket
    await manager.broadcast({
        "type": "NEW_ACTIVITY",
        "payload": log_item
    })

    return log_item

@app.get("/api/v1/dashboard/kpis")
def get_dashboard_kpis():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*), AVG(risk_score) FROM activity_log")
    total_row = cursor.fetchone()
    total_intercepted = total_row[0] or 0
    avg_risk = round(total_row[1] or 0, 1)

    cursor.execute("SELECT COUNT(*) FROM activity_log WHERE action = 'BLOCKED'")
    threats_blocked = cursor.fetchone()[0] or 0

    cursor.execute("SELECT COUNT(*) FROM activity_log WHERE action = 'REDACTED'")
    pii_redacted = cursor.fetchone()[0] or 0

    conn.close()

    return {
        "total_intercepted": total_intercepted,
        "threats_blocked": threats_blocked,
        "pii_redacted": pii_redacted,
        "average_risk_score": avg_risk
    }

@app.get("/api/v1/dashboard/activity")
def get_activity_logs():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT id, timestamp, employee_id, employee_name, department, original_prompt, processed_prompt, action, risk_score, entities_found, model_response, attachment_name FROM activity_log ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for r in rows:
        logs.append({
            "id": r[0],
            "timestamp": r[1],
            "employee_id": r[2],
            "employee_name": r[3],
            "department": r[4],
            "original_prompt": r[5],
            "processed_prompt": r[6],
            "action": r[7],
            "risk_score": r[8],
            "entities_found": json.loads(r[9]),
            "model_response": r[10],
            "attachment_name": r[11]
        })
    return logs

@app.get("/api/v1/policies")
def get_policies():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT key, label, description, enabled, category FROM policies")
    rows = cursor.fetchall()
    conn.close()

    return [
        {"key": r[0], "label": r[1], "description": r[2], "enabled": bool(r[3]), "category": r[4]}
        for r in rows
    ]

@app.patch("/api/v1/policies/{key}")
async def update_policy(key: str, body: PolicyUpdate):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE policies SET enabled = ? WHERE key = ?", (1 if body.enabled else 0, key))
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    conn.commit()
    conn.close()

    # Broadcast policy update over WS
    await manager.broadcast({
        "type": "POLICY_UPDATE",
        "payload": {"key": key, "enabled": body.enabled}
    })

    return {"status": "ok", "key": key, "enabled": body.enabled}

@app.get("/api/v1/employees")
def get_employees():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, department, role, avatar_color, email FROM employees")
    rows = cursor.fetchall()
    conn.close()

    return [
        {"id": r[0], "name": r[1], "department": r[2], "role": r[3], "avatar_color": r[4], "email": r[5]}
        for r in rows
    ]

@app.websocket("/ws/live-feed")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
