import initSqlJs, { Database } from 'sql.js';
import fs from 'fs';
import path from 'path';

// On Vercel / serverless environments, process.cwd() is read-only, so write DB to /tmp
const DB_FILE = process.env.VERCEL || process.env.TMPDIR
  ? path.join('/tmp', 'aegis.db')
  : path.join(process.cwd(), 'aegis.db');

let dbInstance: any = null;

async function createSqlInstance(): Promise<any> {
  try {
    const locateFile = (file: string) => {
      const currentDir = typeof __dirname !== 'undefined' ? __dirname : process.cwd();
      const candidates = [
        path.join(process.cwd(), 'node_modules', 'sql.js', 'dist', file),
        path.join(currentDir, '..', '..', 'node_modules', 'sql.js', 'dist', file),
        path.join(currentDir, '..', 'node_modules', 'sql.js', 'dist', file)
      ];
      for (const cand of candidates) {
        try {
          if (fs.existsSync(cand)) return cand;
        } catch (_) {}
      }
      return file;
    };

    let wasmBinary: Buffer | undefined;
    const wasmPath = locateFile('sql-wasm.wasm');
    if (fs.existsSync(wasmPath)) {
      wasmBinary = fs.readFileSync(wasmPath);
    }

    const SQL = await initSqlJs({ locateFile, wasmBinary });
    if (fs.existsSync(DB_FILE)) {
      try {
        const filebuffer = fs.readFileSync(DB_FILE);
        if (filebuffer && filebuffer.length >= 16) {
          const header = filebuffer.toString('utf8', 0, 16);
          if (header === 'SQLite format 3\0') {
            const db = new SQL.Database(filebuffer);
            db.exec('SELECT count(*) FROM sqlite_master;');
            return db;
          }
        }
        // If header is invalid or corrupted, quietly unlink
        try { if (fs.existsSync(DB_FILE)) fs.unlinkSync(DB_FILE); } catch (_) {}
      } catch (_) {
        try { if (fs.existsSync(DB_FILE)) fs.unlinkSync(DB_FILE); } catch (_) {}
      }
    }
    return new SQL.Database();
  } catch (err) {
    console.error('[Aegis DB] Primary WASM sql.js init failed, trying fallback init:', err);
    try {
      const SQL = await initSqlJs();
      return new SQL.Database();
    } catch (fallbackErr) {
      console.error('[Aegis DB] All WASM init attempts failed, creating JS Memory DB fallback:', fallbackErr);
      return createJsMemoryDb();
    }
  }
}

// Minimal In-Memory JavaScript DB Fallback if WASM is unavailable
function createJsMemoryDb() {
  const employeesMap = new Map<string, any>([
    ['E001', { id: 'E001', name: 'Sarah Chen', department: 'Engineering', role: 'Lead Backend Engineer', avatar_color: '#3B82F6', email: 'sarah.chen@aegis.internal' }],
    ['E002', { id: 'E002', name: 'Marcus Vance', department: 'Finance', role: 'VP Financial Planning', avatar_color: '#10B981', email: 'marcus.vance@aegis.internal' }],
    ['E003', { id: 'E003', name: 'Elena Rostova', department: 'Product', role: 'Principal Product Manager', avatar_color: '#8B5CF6', email: 'elena.rostova@aegis.internal' }],
    ['E004', { id: 'E004', name: 'David Kim', department: 'Legal', role: 'Chief Compliance Officer', avatar_color: '#F59E0B', email: 'david.kim@aegis.internal' }],
    ['E005', { id: 'E005', name: 'Alex Wright', department: 'Executive', role: 'Chief Technology Officer', avatar_color: '#EC4899', email: 'alex.wright@aegis.internal' }]
  ]);

  const policiesMap = new Map<string, any>([
    ['redact_pii', { key: 'redact_pii', label: 'Redact PII & Secrets', description: 'Automatically mask email, phone, SSN, credit cards, and API keys with bracketed tokens.', enabled: 1, category: 'pii' }],
    ['block_financial', { key: 'block_financial', label: 'Block Financial Exposure', description: 'Strictly block prompts containing revenue figures, market valuations, and financial forecasts.', enabled: 1, category: 'compliance' }],
    ['block_source_code', { key: 'block_source_code', label: 'Block Source Code Leaks', description: 'Prevent sending proprietary source code, credentials, and internal API logic to public LLMs.', enabled: 0, category: 'security' }],
    ['strict_zero_trust', { key: 'strict_zero_trust', label: 'Strict Zero-Trust Mode', description: 'Enforce zero-trust blocking on any prompt exceeding a risk score threshold of 30.', enabled: 0, category: 'zero_trust' }]
  ]);

  const logs: any[] = [];
  let logAutoInc = 1;

  const now = new Date();
  const subMin = (mins: number) => new Date(now.getTime() - mins * 60000).toISOString();

  const seedLogs = [
    {
      ts: subMin(12), emp_id: 'E001', emp_name: 'Sarah Chen', dept: 'Engineering',
      orig: "Debug this auth helper: const key = 'sk-proj-9481726354189201928374'; function verify() { return eval(key); }",
      proc: "Debug this auth helper: const key = '[SECRET_KEY]'; function verify() { return [SOURCE_CODE_REDACTED]; }",
      act: 'REDACTED', risk: 50,
      entities: JSON.stringify([
        { type: 'API_KEY_SECRET', value: 'sk-proj-9481726354189201928374', span: [23, 53], confidence: 0.95 },
        { type: 'SOURCE_CODE_INDICATOR', value: 'function verify() { return eval(key); }', span: [55, 94], confidence: 0.95 }
      ]),
      resp: 'I see the authentication helper script. The API key has been redacted to [SECRET_KEY]. Make sure to store credentials in environment variables rather than hardcoding.',
      att: 'auth_service.py'
    },
    {
      ts: subMin(28), emp_id: 'E002', emp_name: 'Marcus Vance', dept: 'Finance',
      orig: 'Summarize Q3 revenue report for Apple: Total quarterly revenue reached $45 million with an EBITDA margin of 28%.',
      proc: '[PROMPT BLOCKED BY AEGIS GATEWAY POLICY: Contains prohibited financial values or revenue exposure.]',
      act: 'BLOCKED', risk: 70,
      entities: JSON.stringify([
        { type: 'CLIENT_WATCHLIST', value: 'Apple', span: [36, 41], confidence: 0.95 },
        { type: 'FINANCIAL_VALUE', value: '$45 million', span: [68, 79], confidence: 0.95 }
      ]),
      resp: '[BLOCKED BY AEGIS GATEWAY POLICY: Prompt contained prohibited financial exposure ($45 million) for client Apple]',
      att: 'Q3_Revenue_Apple.pdf'
    },
    {
      ts: subMin(45), emp_id: 'E003', emp_name: 'Elena Rostova', dept: 'Product',
      orig: 'Draft customer launch email for Project Titan features. Contact elena.rostova@aegis.internal or call 415-555-0199.',
      proc: 'Draft customer launch email for [CLIENT_A] features. Contact [EMAIL_REDACTED] or call [PHONE_REDACTED].',
      act: 'REDACTED', risk: 40,
      entities: JSON.stringify([
        { type: 'CLIENT_WATCHLIST', value: 'Project Titan', span: [33, 46], confidence: 0.95 },
        { type: 'EMAIL', value: 'elena.rostova@aegis.internal', span: [65, 93], confidence: 0.95 },
        { type: 'PHONE', value: '415-555-0199', span: [102, 114], confidence: 0.95 }
      ]),
      resp: 'Subject: Welcome to [CLIENT_A] New Features!\n\nDear Partner,\n\nWe are excited to share new capabilities.',
      att: null
    },
    {
      ts: subMin(60), emp_id: 'E004', emp_name: 'David Kim', dept: 'Legal',
      orig: 'Is the privacy policy compliant with CCPA standards regarding data deletion requests?',
      proc: 'Is the privacy policy compliant with CCPA standards regarding data deletion requests?',
      act: 'ALLOWED', risk: 0, entities: JSON.stringify([]),
      resp: 'Yes, standard CCPA compliance requires providing consumers a clear mechanism to submit verifiable consumer requests.',
      att: null
    }
  ];

  for (const sl of seedLogs) {
    logs.push({
      id: logAutoInc++,
      timestamp: sl.ts,
      employee_id: sl.emp_id,
      employee_name: sl.emp_name,
      department: sl.dept,
      original_prompt: sl.orig,
      processed_prompt: sl.proc,
      action: sl.act,
      risk_score: sl.risk,
      entities_found: sl.entities,
      model_response: sl.resp,
      attachment_name: sl.att
    });
  }

  return {
    run: (sql: string, params: any[] = []) => {
      const s = sql.trim().toUpperCase();
      if (s.startsWith('INSERT INTO ACTIVITY_LOG')) {
        logs.push({
          id: logAutoInc++,
          timestamp: params[0],
          employee_id: params[1],
          employee_name: params[2],
          department: params[3],
          original_prompt: params[4],
          processed_prompt: params[5],
          action: params[6],
          risk_score: params[7],
          entities_found: params[8],
          model_response: params[9],
          attachment_name: params[10]
        });
      } else if (s.startsWith('UPDATE POLICIES')) {
        const enabled = params[0];
        const key = params[1];
        if (policiesMap.has(key)) {
          policiesMap.get(key).enabled = enabled;
        }
      }
    },
    exec: (sql: string, params: any[] = []) => {
      const s = sql.trim().toUpperCase();
      if (s.includes('COUNT(*)') && s.includes('EMPLOYEES')) {
        return [{ columns: ['COUNT(*)'], values: [[employeesMap.size]] }];
      }
      if (s.includes('COUNT(*)') && s.includes('ACTIVITY_LOG')) {
        let filtered = logs;
        if (s.includes("ACTION = 'BLOCKED'")) filtered = logs.filter(l => l.action === 'BLOCKED');
        else if (s.includes("ACTION = 'REDACTED'")) filtered = logs.filter(l => l.action === 'REDACTED');

        if (s.includes('AVG(RISK_SCORE)')) {
          const avg = logs.length > 0 ? logs.reduce((acc, l) => acc + l.risk_score, 0) / logs.length : 0;
          return [{ columns: ['COUNT(*)', 'AVG(risk_score)'], values: [[logs.length, avg]] }];
        }
        return [{ columns: ['COUNT(*)'], values: [[filtered.length]] }];
      }
      if (s.includes('SELECT KEY, ENABLED FROM POLICIES')) {
        const rows = Array.from(policiesMap.values()).map(p => [p.key, p.enabled]);
        return [{ columns: ['key', 'enabled'], values: rows }];
      }
      if (s.includes('SELECT KEY, LABEL, DESCRIPTION, ENABLED, CATEGORY FROM POLICIES')) {
        const rows = Array.from(policiesMap.values()).map(p => [p.key, p.label, p.description, p.enabled, p.category]);
        return [{ columns: ['key', 'label', 'description', 'enabled', 'category'], values: rows }];
      }
      if (s.includes('SELECT ID, NAME, DEPARTMENT, ROLE, AVATAR_COLOR, EMAIL FROM EMPLOYEES')) {
        const rows = Array.from(employeesMap.values()).map(e => [e.id, e.name, e.department, e.role, e.avatar_color, e.email]);
        return [{ columns: ['id', 'name', 'department', 'role', 'avatar_color', 'email'], values: rows }];
      }
      if (s.includes('SELECT NAME, DEPARTMENT FROM EMPLOYEES')) {
        const empId = params[0];
        const emp = employeesMap.get(empId) || Array.from(employeesMap.values())[0];
        return emp ? [{ columns: ['name', 'department'], values: [[emp.name, emp.department]] }] : [];
      }
      if (s.includes('SELECT ENTITIES_FOUND, RISK_SCORE, ACTION FROM ACTIVITY_LOG')) {
        const rows = logs.map(l => [l.entities_found, l.risk_score, l.action]);
        return [{ columns: ['entities_found', 'risk_score', 'action'], values: rows }];
      }
      if (s.includes('SELECT ID, TIMESTAMP, EMPLOYEE_ID, EMPLOYEE_NAME, DEPARTMENT, ORIGINAL_PROMPT, PROCESSED_PROMPT, ACTION, RISK_SCORE, ENTITIES_FOUND, MODEL_RESPONSE, ATTACHMENT_NAME FROM ACTIVITY_LOG')) {
        const sorted = [...logs].reverse();
        const rows = sorted.map(r => [r.id, r.timestamp, r.employee_id, r.employee_name, r.department, r.original_prompt, r.processed_prompt, r.action, r.risk_score, r.entities_found, r.model_response, r.attachment_name]);
        return [{ columns: ['id', 'timestamp', 'employee_id', 'employee_name', 'department', 'original_prompt', 'processed_prompt', 'action', 'risk_score', 'entities_found', 'model_response', 'attachment_name'], values: rows }];
      }
      if (s.includes('LAST_INSERT_ROWID()')) {
        return [{ columns: ['last_insert_rowid()'], values: [[logs[logs.length - 1]?.id || 1]] }];
      }
      return [];
    },
    export: () => new Uint8Array()
  };
}

function seedSchema(db: any) {
  db.run(`
    CREATE TABLE IF NOT EXISTS employees (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      department TEXT NOT NULL,
      role TEXT NOT NULL,
      avatar_color TEXT NOT NULL,
      email TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS policies (
      key TEXT PRIMARY KEY,
      label TEXT NOT NULL,
      description TEXT NOT NULL,
      enabled INTEGER NOT NULL,
      category TEXT NOT NULL
    );

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
    );
  `);

  const empCountRes = db.exec('SELECT COUNT(*) FROM employees');
  const empCount = empCountRes[0]?.values[0]?.[0] as number || 0;

  if (empCount === 0) {
    db.run(`
      INSERT INTO employees VALUES
      ('E001', 'Sarah Chen', 'Engineering', 'Lead Backend Engineer', '#3B82F6', 'sarah.chen@aegis.internal'),
      ('E002', 'Marcus Vance', 'Finance', 'VP Financial Planning', '#10B981', 'marcus.vance@aegis.internal'),
      ('E003', 'Elena Rostova', 'Product', 'Principal Product Manager', '#8B5CF6', 'elena.rostova@aegis.internal'),
      ('E004', 'David Kim', 'Legal', 'Chief Compliance Officer', '#F59E0B', 'david.kim@aegis.internal'),
      ('E005', 'Alex Wright', 'Executive', 'Chief Technology Officer', '#EC4899', 'alex.wright@aegis.internal');
    `);

    db.run(`
      INSERT INTO policies VALUES
      ('redact_pii', 'Redact PII & Secrets', 'Automatically mask email, phone, SSN, credit cards, and API keys with bracketed tokens.', 1, 'pii'),
      ('block_financial', 'Block Financial Exposure', 'Strictly block prompts containing revenue figures, market valuations, and financial forecasts.', 0, 'compliance'),
      ('block_source_code', 'Block Source Code Leaks', 'Prevent sending proprietary source code, credentials, and internal API logic to public LLMs.', 0, 'security'),
      ('strict_zero_trust', 'Strict Zero-Trust Mode', 'Enforce zero-trust blocking on any prompt exceeding a risk score threshold of 30.', 0, 'zero_trust');
    `);

    // Ensure block_financial is updated to 0 so token masking takes effect
    db.run("UPDATE policies SET enabled = 0 WHERE key = 'block_financial'");

    const now = new Date();
    const subMin = (mins: number) => new Date(now.getTime() - mins * 60000).toISOString();

    const logs = [
      {
        ts: subMin(12), emp_id: 'E001', emp_name: 'Sarah Chen', dept: 'Engineering',
        orig: "Debug this auth helper: const key = 'sk-proj-9481726354189201928374'; function verify() { return eval(key); }",
        proc: "Debug this auth helper: const key = '[SECRET_KEY]'; function verify() { return [SOURCE_CODE_REDACTED]; }",
        act: 'REDACTED', risk: 50,
        entities: JSON.stringify([
          { type: 'API_KEY_SECRET', value: 'sk-proj-9481726354189201928374', span: [23, 53], confidence: 0.95 },
          { type: 'SOURCE_CODE_INDICATOR', value: 'function verify() { return eval(key); }', span: [55, 94], confidence: 0.95 }
        ]),
        resp: 'I see the authentication helper script. The API key has been redacted to [SECRET_KEY]. Make sure to store credentials in environment variables rather than hardcoding.',
        att: 'auth_service.py'
      },
      {
        ts: subMin(28), emp_id: 'E002', emp_name: 'Marcus Vance', dept: 'Finance',
        orig: 'Summarize Q3 revenue report for Apple: Total quarterly revenue reached $45 million with an EBITDA margin of 28%.',
        proc: '[PROMPT BLOCKED BY AEGIS GATEWAY POLICY: Contains prohibited financial values or revenue exposure.]',
        act: 'BLOCKED', risk: 70,
        entities: JSON.stringify([
          { type: 'CLIENT_WATCHLIST', value: 'Apple', span: [36, 41], confidence: 0.95 },
          { type: 'FINANCIAL_VALUE', value: '$45 million', span: [68, 79], confidence: 0.95 }
        ]),
        resp: '[BLOCKED BY AEGIS GATEWAY POLICY: Prompt contained prohibited financial exposure ($45 million) for client Apple]',
        att: 'Q3_Revenue_Apple.pdf'
      },
      {
        ts: subMin(45), emp_id: 'E003', emp_name: 'Elena Rostova', dept: 'Product',
        orig: 'Draft customer launch email for Project Titan features. Contact elena.rostova@aegis.internal or call 415-555-0199.',
        proc: 'Draft customer launch email for [CLIENT_A] features. Contact [EMAIL_REDACTED] or call [PHONE_REDACTED].',
        act: 'REDACTED', risk: 40,
        entities: JSON.stringify([
          { type: 'CLIENT_WATCHLIST', value: 'Project Titan', span: [33, 46], confidence: 0.95 },
          { type: 'EMAIL', value: 'elena.rostova@aegis.internal', span: [65, 93], confidence: 0.95 },
          { type: 'PHONE', value: '415-555-0199', span: [102, 114], confidence: 0.95 }
        ]),
        resp: 'Subject: Welcome to [CLIENT_A] New Features!\n\nDear Partner,\n\nWe are excited to share new capabilities. For inquiries, reach out to our team at [EMAIL_REDACTED].',
        att: null
      },
      {
        ts: subMin(60), emp_id: 'E004', emp_name: 'David Kim', dept: 'Legal',
        orig: 'Is the privacy policy compliant with CCPA standards regarding data deletion requests?',
        proc: 'Is the privacy policy compliant with CCPA standards regarding data deletion requests?',
        act: 'ALLOWED', risk: 0, entities: JSON.stringify([]),
        resp: 'Yes, standard CCPA compliance requires providing consumers a clear mechanism to submit verifiable consumer requests for data deletion within 45 days.',
        att: null
      },
      {
        ts: subMin(95), emp_id: 'E002', emp_name: 'Marcus Vance', dept: 'Finance',
        orig: 'Process refund for credit card 4532-0158-9231-8841 belonging to customer SSN 123-45-6789.',
        proc: 'Process refund for credit card [CARD_REDACTED] belonging to customer SSN [SSN_REDACTED].',
        act: 'REDACTED', risk: 60,
        entities: JSON.stringify([
          { type: 'CREDIT_CARD', value: '4532-0158-9231-8841', span: [31, 50], confidence: 0.95 },
          { type: 'US_SSN', value: '123-45-6789', span: [76, 87], confidence: 0.95 }
        ]),
        resp: 'I have processed the refund confirmation template for card [CARD_REDACTED] and account [SSN_REDACTED].',
        att: 'customer_export.csv'
      }
    ];

    for (const log of logs) {
      db.run(
        `INSERT INTO activity_log (timestamp, employee_id, employee_name, department, original_prompt, processed_prompt, action, risk_score, entities_found, model_response, attachment_name)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [log.ts, log.emp_id, log.emp_name, log.dept, log.orig, log.proc, log.act, log.risk, log.entities, log.resp, log.att]
      );
    }
  }
}

export async function getDb(): Promise<any> {
  if (dbInstance) return dbInstance;

  dbInstance = await createSqlInstance();

  if (dbInstance && typeof dbInstance.run === 'function') {
    try {
      seedSchema(dbInstance);
    } catch (e) {
      console.warn('[Aegis DB] Seeding schema failed on initial dbInstance, purging DB file and recreating:', e);
      try {
        if (fs.existsSync(DB_FILE)) fs.unlinkSync(DB_FILE);
      } catch (_) {}

      try {
        const SQL = await initSqlJs();
        dbInstance = new SQL.Database();
        seedSchema(dbInstance);
      } catch (fallbackErr) {
        console.error('[Aegis DB] Hard failure seeding DB, activating JS Memory DB fallback:', fallbackErr);
        dbInstance = createJsMemoryDb();
      }
    }
  }

  saveDb();
  return dbInstance;
}

export function saveDb() {
  if (!dbInstance) return;
  try {
    if (typeof dbInstance.export === 'function') {
      const data = dbInstance.export();
      if (data && data.length) {
        const buffer = Buffer.from(data);
        const tmpFile = `${DB_FILE}.tmp`;
        fs.writeFileSync(tmpFile, buffer);
        fs.renameSync(tmpFile, DB_FILE);
      }
    }
  } catch (err) {
    // Non-fatal notice if storage is ephemeral
  }
}

