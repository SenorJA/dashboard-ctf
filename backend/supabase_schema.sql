-- ============================================================
-- VulnForge — Supabase Schema
-- Run this SQL in the Supabase SQL Editor (Dashboard → SQL Editor)
-- or via psql once.
-- ============================================================

-- ── SSH Connection Profiles ──
CREATE TABLE IF NOT EXISTS ssh_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── RCE Scripts ──
CREATE TABLE IF NOT EXISTS scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    language TEXT DEFAULT 'bash',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Scan Reports ──
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,              -- 'nmap', 'gobuster', 'bounty', 'ai_writeup', 'manual'
    title TEXT DEFAULT '',
    target TEXT DEFAULT '',
    raw_output TEXT DEFAULT '',
    parsed_data JSONB DEFAULT '{}',  -- structured: ports[], dirs[], etc.
    format TEXT DEFAULT 'md',         -- 'md', 'html', 'pdf'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Hak5 Payloads ──
CREATE TABLE IF NOT EXISTS hak5_payloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device TEXT NOT NULL,             -- 'bunny', 'omg', 'm5', 'shack'
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── App Settings (key-value store) ──
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Uploaded Files Metadata ──
CREATE TABLE IF NOT EXISTS uploaded_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    mime_type TEXT DEFAULT 'application/octet-stream',
    storage_path TEXT NOT NULL,       -- path inside Supabase Storage bucket
    public_url TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── Indexes for common queries ──
CREATE INDEX IF NOT EXISTS idx_reports_type ON reports(type);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hak5_device ON hak5_payloads(device);
CREATE INDEX IF NOT EXISTS idx_scripts_name ON scripts(name);
CREATE INDEX IF NOT EXISTS idx_files_created ON uploaded_files(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  FINDINGS (parsed tool output)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool TEXT NOT NULL,
    target TEXT DEFAULT '',
    type TEXT NOT NULL,              -- 'port', 'directory', 'vuln', 'tech', 'user', 'plugin', 'os', 'generic'
    severity TEXT DEFAULT 'info',
    title TEXT DEFAULT '',
    detail TEXT DEFAULT '',
    port TEXT DEFAULT '',
    protocol TEXT DEFAULT '',
    service TEXT DEFAULT '',
    version TEXT DEFAULT '',
    status INTEGER DEFAULT 0,
    path TEXT DEFAULT '',
    raw TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_findings_tool ON findings(tool);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  CREDENTIALS (discovered creds)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS credentials (
    uuid UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    type VARCHAR(20) NOT NULL DEFAULT 'password',
    target VARCHAR(255) NOT NULL,
    username VARCHAR(255) DEFAULT '',
    password TEXT DEFAULT '',
    hash TEXT DEFAULT '',
    token TEXT DEFAULT '',
    service VARCHAR(100) DEFAULT '',
    port VARCHAR(10) DEFAULT '',
    source VARCHAR(100) DEFAULT '',
    notes TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_credentials_target ON credentials(target);
CREATE INDEX IF NOT EXISTS idx_credentials_service ON credentials(service);

-- ════════════════════════════════════════════════════════════════
--  CTF CHALLENGES
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ctf_challenges (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT DEFAULT '',
    flags TEXT DEFAULT '',
    points INTEGER DEFAULT 100,
    target VARCHAR(255) DEFAULT '',
    hints TEXT DEFAULT '',
    difficulty VARCHAR(20) DEFAULT 'medium',
    solved BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ctf_category ON ctf_challenges(category);
CREATE INDEX IF NOT EXISTS idx_ctf_solved ON ctf_challenges(solved);

-- ════════════════════════════════════════════════════════════════
--  CTF SOLVES (flag submissions)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ctf_solves (
    id SERIAL PRIMARY KEY,
    challenge_id INTEGER REFERENCES ctf_challenges(id),
    flag_value TEXT NOT NULL,
    solved_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_ctf_solves_challenge ON ctf_solves(challenge_id);

-- ════════════════════════════════════════════════════════════════
--  MOBILE APK ANALYSES
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mobile_apks (
    apk_id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    package TEXT DEFAULT '',
    version_name TEXT DEFAULT '',
    version_code TEXT DEFAULT '',
    min_sdk TEXT DEFAULT '',
    target_sdk TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    md5 TEXT DEFAULT '',
    sha256 TEXT DEFAULT '',
    findings JSONB DEFAULT '[]',
    summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}',
    permissions JSONB DEFAULT '[]',
    components JSONB DEFAULT '{}',
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mobile_created ON mobile_apks(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  FORENSICS EVIDENCE
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS forensics_evidence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    file_type TEXT DEFAULT '',
    category TEXT DEFAULT '',
    size INTEGER DEFAULT 0,
    md5 TEXT DEFAULT '',
    sha256 TEXT DEFAULT '',
    analysis JSONB DEFAULT '{}',
    findings JSONB DEFAULT '[]',
    summary JSONB DEFAULT '{"critical":0,"high":0,"medium":0,"low":0,"info":0}',
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_forensics_category ON forensics_evidence(category);
CREATE INDEX IF NOT EXISTS idx_forensics_created ON forensics_evidence(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  MISSION HISTORY (self-improvement loop)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mission_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    os_detected TEXT DEFAULT '',
    tools_used JSONB DEFAULT '[]',
    findings_count INT DEFAULT 0,
    findings_summary JSONB DEFAULT '[]',
    plan_steps INT DEFAULT 0,
    success_score INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mission_history_target ON mission_history(target);
CREATE INDEX IF NOT EXISTS idx_mission_history_os      ON mission_history(os_detected);
CREATE INDEX IF NOT EXISTS idx_mission_history_score   ON mission_history(success_score DESC);

-- ════════════════════════════════════════════════════════════════
--  SCOPE EVENTS (audit log for scope guard blocks/warnings)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS scope_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    action TEXT NOT NULL,            -- 'block', 'warn', 'allow'
    tool TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    mode TEXT DEFAULT 'warn',        -- 'warn' or 'block'
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scope_events_target ON scope_events(target);
CREATE INDEX IF NOT EXISTS idx_scope_events_created ON scope_events(created_at DESC);

-- ════════════════════════════════════════════════════════════════
--  SWARM SESSIONS (multi-operator pipeline results)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS swarm_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    mode TEXT DEFAULT 'auto',        -- 'auto', 'manual'
    status TEXT DEFAULT 'running',   -- 'running', 'completed', 'cancelled', 'error'
    phases JSONB DEFAULT '[]',       -- [{name, status, findings_count, ...}]
    total_findings INT DEFAULT 0,
    report_id UUID REFERENCES reports(id),
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_swarm_target ON swarm_sessions(target);
CREATE INDEX IF NOT EXISTS idx_swarm_status ON swarm_sessions(status);

-- ════════════════════════════════════════════════════════════════
--  MISSION PLANS (Op Admiral saved plans)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS mission_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    name TEXT DEFAULT '',
    steps JSONB DEFAULT '[]',        -- [{tool, command, target, priority, status}, ...]
    total_steps INT DEFAULT 0,
    completed_steps INT DEFAULT 0,
    status TEXT DEFAULT 'active',    -- 'active', 'completed', 'archived'
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_plans_target ON mission_plans(target);
CREATE INDEX IF NOT EXISTS idx_plans_status ON mission_plans(status);

-- ════════════════════════════════════════════════════════════════
--  APP_CREDENTIALS (encrypted secrets storage for AI keys etc.)
-- ════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS app_credentials (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,              -- encrypted value (AES-256-GCM or similar)
    description TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- ════════════════════════════════════════════════════════════════
--  Storage bucket (run once via Supabase Dashboard)
-- ════════════════════════════════════════════════════════════════
-- Go to Storage → Create bucket → Name: "vulnforge" → Public
