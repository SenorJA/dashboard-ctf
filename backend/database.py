"""
VulnForge — Supabase Database Layer

Provides:
  - Supabase client initialization from env vars
  - Auto-create tables on first connect
  - CRUD helpers for each entity
  - Graceful fallback when Supabase is not configured

Env vars (in .env or system):
  SUPABASE_URL=https://xxxxx.supabase.co
  SUPABASE_KEY=service_role_key_here
"""

import os
import json
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("vulnforge.db")

# ── Supabase client (lazy init) ──
_supabase = None
_available = False


def get_client():
    """Return the Supabase client, or None if not configured."""
    global _supabase, _available
    if _supabase is not None:
        return _supabase

    url = os.getenv("SUPABASE_URL", "")
    key = os.getenv("SUPABASE_KEY", "")

    if not url or not key:
        logger.info("Supabase not configured — set SUPABASE_URL and SUPABASE_KEY")
        _available = False
        return None

    try:
        from supabase import create_client
        _supabase = create_client(url, key)
        _available = True
        logger.info("Supabase connected: %s", url)
        _ensure_tables()
        return _supabase
    except Exception as e:
        logger.warning("Supabase init failed: %s", e)
        _available = False
        return None


def is_available() -> bool:
    """Check if Supabase is configured and reachable."""
    if not _available:
        get_client()
    return _available


# ════════════════════════════════════════════════════════════════
#  SCHEMA — table creation
# ════════════════════════════════════════════════════════════════

SCHEMA_SQL = """
-- ssh_connections
CREATE TABLE IF NOT EXISTS ssh_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    ip TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- scripts
CREATE TABLE IF NOT EXISTS scripts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    language TEXT DEFAULT 'bash',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- reports
CREATE TABLE IF NOT EXISTS reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type TEXT NOT NULL,
    title TEXT DEFAULT '',
    target TEXT DEFAULT '',
    raw_output TEXT DEFAULT '',
    parsed_data JSONB DEFAULT '{}',
    format TEXT DEFAULT 'md',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- hak5_payloads
CREATE TABLE IF NOT EXISTS hak5_payloads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device TEXT NOT NULL,
    name TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- app_settings
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- uploaded_files
CREATE TABLE IF NOT EXISTS uploaded_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    filename TEXT NOT NULL,
    original_name TEXT NOT NULL,
    size_bytes INTEGER DEFAULT 0,
    mime_type TEXT DEFAULT 'application/octet-stream',
    storage_path TEXT NOT NULL,
    public_url TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- credentials
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

-- ctf_challenges
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

-- ctf_solves
CREATE TABLE IF NOT EXISTS ctf_solves (
    id SERIAL PRIMARY KEY,
    challenge_id INTEGER REFERENCES ctf_challenges(id),
    flag_value TEXT NOT NULL,
    solved_at TIMESTAMPTZ DEFAULT NOW()
);

-- findings
CREATE TABLE IF NOT EXISTS findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tool TEXT NOT NULL,
    target TEXT DEFAULT '',
    type TEXT NOT NULL,
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

-- mobile_apks
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

-- forensics_evidence
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

-- mission_history (self-improvement loop — see PLAN_SELFIMPROVEMENT.md)
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

-- scope_events (audit log for scope guard blocks/warnings)
CREATE TABLE IF NOT EXISTS scope_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    action TEXT NOT NULL,
    tool TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    mode TEXT DEFAULT 'warn',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_scope_events_target ON scope_events(target);
CREATE INDEX IF NOT EXISTS idx_scope_events_created ON scope_events(created_at DESC);

-- swarm_sessions (multi-operator pipeline results)
CREATE TABLE IF NOT EXISTS swarm_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    mode TEXT DEFAULT 'auto',
    status TEXT DEFAULT 'running',
    phases JSONB DEFAULT '[]',
    total_findings INT DEFAULT 0,
    report_id UUID,
    error TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_swarm_target ON swarm_sessions(target);
CREATE INDEX IF NOT EXISTS idx_swarm_status ON swarm_sessions(status);

-- mission_plans (Op Admiral saved plans)
CREATE TABLE IF NOT EXISTS mission_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target TEXT NOT NULL,
    name TEXT DEFAULT '',
    steps JSONB DEFAULT '[]',
    total_steps INT DEFAULT 0,
    completed_steps INT DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_plans_target ON mission_plans(target);
CREATE INDEX IF NOT EXISTS idx_plans_status ON mission_plans(status);

-- app_credentials (encrypted secrets storage)
CREATE TABLE IF NOT EXISTS app_credentials (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
"""


def _ensure_tables():
    """Create all tables if they don't exist.

    Attempts three strategies in order:
    1. Direct PostgreSQL connection via ``psycopg2`` (requires
       ``SUPABASE_DB_PASSWORD`` env var — most reliable).
    2. Supabase Management API query endpoint if a management token
       is available (``SUPABASE_MGMT_TOKEN``).
    3. Gentle check-and-warn — the Supabase SQL editor or
       ``supabase_schema.sql`` must be run manually.
    """
    if not _supabase:
        return

    url = os.getenv("SUPABASE_URL", "")
    db_password = os.getenv("SUPABASE_DB_PASSWORD", "")

    # ── Strategy 1: Direct PostgreSQL (psycopg2) ─────────────────
    if url and db_password:
        try:
            import psycopg2
            project_ref = url.replace("https://", "").replace(".supabase.co", "").strip()
            host = f"db.{project_ref}.supabase.co"
            conn = psycopg2.connect(
                host=host, port=5432,
                database="postgres",
                user="postgres",
                password=db_password,
                connect_timeout=5,
            )
            with conn:
                with conn.cursor() as cur:
                    cur.execute(SCHEMA_SQL)
            conn.close()
            logger.info("All tables created/verified via direct PostgreSQL connection")
            return
        except ImportError:
            logger.debug("psycopg2 not installed — skipping direct DB bootstrap")
        except Exception as e:
            logger.warning("Direct PostgreSQL bootstrap failed: %s", e)

    # ── Strategy 2: Supabase Management API (pg_dump endpoint) ──
    mgmt_token = os.getenv("SUPABASE_MGMT_TOKEN", "")
    if url and mgmt_token:
        try:
            project_ref = url.replace("https://", "").replace(".supabase.co", "").strip()
            import urllib.request
            import json as _json
            mgmt_url = f"https://api.supabase.com/v1/projects/{project_ref}/database/query"
            req = urllib.request.Request(
                mgmt_url,
                data=_json.dumps({"query": SCHEMA_SQL}).encode(),
                headers={
                    "Authorization": f"Bearer {mgmt_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                logger.info("Tables created via Management API (status %s)", resp.status)
                return
        except Exception as e:
            logger.warning("Management API bootstrap failed: %s", e)

    # ── Strategy 3: Gentle check + instructions ─────────────────
    try:
        tables = [
            "ssh_connections", "scripts", "reports",
            "hak5_payloads", "app_settings", "uploaded_files",
            "findings", "credentials", "ctf_challenges", "ctf_solves",
            "mobile_apks", "forensics_evidence", "mission_history",
            "scope_events", "swarm_sessions", "mission_plans", "app_credentials",
        ]
        missing = []
        for table in tables:
            try:
                _supabase.table(table).select("id").limit(1).execute()
            except Exception:
                missing.append(table)

        if missing:
            logger.info(
                "Tables missing (%s). To create them automatically, set "
                "SUPABASE_DB_PASSWORD env var (PostgreSQL direct connection) "
                "or run supabase_schema.sql in the Supabase SQL editor.",
                ", ".join(missing),
            )
        else:
            logger.info("All %d tables verified in Supabase", len(tables))
    except Exception as e:
        logger.warning("Table check failed: %s", e)


# ════════════════════════════════════════════════════════════════
#  CRUD HELPERS
# ════════════════════════════════════════════════════════════════

def _table(name: str):
    """Get a Supabase table reference."""
    client = get_client()
    if not client:
        return None
    return client.table(name)


# ── SSH Connections ──

def list_connections():
    tbl = _table("ssh_connections")
    if not tbl:
        return None
    try:
        resp = tbl.select("*").order("created_at", desc=True).execute()
        return resp.data
    except Exception as e:
        logger.error("list_connections: %s", e)
        return []


def save_connection(data: dict):
    tbl = _table("ssh_connections")
    if not tbl:
        return None
    try:
        resp = tbl.insert({
            "name": data["name"],
            "ip": data["ip"],
            "username": data["username"],
            "password": data["password"]
        }).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_connection: %s", e)
        return None


def delete_connection(conn_id: str):
    tbl = _table("ssh_connections")
    if not tbl:
        return False
    try:
        tbl.delete().eq("id", conn_id).execute()
        return True
    except Exception as e:
        logger.error("delete_connection: %s", e)
        return False


# ── Scripts ──

def list_scripts():
    tbl = _table("scripts")
    if not tbl:
        return None
    try:
        resp = tbl.select("*").order("created_at", desc=True).execute()
        return resp.data
    except Exception as e:
        logger.error("list_scripts: %s", e)
        return []


def save_script(data: dict):
    tbl = _table("scripts")
    if not tbl:
        return None
    try:
        resp = tbl.insert({
            "name": data["name"],
            "content": data["content"],
            "language": data.get("language", "bash")
        }).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_script: %s", e)
        return None


def delete_script(script_id: str):
    tbl = _table("scripts")
    if not tbl:
        return False
    try:
        tbl.delete().eq("id", script_id).execute()
        return True
    except Exception as e:
        logger.error("delete_script: %s", e)
        return False


# ── Reports ──

def list_reports():
    tbl = _table("reports")
    if not tbl:
        return None
    try:
        resp = tbl.select("*").order("created_at", desc=True).execute()
        return resp.data
    except Exception as e:
        logger.error("list_reports: %s", e)
        return []


def save_report(data: dict):
    tbl = _table("reports")
    if not tbl:
        return None
    try:
        resp = tbl.insert({
            "type": data["type"],
            "title": data.get("title", ""),
            "target": data.get("target", ""),
            "raw_output": data.get("raw_output", ""),
            "parsed_data": json.dumps(data.get("parsed_data", {})),
            "format": data.get("format", "md")
        }).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_report: %s", e)
        return None


def delete_report(report_id: str):
    tbl = _table("reports")
    if not tbl:
        return False
    try:
        tbl.delete().eq("id", report_id).execute()
        return True
    except Exception as e:
        logger.error("delete_report: %s", e)
        return False


# ── Findings ──

def list_findings(target: str = None, tool: str = None, severity: str = None, limit: int = 200):
    tbl = _table("findings")
    if not tbl:
        return None
    try:
        q = tbl.select("*").order("created_at", desc=True)
        if target:
            q = q.eq("target", target)
        if tool:
            q = q.eq("tool", tool)
        if severity:
            q = q.eq("severity", severity)
        resp = q.limit(limit).execute()
        return resp.data
    except Exception as e:
        logger.error("list_findings: %s", e)
        return []


def save_finding(data: dict):
    tbl = _table("findings")
    if not tbl:
        return None
    try:
        row = {
            "tool": data["tool"],
            "target": data.get("target", ""),
            "type": data.get("type", "generic"),
            "severity": data.get("severity", "info"),
            "title": data.get("title", ""),
            "detail": data.get("detail", ""),
            "port": data.get("port", ""),
            "protocol": data.get("protocol", ""),
            "service": data.get("service", ""),
            "version": data.get("version", ""),
            "status": data.get("status", 0),
            "path": data.get("path", ""),
            "raw": data.get("raw", ""),
        }
        resp = tbl.insert(row).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_finding: %s", e)
        return None


def save_findings_bulk(items: list):
    """Save multiple findings at once."""
    tbl = _table("findings")
    if not tbl:
        return None
    try:
        rows = []
        for data in items:
            rows.append({
                "tool": data["tool"],
                "target": data.get("target", ""),
                "type": data.get("type", "generic"),
                "severity": data.get("severity", "info"),
                "title": data.get("title", ""),
                "detail": data.get("detail", ""),
                "port": data.get("port", ""),
                "protocol": data.get("protocol", ""),
                "service": data.get("service", ""),
                "version": data.get("version", ""),
                "status": data.get("status", 0),
                "path": data.get("path", ""),
                "raw": data.get("raw", ""),
            })
        resp = tbl.insert(rows).execute()
        return len(resp.data) if resp.data else 0
    except Exception as e:
        logger.error("save_findings_bulk: %s", e)
        return 0


def delete_finding(finding_id: str):
    tbl = _table("findings")
    if not tbl:
        return False
    try:
        tbl.delete().eq("id", finding_id).execute()
        return True
    except Exception as e:
        logger.error("delete_finding: %s", e)
        return False


def delete_all_findings():
    tbl = _table("findings")
    if not tbl:
        return False
    try:
        tbl.delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        return True
    except Exception as e:
        logger.error("delete_all_findings: %s", e)
        return False


def count_findings():
    tbl = _table("findings")
    if not tbl:
        return 0
    try:
        resp = tbl.select("id", count="exact").execute()
        return resp.count if hasattr(resp, 'count') else 0
    except Exception as e:
        logger.error("count_findings: %s", e)
        return 0


# ── Credentials ──

def save_credential(data: dict):
    tbl = _table("credentials")
    if not tbl:
        return None
    try:
        row = {
            "type": data.get("type", "password"),
            "target": data.get("target", ""),
            "username": data.get("username", ""),
            "password": data.get("password", ""),
            "hash": data.get("hash", ""),
            "token": data.get("token", ""),
            "service": data.get("service", ""),
            "port": data.get("port", ""),
            "source": data.get("source", ""),
            "notes": data.get("notes", ""),
        }
        resp = tbl.insert(row).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_credential: %s", e)
        return None


def list_credentials(target: str = None, service: str = None):
    tbl = _table("credentials")
    if not tbl:
        return None
    try:
        q = tbl.select("*").order("created_at", desc=True)
        if target:
            q = q.eq("target", target)
        if service:
            q = q.eq("service", service)
        resp = q.execute()
        return resp.data
    except Exception as e:
        logger.error("list_credentials: %s", e)
        return []


def delete_credential(cred_id: str):
    tbl = _table("credentials")
    if not tbl:
        return False
    try:
        tbl.delete().eq("uuid", cred_id).execute()
        return True
    except Exception as e:
        logger.error("delete_credential: %s", e)
        return False


def delete_all_credentials():
    tbl = _table("credentials")
    if not tbl:
        return False
    try:
        tbl.delete().neq("uuid", "00000000-0000-0000-0000-000000000000").execute()
        return True
    except Exception as e:
        logger.error("delete_all_credentials: %s", e)
        return False


# ── Hak5 Payloads ──

def list_hak5_payloads(device: str = None):
    tbl = _table("hak5_payloads")
    if not tbl:
        return None
    try:
        q = tbl.select("*").order("created_at", desc=True)
        if device:
            q = q.eq("device", device)
        resp = q.execute()
        return resp.data
    except Exception as e:
        logger.error("list_hak5_payloads: %s", e)
        return []


def save_hak5_payload(data: dict):
    tbl = _table("hak5_payloads")
    if not tbl:
        return None
    try:
        resp = tbl.insert({
            "device": data["device"],
            "name": data["name"],
            "content": data["content"]
        }).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_hak5_payload: %s", e)
        return None


def delete_hak5_payload(payload_id: str):
    tbl = _table("hak5_payloads")
    if not tbl:
        return False
    try:
        tbl.delete().eq("id", payload_id).execute()
        return True
    except Exception as e:
        logger.error("delete_hak5_payload: %s", e)
        return False


# ── Settings ──

def get_setting(key: str):
    tbl = _table("app_settings")
    if not tbl:
        return None
    try:
        resp = tbl.select("*").eq("key", key).maybe_single().execute()
        return resp.data["value"] if resp.data else None
    except Exception as e:
        logger.error("get_setting(%s): %s", key, e)
        return None


def set_setting(key: str, value):
    tbl = _table("app_settings")
    if not tbl:
        return None
    try:
        # Upsert
        resp = tbl.upsert({
            "key": key,
            "value": json.dumps(value) if not isinstance(value, str) else value,
            "updated_at": datetime.utcnow().isoformat()
        }).execute()
        return resp.data
    except Exception as e:
        logger.error("set_setting(%s): %s", key, e)
        return None


# ── Uploaded Files ──

def save_uploaded_file(data: dict):
    tbl = _table("uploaded_files")
    if not tbl:
        return None
    try:
        resp = tbl.insert({
            "filename": data["filename"],
            "original_name": data.get("original_name", data["filename"]),
            "size_bytes": data.get("size_bytes", 0),
            "mime_type": data.get("mime_type", "application/octet-stream"),
            "storage_path": data["storage_path"],
            "public_url": data.get("public_url", "")
        }).execute()
        return resp.data[0] if resp.data else None
    except Exception as e:
        logger.error("save_uploaded_file: %s", e)
        return None


def list_uploaded_files():
    tbl = _table("uploaded_files")
    if not tbl:
        return None
    try:
        resp = tbl.select("*").order("created_at", desc=True).execute()
        return resp.data
    except Exception as e:
        logger.error("list_uploaded_files: %s", e)
        return []


def delete_uploaded_file(file_id: str):
    tbl = _table("uploaded_files")
    if not tbl:
        return False
    try:
        tbl.delete().eq("id", file_id).execute()
        return True
    except Exception as e:
        logger.error("delete_uploaded_file: %s", e)
        return False


# ── CTF Challenges ──

def save_ctf_challenge(challenge: dict) -> dict | None:
    if not is_available():
        return None
    try:
        data = {
            "title": challenge.get("title", ""),
            "category": challenge.get("category", ""),
            "description": challenge.get("description", ""),
            "flags": challenge.get("flags", ""),
            "points": challenge.get("points", 100),
            "target": challenge.get("target", ""),
            "hints": challenge.get("hints", ""),
            "difficulty": challenge.get("difficulty", "medium"),
            "solved": challenge.get("solved", False),
        }
        result = _table("ctf_challenges").insert(data).execute()
        return dict(result.data[0]) if result.data else None
    except Exception as e:
        print(f"[db] save_ctf_challenge error: {e}")
        return None


def list_ctf_challenges() -> list | None:
    if not is_available():
        return None
    try:
        result = _table("ctf_challenges").select("*").order("created_at", desc=True).execute()
        return [dict(r) for r in result.data] if result.data else []
    except Exception as e:
        print(f"[db] list_ctf_challenges error: {e}")
        return None


def delete_ctf_challenge(challenge_id: int) -> bool:
    if not is_available():
        return False
    try:
        _table("ctf_challenges").delete().eq("id", challenge_id).execute()
        _table("ctf_solves").delete().eq("challenge_id", challenge_id).execute()
        return True
    except Exception as e:
        print(f"[db] delete_ctf_challenge error: {e}")
        return False


def solve_ctf_challenge(challenge_id: int, flag_value: str) -> dict | None:
    if not is_available():
        return None
    try:
        chal_result = _table("ctf_challenges").select("*").eq("id", challenge_id).execute()
        if not chal_result.data:
            return {"ok": False, "error": "Challenge not found"}
        challenge = chal_result.data[0]
        flags_list = [f.strip() for f in challenge.get("flags", "").split("\n") if f.strip()]
        if flag_value not in flags_list:
            return {"ok": False, "error": "Incorrect flag"}
        if challenge.get("solved"):
            return {"ok": True, "message": "Flag correct (already solved)"}
        _table("ctf_solves").insert({
            "challenge_id": challenge_id,
            "flag_value": flag_value,
        }).execute()
        _table("ctf_challenges").update({"solved": True}).eq("id", challenge_id).execute()
        return {"ok": True, "message": f"Correct! +{challenge['points']} points"}
    except Exception as e:
        print(f"[db] solve_ctf_challenge error: {e}")
        return None


def get_ctf_score() -> dict | None:
    if not is_available():
        return None
    try:
        result = _table("ctf_challenges").select("*").execute()
        if not result.data:
            return {"solved": 0, "total": 0, "points": 0, "total_points": 0}
        total = len(result.data)
        solved = sum(1 for c in result.data if c.get("solved"))
        total_points = sum(c.get("points", 0) for c in result.data)
        points = sum(c.get("points", 0) for c in result.data if c.get("solved"))
        return {"solved": solved, "total": total, "points": points, "total_points": total_points}
    except Exception as e:
        print(f"[db] get_ctf_score error: {e}")
        return None


# ════════════════════════════════════════════════════════════════
#  MOBILE LAB
# ════════════════════════════════════════════════════════════════

def save_mobile_apk(data: dict) -> dict | None:
    if not is_available():
        return None
    try:
        row = {
            "apk_id": data["apk_id"],
            "filename": data.get("filename", ""),
            "package": data.get("package", ""),
            "version_name": data.get("version_name", ""),
            "version_code": data.get("version_code", ""),
            "min_sdk": data.get("min_sdk", ""),
            "target_sdk": data.get("target_sdk", ""),
            "size": data.get("size", 0),
            "md5": data.get("md5", ""),
            "sha256": data.get("sha256", ""),
            "findings": json.dumps(data.get("findings", [])),
            "summary": json.dumps(data.get("summary", {"critical":0,"high":0,"medium":0,"low":0,"info":0})),
            "permissions": json.dumps(data.get("permissions", [])),
            "components": json.dumps(data.get("components", {})),
            "error": data.get("error", ""),
        }
        # Upsert (replace if exists)
        result = _table("mobile_apks").upsert(row).execute()
        return dict(result.data[0]) if result.data else None
    except Exception as e:
        logger.error("save_mobile_apk: %s", e)
        return None


def list_mobile_apks() -> list | None:
    if not is_available():
        return None
    try:
        result = _table("mobile_apks").select("*").order("created_at", desc=True).execute()
        return [dict(r) for r in result.data] if result.data else []
    except Exception as e:
        logger.error("list_mobile_apks: %s", e)
        return []


def get_mobile_apk(apk_id: str) -> dict | None:
    if not is_available():
        return None
    try:
        result = _table("mobile_apks").select("*").eq("apk_id", apk_id).maybe_single().execute()
        return dict(result.data) if result.data else None
    except Exception as e:
        logger.error("get_mobile_apk: %s", e)
        return None


def delete_mobile_apk(apk_id: str) -> bool:
    if not is_available():
        return False
    try:
        _table("mobile_apks").delete().eq("apk_id", apk_id).execute()
        return True
    except Exception as e:
        logger.error("delete_mobile_apk: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  FORENSICS LAB
# ════════════════════════════════════════════════════════════════

def save_forensics_evidence(data: dict) -> dict | None:
    if not is_available():
        return None
    try:
        row = {
            "filename": data.get("filename", ""),
            "file_type": data.get("file_type", ""),
            "category": data.get("category", ""),
            "size": data.get("size", 0),
            "md5": data.get("md5", ""),
            "sha256": data.get("sha256", ""),
            "analysis": json.dumps(data.get("analysis", {})),
            "findings": json.dumps(data.get("findings", [])),
            "summary": json.dumps(data.get("summary", {"critical":0,"high":0,"medium":0,"low":0,"info":0})),
            "error": data.get("error", ""),
        }
        result = _table("forensics_evidence").insert(row).execute()
        return dict(result.data[0]) if result.data else None
    except Exception as e:
        logger.error("save_forensics_evidence: %s", e)
        return None


def list_forensics_evidence() -> list | None:
    if not is_available():
        return None
    try:
        result = _table("forensics_evidence").select("*").order("created_at", desc=True).execute()
        return [dict(r) for r in result.data] if result.data else []
    except Exception as e:
        logger.error("list_forensics_evidence: %s", e)
        return []


def get_forensics_evidence(ev_id: str) -> dict | None:
    if not is_available():
        return None
    try:
        result = _table("forensics_evidence").select("*").eq("id", ev_id).maybe_single().execute()
        return dict(result.data) if result.data else None
    except Exception as e:
        logger.error("get_forensics_evidence: %s", e)
        return None


def delete_forensics_evidence(ev_id: str) -> bool:
    if not is_available():
        return False
    try:
        _table("forensics_evidence").delete().eq("id", ev_id).execute()
        return True
    except Exception as e:
        logger.error("delete_forensics_evidence: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  MISSION HISTORY (self-improvement loop — see PLAN_SELFIMPROVEMENT.md)
# ════════════════════════════════════════════════════════════════

def save_mission_history(data: dict):
    """Insert one completed mission row into ``mission_history``.

    Purpose: record the outcome of a pentest engagement (target, OS,
    tools used, top findings, success score) so future missions on
    similar targets can reuse the playbook. Returns the inserted row,
    or ``None`` when Supabase is not configured / the insert failed.
    """
    tbl = _table("mission_history")
    if tbl is None:
        return None
    target = (data.get("target") or "").strip()
    if not target:
        logger.warning("save_mission_history: empty target — refusing")
        return None
    try:
        row = {
            "target":          target,
            "os_detected":     data.get("os_detected", ""),
            "tools_used":      json.dumps(data.get("tools_used", [])),
            "findings_count":  int(data.get("findings_count", 0) or 0),
            "findings_summary": json.dumps(data.get("findings_summary", [])),
            "plan_steps":      int(data.get("plan_steps", 0) or 0),
            "success_score":   int(data.get("success_score", 0) or 0),
        }
        resp = tbl.insert(row).execute()
        return dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("save_mission_history: %s", e)
        return None


def list_mission_history(limit: int = 50, target: str = None):
    """List missions newest-first, optionally filtered by target.

    Returns ``[]`` when the DB is unavailable so the API layer can flag
    ``fallback=True`` without crashing.
    """
    tbl = _table("mission_history")
    if tbl is None:
        return None
    try:
        q = tbl.select("*").order("created_at", desc=True)
        if target:
            q = q.eq("target", target)
        resp = q.limit(int(limit or 50)).execute()
        return [dict(r) for r in resp.data] if resp.data else []
    except Exception as e:
        logger.error("list_mission_history: %s", e)
        return []


def delete_mission_history(mission_id: str):
    """Delete a single mission row by UUID.

    Returns ``True`` on success, ``False`` if the DB is unavailable or
    the delete failed.
    """
    tbl = _table("mission_history")
    if tbl is None:
        return False
    try:
        tbl.delete().eq("id", mission_id).execute()
        return True
    except Exception as e:
        logger.error("delete_mission_history: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  MISSION PLANS (Op Admiral — saved attack plans)
# ════════════════════════════════════════════════════════════════

def save_mission_plan(data: dict) -> dict | None:
    """Save or update an Op Admiral mission plan.

    If ``data`` has an ``id`` that already exists, it is updated;
    otherwise a new row is inserted. Returns the saved row or ``None``.
    """
    tbl = _table("mission_plans")
    if tbl is None:
        return None
    try:
        if data.get("id"):
            # Update existing
            row_id = data.pop("id")
            data["updated_at"] = datetime.utcnow().isoformat()
            resp = tbl.update(data).eq("id", row_id).execute()
        else:
            data["steps"] = json.dumps(data.get("steps", []))
            resp = tbl.insert(data).execute()
        return dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("save_mission_plan: %s", e)
        return None


def list_mission_plans(limit: int = 20, target: str = None):
    """List mission plans newest-first, optionally filtered by target."""
    tbl = _table("mission_plans")
    if tbl is None:
        return None
    try:
        q = tbl.select("*").order("updated_at", desc=True)
        if target:
            q = q.eq("target", target)
        resp = q.limit(int(limit or 20)).execute()
        return [dict(r) for r in resp.data] if resp.data else []
    except Exception as e:
        logger.error("list_mission_plans: %s", e)
        return []


def delete_mission_plan(plan_id: str) -> bool:
    """Delete a mission plan by UUID."""
    tbl = _table("mission_plans")
    if tbl is None:
        return False
    try:
        tbl.delete().eq("id", plan_id).execute()
        return True
    except Exception as e:
        logger.error("delete_mission_plan: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  SCOPE EVENTS (audit log for scope guard blocks/warnings)
# ════════════════════════════════════════════════════════════════

def save_scope_event(data: dict) -> dict | None:
    """Log a scope guard event (block/warn/allow)."""
    tbl = _table("scope_events")
    if tbl is None:
        return None
    try:
        resp = tbl.insert({
            "target":  data.get("target", ""),
            "action":  data.get("action", "block"),
            "tool":    data.get("tool", ""),
            "reason":  data.get("reason", ""),
            "mode":    data.get("mode", "warn"),
        }).execute()
        return dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("save_scope_event: %s", e)
        return None


def list_scope_events(limit: int = 100):
    """List scope events newest-first."""
    tbl = _table("scope_events")
    if tbl is None:
        return None
    try:
        resp = tbl.select("*").order("created_at", desc=True).limit(int(limit or 100)).execute()
        return [dict(r) for r in resp.data] if resp.data else []
    except Exception as e:
        logger.error("list_scope_events: %s", e)
        return []


def clear_scope_events() -> bool:
    """Delete all scope events."""
    tbl = _table("scope_events")
    if tbl is None:
        return False
    try:
        tbl.delete().neq("id", "00000000-0000-0000-0000-000000000000").execute()
        return True
    except Exception as e:
        logger.error("clear_scope_events: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  SWARM SESSIONS (multi-operator pipeline)
# ════════════════════════════════════════════════════════════════

def save_swarm_session(data: dict) -> dict | None:
    """Create or update a swarm session."""
    tbl = _table("swarm_sessions")
    if tbl is None:
        return None
    try:
        if data.get("id"):
            row_id = data.pop("id")
            if "phases" in data:
                data["phases"] = json.dumps(data["phases"])
            resp = tbl.update(data).eq("id", row_id).execute()
        else:
            data["phases"] = json.dumps(data.get("phases", []))
            resp = tbl.insert(data).execute()
        return dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("save_swarm_session: %s", e)
        return None


def list_swarm_sessions(limit: int = 20):
    """List swarm sessions newest-first."""
    tbl = _table("swarm_sessions")
    if tbl is None:
        return None
    try:
        resp = tbl.select("*").order("created_at", desc=True).limit(int(limit or 20)).execute()
        return [dict(r) for r in resp.data] if resp.data else []
    except Exception as e:
        logger.error("list_swarm_sessions: %s", e)
        return []


def get_swarm_session(session_id: str) -> dict | None:
    """Get a single swarm session by UUID."""
    tbl = _table("swarm_sessions")
    if tbl is None:
        return None
    try:
        resp = tbl.select("*").eq("id", session_id).limit(1).execute()
        return dict(resp.data[0]) if resp.data else None
    except Exception as e:
        logger.error("get_swarm_session: %s", e)
        return None


def delete_swarm_session(session_id: str) -> bool:
    """Delete a swarm session by UUID."""
    tbl = _table("swarm_sessions")
    if tbl is None:
        return False
    try:
        tbl.delete().eq("id", session_id).execute()
        return True
    except Exception as e:
        logger.error("delete_swarm_session: %s", e)
        return False


# ════════════════════════════════════════════════════════════════
#  APP CREDENTIALS (encrypted secrets: AI keys, etc.)
# ════════════════════════════════════════════════════════════════

def save_app_credential(key: str, value: str, description: str = "") -> bool:
    """Store a credential/secret in ``app_credentials``.

    This is a simple key-value store for secrets like AI API keys.
    In production, ``value`` should be encrypted before storage.
    """
    tbl = _table("app_credentials")
    if tbl is None:
        return False
    try:
        # Upsert: insert or update
        existing = tbl.select("key").eq("key", key).limit(1).execute()
        if existing.data:
            tbl.update({
                "value": value,
                "description": description,
                "updated_at": datetime.utcnow().isoformat()
            }).eq("key", key).execute()
        else:
            tbl.insert({
                "key": key,
                "value": value,
                "description": description
            }).execute()
        return True
    except Exception as e:
        logger.error("save_app_credential: %s", e)
        return False


def get_app_credential(key: str) -> str | None:
    """Retrieve a stored credential value by key."""
    tbl = _table("app_credentials")
    if tbl is None:
        return None
    try:
        resp = tbl.select("value").eq("key", key).limit(1).execute()
        return resp.data[0]["value"] if resp.data else None
    except Exception as e:
        logger.error("get_app_credential: %s", e)
        return None


def delete_app_credential(key: str) -> bool:
    """Delete a stored credential by key."""
    tbl = _table("app_credentials")
    if tbl is None:
        return False
    try:
        tbl.delete().eq("key", key).execute()
        return True
    except Exception as e:
        logger.error("delete_app_credential: %s", e)
        return False
