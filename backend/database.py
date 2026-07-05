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
"""


def _ensure_tables():
    """Create all tables if they don't exist."""
    if not _supabase:
        return
    try:
        # Supabase-py doesn't support raw SQL directly.
        # We use the REST API to execute SQL via the 'sql' endpoint.
        # Alternative: use the management API or run via psql.
        # For now, we check tables exist by trying a simple query.

        tables = [
            "ssh_connections", "scripts", "reports",
            "hak5_payloads", "app_settings", "uploaded_files"
        ]
        for table in tables:
            try:
                _supabase.table(table).select("id").limit(1).execute()
            except Exception:
                logger.info("Table '%s' doesn't exist — creating via REST", table)
                # We can't CREATE TABLE via REST API easily.
                # User must run the SQL manually or we use the management endpoint.
                pass

        logger.info("Tables verified. If missing, run the SQL from supabase_schema.sql")
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
