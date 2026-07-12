"""
VulnForge — Backend Server
FastAPI + WebSocket + Paramiko (Dynamic SSH)

STARTUP:
  From project root:    uvicorn backend.main:app --reload
  OR:                   python run.py
  From backend/:        python main.py
  OR:                   uvicorn main:app --reload
"""

import json
import os
import sys
import io
import shlex
import asyncio
import logging
import urllib.request
import urllib.error
from datetime import datetime

# ── Production mode detection ──
# If run WITHOUT --reload, we're in production mode
# We detect this by checking if uvicorn's --reload flag is absent
PRODUCTION = "--reload" not in " ".join(sys.argv)
VERSION = "1.0.0"

# ── Load .env (if exists) ──
try:
    from dotenv import load_dotenv
    _dotenv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(_dotenv_path):
        load_dotenv(_dotenv_path)
        print("[*] Loaded .env")
except ImportError:
    pass

# ── Fix path: allow import from project root even when run from backend/ ──
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import paramiko

# ── Supabase Database Layer ──
from backend import database as db

# ── OPSEC Levels (command stealth rewriting) ──
from backend.opsec import apply_opsec as opsec_apply, LEVELS_INFO

# ── Mission History (self-improvement loop) ──
from backend.mission_store import (
    save_mission,
    list_missions,
    find_similar,
    get_suggestion_context,
)
from backend import database as _db_module  # alias used by mission delete endpoint

# ── New CRUD functions (Phases 7-10: plans, events, swarm, secrets) ──
from backend.database import (
    save_mission_plan, list_mission_plans, delete_mission_plan,
    save_scope_event, list_scope_events, clear_scope_events,
    save_swarm_session, list_swarm_sessions, get_swarm_session, delete_swarm_session,
    save_app_credential, get_app_credential, delete_app_credential,
)

# ── Mobile Lab Modules ──
from backend.mobile_analyzer import (
    analyze_apk as mobile_analyze_apk,
    list_apks as mobile_list_apks,
    get_apk as mobile_get_apk,
    delete_apk as mobile_delete_apk,
    init_work_dir as mobile_init_work_dir,
    set_ssh_client as mobile_set_ssh_client,
)
from backend.adb_controller import (
    list_devices as mobile_list_devices,
    run_frida_script as mobile_run_frida_script,
    get_available_scripts as mobile_get_frida_scripts,
)
from backend.forensics import (
    analyze_file as forensics_analyze,
    list_evidence as forensics_list,
    get_evidence as forensics_get,
    delete_evidence as forensics_delete,
    run_tool as forensics_run_tool,
)

app = FastAPI(title="VulnForge", version=VERSION)

# ── Production logging ──
if PRODUCTION:
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "vulnforge.log")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout),
        ],
    )
    logging.info("=" * 50)
    logging.info("VulnForge starting in PRODUCTION mode")
    logging.info(f"Version: {VERSION}")
    logging.info("=" * 50)
else:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

logger = logging.getLogger("vulnforge")

# ── Middleware: force no-cache on everything (kill browser cache) ──
class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

app.add_middleware(NoCacheMiddleware)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ════════════════════════════════════════════════════════════════
#  SHARED SSH CLIENT (for Mobile Lab API endpoints)
# ════════════════════════════════════════════════════════════════

_active_ssh_client: paramiko.SSHClient | None = None
_ssh_credentials: dict = {}


def get_active_ssh_client() -> paramiko.SSHClient | None:
    """Get the shared SSH client. Returns None if not connected."""
    global _active_ssh_client
    if _active_ssh_client:
        transport = _active_ssh_client.get_transport()
        if transport and transport.is_active():
            return _active_ssh_client
        _active_ssh_client = None
    return None


async def _ensure_ssh_connection(ssh_ip: str = None, ssh_user: str = None, ssh_pass: str = None) -> paramiko.SSHClient | None:
    """Ensure a shared SSH connection exists. Reconnect if needed."""
    global _active_ssh_client, _ssh_credentials
    client = get_active_ssh_client()
    if client:
        return client

    # Use provided creds or stored creds or env defaults
    ip = ssh_ip or _ssh_credentials.get("ip") or os.getenv("KALI_IP", "192.168.214.142")
    user = ssh_user or _ssh_credentials.get("user") or os.getenv("KALI_USER", "javi")
    pwd = ssh_pass or _ssh_credentials.get("pass") or os.getenv("KALI_PASS", "javi")
    port = int(os.getenv("KALI_PORT", "22"))

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        await asyncio.to_thread(
            client.connect, ip, port=port, username=user, password=pwd,
            timeout=8, look_for_keys=False, allow_agent=False,
        )
        _active_ssh_client = client
        _ssh_credentials = {"ip": ip, "user": user, "pass": pwd}
        # Share with mobile_analyzer
        mobile_set_ssh_client(client)
        logger.info("Shared SSH connected: %s@%s", user, ip)
        return client
    except Exception as e:
        logger.warning("Shared SSH connection failed: %s", e)
        return None

# ── Static files ──
frontend_dir = os.path.normpath(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend"))
css_dir = os.path.normpath(os.path.join(frontend_dir, "css"))
js_dir = os.path.normpath(os.path.join(frontend_dir, "js"))
print(f"[*] Frontend dir: {frontend_dir}")
print(f"[*] CSS dir: {css_dir} (exists: {os.path.isdir(css_dir)})")
print(f"[*] JS dir: {js_dir} (exists: {os.path.isdir(js_dir)})")

@app.get("/css/{filepath:path}")
async def css_file(filepath: str):
    file_path = os.path.normpath(os.path.join(css_dir, filepath))
    # Security: prevent path traversal
    if not file_path.startswith(css_dir):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return JSONResponse({"detail": "Not Found"}, status_code=404)

@app.get("/js/{filepath:path}")
async def js_file(filepath: str):
    file_path = os.path.normpath(os.path.join(js_dir, filepath))
    if not file_path.startswith(js_dir):
        return JSONResponse({"detail": "Forbidden"}, status_code=403)
    if os.path.isfile(file_path):
        return FileResponse(file_path)
    return JSONResponse({"detail": "Not Found"}, status_code=404)

# ════════════════════════════════════════════════════════════════
#  RESPONSE HELPERS
# ════════════════════════════════════════════════════════════════

def _ok(data, status=200):
    """Return success JSON, or a 503 error if data is None (DB not configured)."""
    if data is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": True, "data": data}, status_code=status)

def _delete_ok(ok):
    """Return success JSON for a delete operation, or an error if it failed."""
    if not ok:
        return JSONResponse({"ok": False, "error": "Delete failed"}, status_code=400)
    return JSONResponse({"ok": True})

# ════════════════════════════════════════════════════════════════
#  N8N AUTOMATION PROXY
# ════════════════════════════════════════════════════════════════

class N8nTriggerRequest(BaseModel):
    target: str
    scan_type: str = "full"
    n8n_url: str = "http://localhost:5678"

def _http_post_json(url: str, data: dict, timeout: int = 120):
    """Synchronous HTTP POST with JSON body (runs in thread via asyncio)."""
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:2000]
    except urllib.error.URLError as e:
        raise ConnectionError(f"n8n unreachable: {e.reason}")

def _http_get(url: str, timeout: int = 5):
    """Synchronous HTTP GET (runs in thread via asyncio)."""
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status
    except urllib.error.URLError:
        return 0

@app.post("/api/n8n/trigger")
async def trigger_n8n_workflow(req: N8nTriggerRequest):
    """Proxy a trigger request to the n8n webhook."""
    webhook_url = f"{req.n8n_url.rstrip('/')}/webhook/attack-surface-scan"
    payload = {"target": req.target, "scan_type": req.scan_type}
    try:
        status, text = await asyncio.to_thread(_http_post_json, webhook_url, payload, 120)
        return JSONResponse(
            content={"status": status, "ok": 200 <= status < 300, "data": text[:2000]}
        )
    except ConnectionError as e:
        return JSONResponse(
            status_code=502,
            content={"status": 502, "ok": False, "error": str(e)}
        )

@app.get("/api/n8n/status")
async def check_n8n_status(n8n_url: str = "http://localhost:5678"):
    """Health-check that n8n is reachable."""
    health_url = f"{n8n_url.rstrip('/')}/healthz"
    status = await asyncio.to_thread(_http_get, health_url, 5)
    return JSONResponse(content={"reachable": status != 0, "status": status})


# ════════════════════════════════════════════════════════════════
#  AI SUGGEST PROXY (Fase 2)
# ════════════════════════════════════════════════════════════════

class SuggestRequest(BaseModel):
    provider: str = "openai"       # openai | gemini | anthropic | openrouter | deepseek | groq
    api_key: str = ""
    model: str = ""
    target: str = ""
    findings: str = ""
    history: list = []              # list of {"role":"user"/"assistant","content":"..."}
    system_prompt: str = ""

def _clean_text(text: str) -> str:
    """Remove non-ASCII characters (emojis, special symbols) that break Latin-1 encoding in urllib."""
    if not text:
        return text
    return text.encode('ascii', 'ignore').decode('ascii').strip()

def _build_suggest_prompt(target: str, findings: str) -> str:
    """Build the system prompt for penetration testing suggestions."""
    return f"""You are an expert penetration testing assistant integrated into VulnForge, a red team dashboard.

Your role is to analyze the current findings and suggest the NEXT logical step.

Target: {target}

Current findings:
{findings if findings else "No findings yet. Suggest initial reconnaissance steps."}

Based on these findings, suggest the single most impactful next step. Be concise and specific:
1. What tool/command to run
2. Why this step is important
3. What to look for in the output

Keep suggestions actionable and technical. Focus on the most promising attack path."""

def _call_llm_sync(provider: str, api_key: str, model: str, messages: list, timeout: int = 60) -> str:
    """Synchronous LLM API call (runs in thread via asyncio). Returns the response text."""
    if provider in ("openai", "openrouter", "deepseek", "groq"):
        # OpenAI-compatible API
        base_map = {
            "openai":     "https://api.openai.com/v1",
            "openrouter": "https://openrouter.ai/api/v1",
            "deepseek":   "https://api.deepseek.com/v1",
            "groq":       "https://api.groq.com/openai/v1",
        }
        default_model_map = {
            "openai":     "gpt-4o-mini",
            "openrouter": "gpt-4o-mini",
            "deepseek":   "deepseek-chat",
            "groq":       "llama-3.3-70b-versatile",
        }
        base = base_map.get(provider, "https://api.openai.com/v1")
        if not model or model.lower() in ("openai", "gemini", "anthropic", "openrouter", "deepseek", "groq"):
            model = default_model_map.get(provider, "gpt-4o-mini")
        url = f"{base}/chat/completions"
        body = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1024
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("Authorization", f"Bearer {api_key}")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
        req.add_header("Accept", "*/*")
        req.add_header("Cache-Control", "no-cache")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", str(data))
                return str(data)
        except UnicodeDecodeError:
            raise RuntimeError(f"Encoding error — the API returned non-UTF-8 data. Check your model name.")
        except urllib.error.HTTPError as e:
            # Provide a clearer error for invalid models
            body = e.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"API error {e.code} (model={model}): {body}")

    elif provider == "gemini":
        if not model: model = "gemini-2.0-flash"
        url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent?key={api_key}"
        # Convert messages to Gemini format
        gemini_contents = []
        for msg in messages:
            role = "model" if msg["role"] == "assistant" else "user"
            gemini_contents.append({
                "role": role,
                "parts": [{"text": msg["content"]}]
            })
        body = json.dumps({"contents": gemini_contents}).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            candidates = data.get("candidates", [])
            if candidates:
                parts = candidates[0].get("content", {}).get("parts", [])
                if parts:
                    return parts[0].get("text", str(data))
            return str(data)

    elif provider == "anthropic":
        if not model: model = "claude-3-haiku-20240307"
        url = "https://api.anthropic.com/v1/messages"
        # Build Anthropic messages format
        anthy_messages = [m for m in messages if m["role"] != "system"]
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        body = json.dumps({
            "model": model,
            "messages": anthy_messages,
            "system": system,
            "max_tokens": 1024,
            "temperature": 0.3
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("x-api-key", api_key)
        req.add_header("anthropic-version", "2023-06-01")
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data.get("content", [])
            if content:
                return content[0].get("text", str(data))
            return str(data)

    elif provider == "local":
        # Ollama / LM Studio (OpenAI-compatible API, no API key required)
        base = os.getenv("OLLAMA_URL", "http://localhost:11434")
        if not model: model = "llama3"
        url = f"{base.rstrip('/')}/v1/chat/completions"
        body = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1024
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json; charset=utf-8")
        req.add_header("User-Agent", "Mozilla/5.0")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                data = json.loads(raw.decode("utf-8"))
                choices = data.get("choices", [])
                if choices:
                    return choices[0].get("message", {}).get("content", str(data))
                return str(data)
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"Local AI error {e.code} (model={model}, url={url}): {err_body}")
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cannot connect to local AI at {base}. Is Ollama/LM Studio running? Error: {e.reason}")

    else:
        raise ValueError(f"Unknown provider: {provider}")

@app.post("/api/suggest")
async def suggest_next_step(req: SuggestRequest):
    """AI-powered suggestion for the next penetration testing step.

    Self-improvement loop: looks up similar past missions (via
    ``mission_store.get_suggestion_context``) and injects them into the
    system prompt as a ``## Mission History Context`` section so the LLM
    grounds its next-step recommendation on what worked previously.
    The lookup is wrapped defensively: any failure degrades to the
    original (context-less) prompt — the suggest endpoint must never
    crash because of the memory layer.
    """
    try:
        if not req.api_key and req.provider != "local":
            return JSONResponse({"ok": False, "error": "API key is required"}, status_code=400)

        # Build messages
        system = req.system_prompt or _build_suggest_prompt(req.target, req.findings)

        # ── Mission history context (self-improvement) ──
        # Non-ASCII chars are stripped later by _clean_text, so the
        # context block is safe to embed.
        try:
            context = get_suggestion_context(req.findings)
        except Exception as e:
            logger.warning("[suggest] mission context lookup failed: %s", e)
            context = ""
        if context:
            system = f"{system}\n\n{context}"

        messages = [{"role": "system", "content": _clean_text(system)}]

        # Add history
        for h in req.history:
            messages.append({
                "role": h.get("role", "user"),
                "content": _clean_text(h.get("content", ""))
            })

        # Add current context as user message
        clean_findings = _clean_text(req.findings)
        clean_target = _clean_text(req.target) or "unknown"
        user_msg = f"Target: {clean_target}\n\nCurrent findings:\n{clean_findings if clean_findings else 'None yet'}\n\nWhat should I do next?"
        messages.append({"role": "user", "content": user_msg})

        result = await asyncio.to_thread(
            _call_llm_sync, req.provider, req.api_key, req.model, messages, 60
        )

        return JSONResponse({"ok": True, "suggestion": result})

    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:500]
        return JSONResponse({"ok": False, "error": f"[{req.provider}] {e.code}: {body}"}, status_code=502)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"[{req.provider}] model={req.model or '(default)'}: {e}"}, status_code=500)

# ════════════════════════════════════════════════════════════════
#  GENERIC AI CHAT (for all sections: scripts, bounty, hak5, etc.)
# ════════════════════════════════════════════════════════════════

class AIChatRequest(BaseModel):
    provider: str = "openai"
    api_key: str = ""
    model: str = ""
    messages: list = []  # [{"role":"user"/"assistant"/"system","content":"..."}]

@app.post("/api/ai/chat")
async def ai_chat(req: AIChatRequest):
    """Generic AI chat endpoint — reusable by any frontend section."""
    try:
        if not req.api_key and req.provider != "local":
            return JSONResponse({"ok": False, "error": "API key is required"}, status_code=400)
        result = await asyncio.to_thread(
            _call_llm_sync, req.provider, req.api_key, req.model, req.messages, 60
        )
        return JSONResponse({"ok": True, "content": result})
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')[:500]
        return JSONResponse({"ok": False, "error": f"[{req.provider}] {e.code}: {body}"}, status_code=502)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"[{req.provider}] model={req.model}: {e}"}, status_code=500)

# ════════════════════════════════════════════════════════════════
#  FINDINGS API (persistent storage)
# ════════════════════════════════════════════════════════════════

@app.get("/api/findings")
async def get_findings(target: str = "", tool: str = "", severity: str = ""):
    """List findings with optional filters."""
    data = db.list_findings(
        target=target or None,
        tool=tool or None,
        severity=severity or None
    )
    if data is None:
        # Fallback: return empty list when DB is not configured
        return JSONResponse({"ok": True, "data": [], "fallback": True})
    return JSONResponse({"ok": True, "data": data})


@app.post("/api/findings")
async def create_finding(req: dict):
    """Save a single finding."""
    if not req:
        return JSONResponse({"ok": False, "error": "Empty body"}, status_code=400)
    result = db.save_finding(req)
    if result is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": True, "data": result}, status_code=201)


@app.post("/api/findings/bulk")
async def create_findings_bulk(req: list):
    """Save multiple findings at once."""
    if not req:
        return JSONResponse({"ok": False, "error": "Empty array"}, status_code=400)
    count = db.save_findings_bulk(req)
    if count is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": True, "count": count}, status_code=201)


@app.delete("/api/findings/{finding_id}")
async def remove_finding(finding_id: str):
    """Delete a single finding."""
    ok = db.delete_finding(finding_id)
    if ok is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": ok})


@app.delete("/api/findings")
async def clear_all_findings():
    """Delete all findings."""
    ok = db.delete_all_findings()
    if ok is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": ok})


@app.get("/api/findings/stats")
async def findings_stats():
    """Return quick stats: total findings, unique tools, unique targets."""
    data = db.list_findings()
    if data is None:
        return JSONResponse({"ok": True, "count": 0, "tools": [], "targets": []})
    tools = list(set(f.get("tool", "?") for f in data))
    targets = list(set(f.get("target", "?") for f in data if f.get("target")))
    return JSONResponse({
        "ok": True,
        "count": len(data),
        "tools": sorted(tools),
        "targets": sorted(targets)
    })

# ════════════════════════════════════════════════════════════════
#  SUPABASE API ENDPOINTS
# ════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def api_health():
    """Check system health — database, uptime, mode."""
    ok = db.is_available()
    uptime_seconds = 0
    if hasattr(app, "_start_time"):
        uptime_seconds = int((datetime.utcnow() - app._start_time).total_seconds())
    return JSONResponse({
        "status": "ok" if ok else "degraded",
        "mode": "production" if PRODUCTION else "development",
        "version": VERSION,
        "uptime_seconds": uptime_seconds,
        "supabase": ok,
        "database": "supabase" if ok else "localstorage (fallback)",
    })

# Record startup time
@app.on_event("startup")
async def _record_startup():
    app._start_time = datetime.utcnow()
    # Initialize Mobile Lab work directory
    mobile_init_work_dir()
    if PRODUCTION:
        logger.info("VulnForge ready — production mode")
    else:
        logger.info("VulnForge ready — development mode (--reload)")
    logger.info("Mobile Lab initialized")

# ── Reports ──

@app.get("/api/reports")
async def get_reports():
    return _ok(db.list_reports())


class ReportCreate(BaseModel):
    type: str
    title: str = ""
    target: str = ""
    raw_output: str = ""
    parsed_data: dict = {}
    format: str = "md"


@app.post("/api/reports")
async def create_report(report: ReportCreate):
    return _ok(db.save_report(report.model_dump()), 201)


@app.delete("/api/reports/{report_id}")
async def delete_report(report_id: str):
    return _delete_ok(db.delete_report(report_id))


# ── Report Generator ──
class ReportGenerateRequest(BaseModel):
    target: str = ""
    title: str = ""
    findings: list = []
    suggestions: list = []


@app.post("/api/report/generate")
async def generate_report(req: ReportGenerateRequest):
    """
    Compile findings into a structured report.
    Returns the created report with all fields populated.
    """
    findings = req.findings or []
    suggestions = req.suggestions or []
    target = req.target or "unknown"
    title = req.title or f"Scan Report — {target} — {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}"

    # Compute stats
    total = len(findings)
    by_severity = {}
    by_tool = {}
    for f in findings:
        sev = f.get("severity", "info")
        tool = f.get("tool", "?")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_tool[tool] = by_tool.get(tool, 0) + 1

    severity_order = ["critical", "high", "medium", "low", "info"]
    severity_labels = {"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🔵 Low", "info": "ℹ️ Info"}

    # Build MD body
    md_lines = [
        f"# {title}",
        f"",
        f"**Target:** `{target}`",
        f"**Date:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Total Findings:** {total}",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in severity_order:
        cnt = by_severity.get(sev, 0)
        label = severity_labels.get(sev, sev)
        md_lines.append(f"| {label} | {cnt} |")
    md_lines.append(f"| **Total** | **{total}** |")
    md_lines.append("")
    md_lines.append("### Tools Used")
    for tool, cnt in sorted(by_tool.items()):
        md_lines.append(f"- **{tool}**: {cnt} finding{'s' if cnt > 1 else ''}")
    md_lines.append("")

    # Per-severity findings
    for sev in severity_order:
        items = [f for f in findings if f.get("severity") == sev]
        if not items:
            continue
        label = severity_labels.get(sev, sev)
        md_lines.append(f"---")
        md_lines.append(f"## {label} ({len(items)})")
        md_lines.append("")
        for i, f in enumerate(items, 1):
            title_f = f.get("title") or f.get("detail", "")[:80] or "Finding"
            detail = f.get("detail", "")
            tool = f.get("tool", "?")
            tgt = f.get("target", target)
            port = f.get("port", "")
            path = f.get("path", "")
            extra = f" on port {port}" if port else ""
            extra += f" — path `{path}`" if path else ""
            md_lines.append(f"### {i}. {title_f}")
            md_lines.append(f"- **Tool:** {tool} | **Target:** `{tgt}`{extra}")
            if detail:
                md_lines.append(f"- **Detail:** {detail}")
            md_lines.append("")

    # AI Suggestions
    if suggestions:
        md_lines.append("---")
        md_lines.append("## 🤖 AI Suggestions")
        md_lines.append("")
        for s in suggestions:
            ts = s.get("created_at", "")[:16] if s.get("created_at") else ""
            text = s.get("suggestion", s.get("text", ""))
            md_lines.append(f"- *({ts})* {text}")
            md_lines.append("")

    md_lines.append("")
    md_lines.append("---")
    md_lines.append(f"*Generated by VulnForge on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}*")

    md_body = "\n".join(md_lines)

    # Build parsed_data
    parsed_data = {
        "summary": {
            "total": total,
            "by_severity": by_severity,
            "by_tool": by_tool
        },
        "findings": findings,
        "suggestions": suggestions
    }

    # Save to DB
    report = db.save_report({
        "type": "scan",
        "title": title,
        "target": target,
        "raw_output": md_body,
        "parsed_data": parsed_data,
        "format": "md"
    })

    if report:
        return _ok(report, 201)
    else:
        # Return the generated data even if DB save fails
        return _ok({
            "title": title,
            "target": target,
            "raw_output": md_body,
            "parsed_data": parsed_data,
            "format": "md",
            "note": "Saved locally only (DB unavailable)"
        })


# ── Scripts ──

@app.get("/api/scripts")
async def get_scripts():
    return _ok(db.list_scripts())


class ScriptCreate(BaseModel):
    name: str
    content: str
    language: str = "bash"


@app.post("/api/scripts")
async def create_script(script: ScriptCreate):
    return _ok(db.save_script(script.model_dump()), 201)


@app.delete("/api/scripts/{script_id}")
async def delete_script(script_id: str):
    return _delete_ok(db.delete_script(script_id))


# ── SSH Connections ──

@app.get("/api/connections")
async def get_connections():
    return _ok(db.list_connections())


class ConnectionCreate(BaseModel):
    name: str
    ip: str
    username: str
    password: str


@app.post("/api/connections")
async def create_connection(conn: ConnectionCreate):
    return _ok(db.save_connection(conn.model_dump()), 201)


@app.delete("/api/connections/{conn_id}")
async def delete_connection(conn_id: str):
    return _delete_ok(db.delete_connection(conn_id))


# ── Hak5 Payloads ──

@app.get("/api/payloads")
async def get_payloads(device: str = None):
    return _ok(db.list_hak5_payloads(device))


class PayloadCreate(BaseModel):
    device: str
    name: str
    content: str


@app.post("/api/payloads")
async def create_payload(payload: PayloadCreate):
    return _ok(db.save_hak5_payload(payload.model_dump()), 201)


@app.delete("/api/payloads/{payload_id}")
async def delete_payload(payload_id: str):
    return _delete_ok(db.delete_hak5_payload(payload_id))


# ── File Upload (to Supabase Storage) ──

@app.get("/api/files")
async def get_files():
    return _ok(db.list_uploaded_files())


@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    """Upload a file to Supabase Storage and record metadata in DB."""
    client = db.get_client()
    if not client:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)

    try:
        # Read file content
        content = await file.read()
        size = len(content)

        # Generate unique filename
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_name = file.filename.replace(" ", "_").replace("..", "_")
        storage_path = f"uploads/{timestamp}_{safe_name}"

        # Upload to Supabase Storage
        bucket = os.getenv("STORAGE_BUCKET", "vulnforge")
        client.storage.from_(bucket).upload(
            path=storage_path,
            file=content,
            file_options={"content-type": file.content_type or "application/octet-stream"}
        )

        # Get public URL
        public_url = client.storage.from_(bucket).get_public_url(storage_path)

        # Save metadata to DB
        meta = {
            "filename": storage_path,
            "original_name": file.filename or safe_name,
            "size_bytes": size,
            "mime_type": file.content_type or "application/octet-stream",
            "storage_path": storage_path,
            "public_url": public_url
        }
        result = db.save_uploaded_file(meta)

        return JSONResponse({
            "ok": True,
            "data": {
                "id": result["id"] if result else None,
                "filename": file.filename,
                "size_bytes": size,
                "public_url": public_url,
                "storage_path": storage_path
            }
        }, status_code=201)

    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── PDF Generation (server-side) ──

class PdfRequest(BaseModel):
    content: str
    title: str = "VulnForge Report"
    author: str = "VulnForge"


@app.post("/api/generate-pdf")
async def generate_pdf(req: PdfRequest):
    """Generate a PDF from markdown-like text using ReportLab."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, PageBreak,
            Table, TableStyle, Preformatted
        )
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.platypus.flowables import HRFlowable

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            title=req.title,
            author=req.author
        )

        styles = getSampleStyleSheet()
        story = []

        # Title
        title_style = ParagraphStyle(
            'CustomTitle', parent=styles['Title'],
            fontSize=18, spaceAfter=12, textColor=colors.HexColor("#d4a843")
        )
        story.append(Paragraph(req.title, title_style))
        story.append(Spacer(1, 6 * mm))

        # Meta line
        date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
        meta_style = ParagraphStyle(
            'Meta', parent=styles['Normal'],
            fontSize=8, textColor=colors.gray
        )
        story.append(Paragraph(f"Generated by VulnForge — {date_str}", meta_style))
        story.append(Spacer(1, 4 * mm))

        # Content — convert simple markdown-like text
        for line in req.content.split("\n"):
            line = line.rstrip()
            if not line:
                story.append(Spacer(1, 2 * mm))
                continue

            # Headers
            if line.startswith("### "):
                s = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=11)
                story.append(Paragraph(line[4:], s))
            elif line.startswith("## "):
                s = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=13)
                story.append(Paragraph(line[3:], s))
            elif line.startswith("# "):
                s = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=15)
                story.append(Paragraph(line[2:], s))
            elif line.startswith("---"):
                story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#3b8f8a")))
            elif line.startswith("```"):
                # Code block — skip markers, capture content
                pass
            elif line.startswith("- ") or line.startswith("* "):
                s = ParagraphStyle('Bullet', parent=styles['Normal'], fontSize=9, leftIndent=12)
                story.append(Paragraph(f"• {line[2:]}", s))
            elif line.startswith("`") and line.endswith("`"):
                s = ParagraphStyle('Code', parent=styles['Code'], fontSize=8)
                story.append(Preformatted(line.strip("`"), s))
            else:
                # Inline formatting
                text = line
                text = text.replace("**", "<b>").replace("**", "</b>")  # bold — crude but works
                text = text.replace("`", "<font face='Courier' size=8>").replace("`", "</font>")
                s = ParagraphStyle('Body', parent=styles['Normal'], fontSize=9, spaceAfter=2)
                story.append(Paragraph(text, s))

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        # Return the PDF as a download
        from fastapi.responses import StreamingResponse
        return StreamingResponse(
            io.BytesIO(pdf_bytes),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{req.title[:50].replace(" ", "_")}.pdf"',
                "Content-Length": str(len(pdf_bytes))
            }
        )

    except ImportError:
        return JSONResponse({"ok": False, "error": "reportlab not installed — run: pip install reportlab"}, status_code=500)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ── Settings ──

class SettingUpdate(BaseModel):
    key: str
    value: object


@app.get("/api/settings/{key}")
async def get_setting(key: str):
    value = db.get_setting(key)
    if value is None and not db.is_available():
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": True, "key": key, "value": value})


@app.post("/api/settings")
async def set_setting(setting: SettingUpdate):
    return _ok(db.set_setting(setting.key, setting.value))


# ════════════════════════════════════════════════════════════════
#  ROOT — serve frontend
# ════════════════════════════════════════════════════════════════

@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))

@app.get("/favicon.ico")
async def favicon():
    favicon_path = os.path.join(frontend_dir, "favicon.ico")
    if os.path.isfile(favicon_path):
        return FileResponse(favicon_path, media_type="image/x-icon")
    return JSONResponse({"detail": "Not Found"}, status_code=404)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    ssh_ip = "192.168.214.142"
    ssh_port = 22
    ssh_user = "javi"
    ssh_pass = "javi"
    channel = None
    stop = asyncio.Event()

    try:
        # ── Wait for authentication JSON ──
        await websocket.send_text("[*] Awaiting authentication... Send JSON: {\"type\":\"auth\",\"ip\":\"...\",\"user\":\"...\",\"pass\":\"...\"}")

        first_msg = await websocket.receive_text()
        try:
            auth_data = json.loads(first_msg)
        except json.JSONDecodeError:
            await websocket.send_text(
                json.dumps({"type": "error", "message": "First message must be JSON {\"type\":\"auth\",\"ip\":...,\"user\":...,\"pass\":...}"})
            )
            await websocket.close(code=1008)
            return

        if not isinstance(auth_data, dict) or auth_data.get("type") != "auth":
            await websocket.send_text(
                json.dumps({"type": "error", "message": "First message must have \"type\":\"auth\""})
            )
            await websocket.close(code=1008)
            return

        ssh_ip = auth_data.get("ip", ssh_ip)
        ssh_port = int(auth_data.get("port", ssh_port))
        ssh_user = auth_data.get("user", ssh_user)
        ssh_pass = auth_data.get("pass", ssh_pass)

        if not ssh_ip or not ssh_user or not ssh_pass:
            await websocket.send_text(
                json.dumps({"type": "error", "message": "Auth JSON must include ip, user, and pass"})
            )
            await websocket.close(code=1008)
            return

        await websocket.send_text(
            json.dumps({"type": "connected", "message": f"Authenticated as {ssh_user}@{ssh_ip}"})
        )

        # ── Connect SSH ──
        await websocket.send_text(f"[*] Connecting to {ssh_user}@{ssh_ip}:{ssh_port} via SSH...")
        await asyncio.to_thread(
            ssh.connect, ssh_ip, port=ssh_port, username=ssh_user, password=ssh_pass,
            timeout=8, look_for_keys=False, allow_agent=False
        )
        await websocket.send_text(f"[+] Connected to {ssh_user}@{ssh_ip}\n")

        # ── Share SSH client with Mobile Lab modules ──
        mobile_set_ssh_client(ssh)
        _active_ssh_client = ssh
        _ssh_credentials = {"ip": ssh_ip, "user": ssh_user, "pass": ssh_pass}

        # ── Open interactive shell with PTY ──
        channel = ssh.invoke_shell(term='xterm', width=120, height=40)
        channel.setblocking(0)

        # Small delay to let shell initialize before sending commands
        await asyncio.sleep(0.3)

        # Disable Powerlevel10k fancy prompt for clean terminal output
        channel.send("p10k disable 2>/dev/null; PROMPT='$ '; RPROMPT=''\n")

        # ── Record the interactive shell's PID for tab completion ──
        # We read /proc/<pid>/cwd via exec_command (no markers, no visible output)
        channel.send("echo $$ > /tmp/.vfshell 2>/dev/null\n")
        _shell_pid = [None]

        # Mutable references for sharing between coroutines
        _ch = [channel]
        _ip = [ssh_ip]
        _port = [ssh_port]
        _user = [ssh_user]
        _pass = [ssh_pass]

        async def read_shell():
            """Forward SSH shell output → WebSocket (non-blocking)."""
            try:
                while not stop.is_set():
                    ch = _ch[0]
                    try:
                        if ch.recv_ready():
                            data = ch.recv(8192).decode("utf-8", errors="replace")
                            await websocket.send_text(data)
                    except (OSError, EOFError):
                        break
                    await asyncio.sleep(0.02)
            except Exception:
                pass
            finally:
                stop.set()

        async def read_ws():
            """Forward WebSocket messages → SSH shell."""
            try:
                while not stop.is_set():
                    msg = await websocket.receive_text()

                    # Check for JSON control messages
                    try:
                        cmd = json.loads(msg)
                        if isinstance(cmd, dict):
                            if cmd.get("type") == "auth":
                                _ch[0].close()
                                await asyncio.to_thread(
                                    ssh.connect, cmd.get("ip", _ip[0]),
                                    port=int(cmd.get("port", 22)),
                                    username=cmd.get("user", _user[0]),
                                    password=cmd.get("pass", _pass[0]),
                                    timeout=8, look_for_keys=False, allow_agent=False
                                )
                                _ch[0] = ssh.invoke_shell(term='xterm', width=120, height=40)
                                _ch[0].setblocking(0)
                                await asyncio.sleep(0.3)  # let shell init before prompt clean
                                _ch[0].send("p10k disable 2>/dev/null; PROMPT='$ '; RPROMPT=''\n")
                                _ch[0].send("echo $$ > /tmp/.vfshell 2>/dev/null\n")
                                _ip[0] = cmd.get("ip", _ip[0])
                                _user[0] = cmd.get("user", _user[0])
                                _pass[0] = cmd.get("pass", _pass[0])
                                # Update shared SSH client for Mobile Lab
                                mobile_set_ssh_client(ssh)
                                _active_ssh_client = ssh
                                _ssh_credentials = {"ip": _ip[0], "user": _user[0], "pass": _pass[0]}
                                await websocket.send_text(f"[+] Re-connected as {_user[0]}@{_ip[0]}")
                                continue
                            if cmd.get("type") == "resize":
                                _ch[0].resize_pty(
                                    width=cmd.get("width", 120),
                                    height=cmd.get("height", 40)
                                )
                                continue
                            if cmd.get("type") == "interrupt":
                                # Send Ctrl+C (SIGINT) to kill the foreground process
                                _ch[0].send("\x03")
                                await websocket.send_text("^C\n⏹ Process interrupted\n")
                                continue
                            if cmd.get("type") == "tab_complete":
                                # ── PID-based approach (clean, no markers, no visible output) ──
                                # We recorded the interactive shell's PID during connection setup.
                                # Then we read /proc/<pid>/cwd via exec_command (invisible to user).
                                try:
                                    partial = cmd.get("text", "")
                                    partial = partial.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`')
                                    is_cmd = cmd.get("is_command", False)
                                    comp_type = "-c" if is_cmd else "-f --"

                                    def _run():
                                        # ── Step 1: Read the PID file to find the interactive shell ──
                                        pid_ch = ssh.exec_command("cat /tmp/.vfshell 2>/dev/null")
                                        pid = pid_ch[1].read().decode("utf-8", errors="replace").strip()
                                        if not pid:
                                            # Fallback: try to find any bash/zsh via pgrep (excluding ourselves)
                                            pid_ch = ssh.exec_command(
                                                "bash -c '"
                                                "  mypid=$$; "
                                                "  pgrep -u $USER -x bash zsh 2>/dev/null "
                                                "    | grep -v \"^$mypid$\" "
                                                "    | tail -1"
                                                "'"
                                            )
                                            pid = pid_ch[1].read().decode("utf-8", errors="replace").strip()
                                        if not pid:
                                            cwd = f"/home/{ssh_user}"
                                        else:
                                            # ── Step 2: Read CWD from /proc/<pid>/cwd ──
                                            cwd_ch = ssh.exec_command(f"readlink /proc/{pid}/cwd 2>/dev/null || echo $HOME")
                                            cwd = cwd_ch[1].read().decode("utf-8", errors="replace").strip()
                                            if not cwd:
                                                cwd = f"/home/{ssh_user}"
                                        cwd_quoted = shlex.quote(cwd)

                                        # ── Step 3: Run compgen from that CWD ──
                                        comp_ch = ssh.exec_command(
                                            f"bash -c 'cd {cwd_quoted} && compgen {comp_type} \"{partial}\" 2>/dev/null' "
                                            f"| tr '\\n' ' '"
                                        )
                                        return comp_ch[1].read().decode("utf-8", errors="replace").strip()

                                    raw = await asyncio.to_thread(_run)
                                    completions = raw.split() if raw else []
                                    await websocket.send_text(json.dumps({
                                        "type": "tab_result",
                                        "completions": completions
                                    }))
                                except Exception as e:
                                    await websocket.send_text(json.dumps({
                                        "type": "tab_result",
                                        "completions": [],
                                        "error": str(e)
                                    }))
                                continue
                    except json.JSONDecodeError:
                        pass

                    # ── Scope Guard: validate command ──
                    if not msg.startswith("sudo ") and not msg.startswith("p10k ") and "PROMPT=" not in msg:
                        from backend.scope_guard import validate_command, log_block
                        scope_check = validate_command(msg)
                        if scope_check:
                            log_block(scope_check)
                            if scope_check.get("mode") == "block":
                                await websocket.send_text(
                                    json.dumps({
                                        "type": "scope_block",
                                        "message": f"🔒 BLOCKED: {scope_check['message']}",
                                        "targets": scope_check["targets"],
                                    })
                                )
                                await websocket.send_text(
                                    f"\n⚠ 🔒 Scope Guard BLOCKED: {scope_check['message']}\n"
                                )
                                continue  # Skip sending to SSH
                            else:
                                # Warn mode: send warning but allow
                                await websocket.send_text(
                                    f"\n⚠ 🔒 Scope Warning: {scope_check['message']}\n"
                                )

                    # If sudo command and we know password, use heredoc with quoted delimiter
                    # The 'SUDOEOF' (quoted) prevents shell expansion of $, `, \, etc.
                    if msg.startswith("sudo ") and _pass[0]:
                        rest = msg[5:]  # everything after "sudo "
                        _ch[0].send(f"sudo -S {rest} << 'SUDOEOF'\n{_pass[0]}\nSUDOEOF\n")
                    else:
                        # Regular command → send to shell
                        _ch[0].send(msg + "\n")
            except Exception:
                pass
            finally:
                stop.set()

        # ── Run both tasks concurrently ──
        tasks = [asyncio.create_task(read_shell()), asyncio.create_task(read_ws())]
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)

    except WebSocketDisconnect:
        print("[*] WebSocket client disconnected")
    except paramiko.AuthenticationException:
        await websocket.send_text("[!] SSH authentication failed")
    except paramiko.SSHException as e:
        await websocket.send_text(f"[!] SSH connection error: {str(e)}")
    except Exception as e:
        await websocket.send_text(f"[!] Error: {str(e)}")
    finally:
        stop.set()
        if channel:
            try:
                channel.close()
            except:
                pass
        try:
            ssh.close()
        except:
            pass


# ════════════════════════════════════════════════════════════════
#  SWARM API (Fase 4 — Multi-Operator)
# ════════════════════════════════════════════════════════════════

from backend.swarm import SwarmCoordinator, get_session, list_sessions


class SwarmStartRequest(BaseModel):
    target: str
    ssh_ip: str = ""
    ssh_user: str = ""
    ssh_pass: str = ""


@app.post("/api/swarm/start")
async def swarm_start(req: SwarmStartRequest):
    """Start a new swarm pipeline."""
    if not req.target:
        return JSONResponse({"ok": False, "error": "Target is required"}, status_code=400)

    # Use defaults if SSH credentials not provided
    ssh_ip = req.ssh_ip or os.getenv("KALI_IP", "192.168.214.142")
    ssh_user = req.ssh_user or os.getenv("KALI_USER", "javi")
    ssh_pass = req.ssh_pass or os.getenv("KALI_PASS", "javi")

    swarm = SwarmCoordinator(
        target=req.target,
        ssh_ip=ssh_ip,
        ssh_user=ssh_user,
        ssh_pass=ssh_pass,
    )
    swarm.start()

    return JSONResponse({
        "ok": True,
        "session_id": swarm.session_id,
        "status": swarm.status,
    }, status_code=201)


@app.get("/api/swarm/{session_id}")
async def swarm_status(session_id: str):
    """Get swarm session status."""
    swarm = get_session(session_id)
    if not swarm:
        return JSONResponse({"ok": False, "error": "Session not found"}, status_code=404)
    return JSONResponse({"ok": True, "data": swarm.to_dict()})


@app.post("/api/swarm/{session_id}/cancel")
async def swarm_cancel(session_id: str):
    """Cancel a running swarm session."""
    swarm = get_session(session_id)
    if not swarm:
        return JSONResponse({"ok": False, "error": "Session not found"}, status_code=404)
    swarm.cancel()
    return JSONResponse({"ok": True, "status": "cancelled"})


@app.get("/api/swarm/list")
async def swarm_list():
    """List all swarm sessions."""
    sessions = list_sessions()
    return JSONResponse({"ok": True, "data": sessions})


@app.get("/api/swarm/{session_id}/report")
async def swarm_report(session_id: str):
    """Get the report from a completed swarm session."""
    swarm = get_session(session_id)
    if not swarm:
        return JSONResponse({"ok": False, "error": "Session not found"}, status_code=404)

    if swarm.status != "completed":
        return JSONResponse({"ok": False, "error": "Swarm not yet completed"}, status_code=400)

    # Find the report operator's findings which contain the report reference
    report_findings = swarm.get_operator_findings("report")
    report_text = ""
    report_id = None
    for f in report_findings:
        if f.get("tool") == "report" and "report saved" in f.get("title", "").lower():
            report_text = f.get("detail", "")
            # Extract report ID
            import re
            m = re.search(r"ID:\s*(\S+)", f.get("title", ""))
            if m:
                report_id = m.group(1)

    try:
        from backend import database as db
        reports = db.list_reports()
        for r in (reports or []):
            if r.get("type") == "swarm" and r.get("target") == swarm.target:
                return JSONResponse({"ok": True, "data": r})
    except Exception:
        pass

    # Fallback: return the swarm session data
    return JSONResponse({
        "ok": True,
        "data": {
            "title": f"Swarm Report — {swarm.target}",
            "target": swarm.target,
            "raw_output": f"Swarm completed with {len(swarm.findings)} findings. "
                          f"View findings in the session data.",
            "type": "swarm",
        }
    })


# ════════════════════════════════════════════════════════════════
#  MOBILE LAB API
# ════════════════════════════════════════════════════════════════

import uuid as _uuid

MOBILE_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "tmp", "mobile")
os.makedirs(MOBILE_UPLOAD_DIR, exist_ok=True)


@app.post("/api/mobile/upload")
async def mobile_upload(file: UploadFile = File(...)):
    """Upload an APK file for static analysis."""
    if not file.filename or not file.filename.lower().endswith(".apk"):
        return JSONResponse({"ok": False, "error": "Only .apk files are accepted"}, status_code=400)

    apk_id = str(_uuid.uuid4())[:8]
    ext = ".apk"
    dest = os.path.join(MOBILE_UPLOAD_DIR, f"{apk_id}{ext}")

    try:
        content = await file.read()
        if len(content) > 200 * 1024 * 1024:  # 200MB limit
            return JSONResponse({"ok": False, "error": "File too large (max 200MB)"}, status_code=400)
        with open(dest, "wb") as f:
            f.write(content)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Upload failed: {e}"}, status_code=500)

    # Ensure SSH connection for analysis
    await _ensure_ssh_connection()

    # Run analysis in a thread (blocking I/O)
    try:
        result = await asyncio.to_thread(mobile_analyze_apk, dest, apk_id)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Analysis failed: {e}"}, status_code=500)

    # Save to DB (async)
    try:
        result["apk_id"] = apk_id
        result["filename"] = file.filename
        await asyncio.to_thread(db.save_mobile_apk, result)
    except Exception as e:
        logger.warning("Failed to save mobile APK to DB: %s", e)

    if result.get("error"):
        return _ok({
            "apk_id": apk_id,
            "filename": file.filename,
            "error": result["error"],
            "md5": result.get("md5", ""),
            "sha256": result.get("sha256", ""),
            "size": result.get("size", 0),
        })

    return _ok({
        "apk_id": apk_id,
        "filename": file.filename,
        "package": result.get("package", ""),
        "version_name": result.get("version_name", ""),
        "version_code": result.get("version_code", ""),
        "min_sdk": result.get("min_sdk", ""),
        "target_sdk": result.get("target_sdk", ""),
        "size": result.get("size", 0),
        "md5": result.get("md5", ""),
        "sha256": result.get("sha256", ""),
        "findings_count": len(result.get("findings", [])),
        "summary": result.get("summary", {}),
    })


@app.get("/api/mobile/apks")
async def mobile_list_apks_endpoint():
    """List all analyzed APKs."""
    # Try DB first, fall back to in-memory
    apks = None
    try:
        apks = await asyncio.to_thread(db.list_mobile_apks)
    except Exception:
        pass
    if apks is None:
        apks = mobile_list_apks()
    return _ok(apks)


@app.get("/api/mobile/analyze/{apk_id}")
async def mobile_get_analysis(apk_id: str):
    """Get full static analysis results for an APK."""
    # Try DB first
    try:
        result = await asyncio.to_thread(db.get_mobile_apk, apk_id)
        if result:
            return _ok(result)
    except Exception:
        pass
    # Fall back to in-memory
    result = mobile_get_apk(apk_id)
    if not result:
        return JSONResponse({"ok": False, "error": "APK not found"}, status_code=404)
    return _ok(result)


@app.delete("/api/mobile/apks/{apk_id}")
async def mobile_delete_apk_endpoint(apk_id: str):
    """Delete an APK analysis and its extracted files."""
    ok = False
    try:
        ok = await asyncio.to_thread(db.delete_mobile_apk, apk_id)
    except Exception:
        pass
    ok = mobile_delete_apk(apk_id) or ok
    # Clean uploaded file
    try:
        for f in os.listdir(MOBILE_UPLOAD_DIR):
            if f.startswith(apk_id):
                os.remove(os.path.join(MOBILE_UPLOAD_DIR, f))
    except OSError:
        pass
    if not ok:
        return JSONResponse({"ok": False, "error": "APK not found"}, status_code=404)
    return JSONResponse({"ok": True})


@app.get("/api/mobile/devices")
async def mobile_list_devices_endpoint():
    """List ADB devices connected to Kali."""
    await _ensure_ssh_connection()
    devices = mobile_list_devices()
    return _ok(devices)


@app.get("/api/mobile/frida/scripts")
async def mobile_list_frida_scripts_endpoint():
    """List available Frida scripts."""
    scripts = mobile_get_frida_scripts()
    return _ok(scripts)


@app.post("/api/mobile/frida/run")
async def mobile_run_frida_endpoint(body: dict):
    """Run a Frida script on a connected device via Kali SSH."""
    device = body.get("device_serial", "")
    script = body.get("script_name", "template.js")
    target = body.get("target_process", "")

    if not script:
        return JSONResponse({"ok": False, "error": "script_name is required"}, status_code=400)

    await _ensure_ssh_connection()
    output = await asyncio.to_thread(mobile_run_frida_script, device, script, target)
    if output.startswith("ERROR"):
        return JSONResponse({"ok": False, "error": output}, status_code=500)
    return _ok({"output": output[:5000]})


# ════════════════════════════════════════════════════════════════
#  SCOPE GUARD API (Fase 6 — Containment)
# ════════════════════════════════════════════════════════════════

from backend.scope_guard import get_config as scope_get_config, save_config, validate_command, _is_ip
from backend.scope_guard import extract_targets, log_block, get_block_history, clear_block_history


@app.get("/api/scope")
async def scope_get():
    """Get current scope configuration."""
    cfg = scope_get_config(force_refresh=True)
    return JSONResponse({
        "ok": True,
        "data": {
            "enabled": cfg.get("enabled", False),
            "mode": cfg.get("mode", "warn"),
            "targets": cfg.get("targets", []),
            "block_private": cfg.get("block_private", False),
            "blocked_count": len(get_block_history()),
        }
    })


class ScopeUpdateRequest(BaseModel):
    enabled: bool = False
    mode: str = "warn"
    targets: list = []
    block_private: bool = False


@app.post("/api/scope")
async def scope_update(req: ScopeUpdateRequest):
    """Update scope configuration."""
    cfg = {
        "enabled": req.enabled,
        "mode": req.mode if req.mode in ("warn", "block") else "warn",
        "targets": req.targets,
        "block_private": req.block_private,
    }
    ok = save_config(cfg)
    if not ok:
        return JSONResponse({"ok": False, "error": "Failed to save config"}, status_code=500)
    return JSONResponse({"ok": True})


@app.get("/api/scope/history")
async def scope_history():
    """Get blocked/warned command history."""
    return JSONResponse({"ok": True, "data": get_block_history()})


@app.post("/api/scope/history/clear")
async def scope_clear_history():
    """Clear block history."""
    clear_block_history()
    return JSONResponse({"ok": True})


@app.post("/api/scope/validate")
async def scope_validate_command(req: dict):
    """Validate a single command against scope."""
    cmd = req.get("command", "") if isinstance(req, dict) else ""
    if not cmd:
        return JSONResponse({"ok": True, "blocked": False})
    result = validate_command(cmd)
    if result:
        return JSONResponse({"ok": True, **result})
    return JSONResponse({"ok": True, "blocked": False})


# ════════════════════════════════════════════════════════════════
#  CREDENTIAL STORE API
# ════════════════════════════════════════════════════════════════

class CredentialCreate(BaseModel):
    type: str = "password"
    target: str = ""
    username: str = ""
    password: str = ""
    hash: str = ""
    token: str = ""
    service: str = ""
    port: str = ""
    source: str = ""
    notes: str = ""


@app.get("/api/credentials")
async def get_credentials(target: str = "", service: str = ""):
    """List credentials with optional filters."""
    data = db.list_credentials(target=target or None, service=service or None)
    if data is None:
        return JSONResponse({"ok": True, "data": [], "fallback": True})
    return _ok(data)


@app.post("/api/credentials")
async def create_credential(cred: CredentialCreate):
    """Save a credential."""
    result = db.save_credential(cred.model_dump())
    if result is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return _ok(result, 201)


@app.delete("/api/credentials/{cred_id}")
async def remove_credential(cred_id: str):
    """Delete a credential."""
    ok = db.delete_credential(cred_id)
    if ok is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": ok})


@app.delete("/api/credentials")
async def clear_all_credentials():
    """Delete all credentials."""
    ok = db.delete_all_credentials()
    if ok is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return JSONResponse({"ok": ok})


# ════════════════════════════════════════════════════════════════
#  KNOWLEDGE BASE API
# ════════════════════════════════════════════════════════════════
from backend.knowledgebase import search_all, search_cve, search_mitre, get_cve, get_mitre

@app.get("/api/knowledgebase/search")
async def kb_search(query: str = ""):
    """Search CVE + MITRE databases."""
    return _ok(search_all(query))

@app.get("/api/knowledgebase/cve/{cve_id}")
async def kb_cve_detail(cve_id: str):
    """Get single CVE detail."""
    result = get_cve(cve_id)
    if not result:
        return JSONResponse({"ok": False, "error": "CVE not found"}, status_code=404)
    return _ok(result)


@app.get("/api/knowledgebase/mitre/{tech_id}")
async def kb_mitre_detail(tech_id: str):
    """Get single MITRE technique detail."""
    result = get_mitre(tech_id)
    if not result:
        return JSONResponse({"ok": False, "error": "Technique not found"}, status_code=404)
    return _ok(result)


# ════════════════════════════════════════════════════════════════
#  CTF MODE API
# ════════════════════════════════════════════════════════════════

class CTFChallengeCreate(BaseModel):
    title: str
    category: str = ""
    description: str = ""
    flags: str = ""
    points: int = 100
    target: str = ""
    hints: str = ""
    difficulty: str = "medium"


@app.get("/api/ctf/challenges")
async def ctf_list_challenges():
    data = db.list_ctf_challenges()
    if data is None:
        return JSONResponse({"ok": True, "data": [], "fallback": True})
    return _ok(data)


@app.post("/api/ctf/challenges")
async def ctf_create_challenge(challenge: CTFChallengeCreate):
    result = db.save_ctf_challenge(challenge.model_dump())
    if result is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return _ok(result, 201)


@app.post("/api/ctf/challenges/{challenge_id}/solve")
async def ctf_submit_flag(challenge_id: int, body: dict):
    flag = body.get("flag", "")
    if not flag:
        return JSONResponse({"ok": False, "error": "Flag is required"}, status_code=400)
    result = db.solve_ctf_challenge(challenge_id, flag)
    if result is None:
        return JSONResponse({"ok": False, "error": "Database not configured"}, status_code=503)
    return result


@app.delete("/api/ctf/challenges/{challenge_id}")
async def ctf_delete_challenge(challenge_id: int):
    ok = db.delete_ctf_challenge(challenge_id)
    return JSONResponse({"ok": ok})


@app.get("/api/ctf/score")
async def ctf_score():
    result = db.get_ctf_score()
    if result is None:
        return JSONResponse({"ok": True, "data": {"solved": 0, "total": 0, "points": 0, "total_points": 0}, "fallback": True})
    return _ok(result)


# ════════════════════════════════════════════════════════════════
#  FORENSICS LAB API
# ════════════════════════════════════════════════════════════════

FORENSICS_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "tmp", "forensics")
os.makedirs(FORENSICS_UPLOAD_DIR, exist_ok=True)


@app.post("/api/forensics/upload")
async def forensics_upload(file: UploadFile = File(...), category: str = Form("file")):
    """Upload a file for forensic analysis."""
    if not file.filename:
        return JSONResponse({"ok": False, "error": "No filename"}, status_code=400)

    ev_id = str(_uuid.uuid4())[:8]
    dest = os.path.join(FORENSICS_UPLOAD_DIR, f"{ev_id}_{file.filename}")

    try:
        content = await file.read()
        if len(content) > 500 * 1024 * 1024:
            return JSONResponse({"ok": False, "error": "File too large (max 500MB)"}, status_code=400)
        with open(dest, "wb") as f:
            f.write(content)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Upload failed: {e}"}, status_code=500)

    try:
        result = await asyncio.to_thread(forensics_analyze, dest, category)
    except Exception as e:
        return JSONResponse({"ok": False, "error": f"Analysis failed: {e}"}, status_code=500)

    try:
        await asyncio.to_thread(db.save_forensics_evidence, result)
    except Exception as e:
        logger.warning("Failed to save forensics to DB: %s", e)

    return _ok({
        "id": ev_id,
        "filename": file.filename,
        "file_type": result.get("file_type", ""),
        "category": category,
        "size": result.get("size", 0),
        "md5": result.get("md5", ""),
        "sha256": result.get("sha256", ""),
        "findings_count": len(result.get("findings", [])),
        "summary": result.get("summary", {}),
    })


@app.get("/api/forensics/list")
async def forensics_list_endpoint():
    """List all analyzed forensic evidence."""
    items = None
    try:
        items = await asyncio.to_thread(db.list_forensics_evidence)
    except Exception:
        pass
    if items is None:
        items = forensics_list()
    return _ok(items)


@app.get("/api/forensics/analyze/{ev_id}")
async def forensics_get_analysis(ev_id: str):
    """Get full analysis for evidence item."""
    result = None
    try:
        result = await asyncio.to_thread(db.get_forensics_evidence, ev_id)
    except Exception:
        pass
    if not result:
        result = forensics_get(ev_id)
    if not result:
        return JSONResponse({"ok": False, "error": "Evidence not found"}, status_code=404)
    return _ok(result)


@app.post("/api/forensics/analyze/{ev_id}/run")
async def forensics_run_tool_endpoint(ev_id: str, body: dict):
    """Run a specific forensic tool on evidence."""
    tool = body.get("tool", "strings")
    ev = forensics_get(ev_id)
    if not ev:
        return JSONResponse({"ok": False, "error": "Evidence not found"}, status_code=404)

    filepath = os.path.join(FORENSICS_UPLOAD_DIR, f"{ev_id}_{ev.get('filename', '')}")
    if not os.path.exists(filepath):
        for f in os.listdir(FORENSICS_UPLOAD_DIR):
            if f.startswith(ev_id):
                filepath = os.path.join(FORENSICS_UPLOAD_DIR, f)
                break
        else:
            return JSONResponse({"ok": False, "error": "File not found on disk"}, status_code=404)

    result = await asyncio.to_thread(forensics_run_tool, filepath, tool, body.get("params", {}))
    return _ok(result)


@app.delete("/api/forensics/{ev_id}")
async def forensics_delete_endpoint(ev_id: str):
    """Delete evidence and analysis."""
    ok = False
    try:
        ok = await asyncio.to_thread(db.delete_forensics_evidence, ev_id)
    except Exception:
        pass
    ok = forensics_delete(ev_id) or ok
    for f in os.listdir(FORENSICS_UPLOAD_DIR):
        if f.startswith(ev_id):
            os.remove(os.path.join(FORENSICS_UPLOAD_DIR, f))
    if not ok:
        return JSONResponse({"ok": False, "error": "Evidence not found"}, status_code=404)
    return JSONResponse({"ok": True})


# ════════════════════════════════════════════════════════════════
#  OPSEC LEVELS API (Silent / Covert / Loud)
# ════════════════════════════════════════════════════════════════

@app.get("/api/opsec/levels")
async def opsec_levels():
    """List the three OPSEC levels and their descriptions.

    Consumed by the frontend header selector and the MCP server / AI
    suggest loop to know which stealth mode is active.
    """
    return JSONResponse({"ok": True, "levels": LEVELS_INFO})


class OpsecApplyRequest(BaseModel):
    tool: str
    command: str
    level: str = "loud"
    target: str = ""  # optional; only used by legacy full-replacement modifiers


@app.post("/api/opsec/apply")
async def opsec_apply_endpoint(req: OpsecApplyRequest):
    """Apply OPSEC transformations to a tool command.

    Returns ``{"ok": True, "blocked": bool, "reason": str,
    "modified_command": str}``. When ``blocked`` is true the caller
    (frontend, MCP, n8n) must NOT launch the command.

    The optional ``target`` field is only consulted when a modifier is a
    full-replacement command (rare — all shipped modifiers are
    flags-only). Passing an empty/None target is safe: the endpoint
    falls back to passthrough rather than risk a localhost scan.
    """
    try:
        result = opsec_apply(req.tool, req.command, req.level, req.target or None)
        return JSONResponse({"ok": True, **result})
    except Exception as e:
        logger.error("[opsec/apply] %s", e)
        return JSONResponse(
            {"ok": False, "error": f"opsec apply failed: {e}"},
            status_code=500,
        )


# ════════════════════════════════════════════════════════════════
#  MISSION HISTORY API (self-improvement loop)
# ════════════════════════════════════════════════════════════════

class MissionSaveRequest(BaseModel):
    target: str
    os_detected: str = ""
    tools_used: list = []
    findings_count: int = 0
    findings_summary: list = []
    plan_steps: int = 0
    success_score: int = 0


@app.get("/api/missions")
async def missions_list(limit: int = 50, target: str = ""):
    """List past missions, newest first, optionally filtered by target."""
    try:
        data = list_missions(limit=limit, target=target or None)
        if data is None:
            # Supabase not configured → empty list so UI doesn't crash
            return JSONResponse({"ok": True, "data": [], "fallback": True})
        return JSONResponse({"ok": True, "data": data})
    except Exception as e:
        logger.error("[missions list] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/missions/save")
async def missions_save(req: MissionSaveRequest):
    """Persist a completed mission for the self-improvement loop."""
    try:
        row = await asyncio.to_thread(
            save_mission, req.model_dump()
        )
        if row is None:
            # DB not configured OR empty target — graceful degradation
            return JSONResponse(
                {"ok": False, "error": "Database not configured or target empty"},
                status_code=503,
            )
        return JSONResponse({"ok": True, "data": row})
    except Exception as e:
        logger.error("[missions save] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.delete("/api/missions/{mission_id}")
async def missions_delete(mission_id: str):
    """Delete a single mission by UUID."""
    try:
        ok = await asyncio.to_thread(
            _db_module.delete_mission_history, mission_id
        )
        return _delete_ok(ok)
    except Exception as e:
        logger.error("[missions delete] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/missions/similar")
async def missions_similar(target_os: str = "", tools: str = "", limit: int = 5):
    """Find past missions similar to the current engagement.

    Query params:
      - ``target_os`` — OS / banner substring to match (ilike)
      - ``tools``     — comma-separated list of already-run tools
      - ``limit``     — max results (default 5)
    """
    try:
        tool_list = [t.strip() for t in tools.split(",") if t.strip()] if tools else []
        rows = await asyncio.to_thread(
            find_similar,
            target_os or None,
            tool_list or None,
            limit,
        )
        return JSONResponse({"ok": True, "data": rows})
    except Exception as e:
        logger.error("[missions similar] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


# ════════════════════════════════════════════════════════════════
#  MISSION PLANS API (Op Admiral)
# ════════════════════════════════════════════════════════════════

@app.get("/api/plans")
async def plans_list(target: str = "", limit: int = 20):
    """List saved mission plans."""
    try:
        data = list_mission_plans(limit=limit, target=target or None)
        return JSONResponse({"ok": True, "data": data or []})
    except Exception as e:
        logger.error("[plans list] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


class MissionPlanSaveRequest(BaseModel):
    id: str = ""
    target: str = ""
    name: str = ""
    steps: list = []
    total_steps: int = 0
    completed_steps: int = 0
    status: str = "active"


@app.post("/api/plans")
async def plans_save(req: MissionPlanSaveRequest):
    """Save or update a mission plan."""
    try:
        row = await asyncio.to_thread(save_mission_plan, req.model_dump())
        return JSONResponse({"ok": True, "data": row}) if row else JSONResponse(
            {"ok": False, "error": "Save failed"}, status_code=503)
    except Exception as e:
        logger.error("[plans save] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.delete("/api/plans/{plan_id}")
async def plans_delete(plan_id: str):
    """Delete a mission plan."""
    ok = delete_mission_plan(plan_id)
    if ok is None:
        return JSONResponse({"ok": False, "error": "DB unavailable"}, status_code=503)
    return JSONResponse({"ok": ok})


# ════════════════════════════════════════════════════════════════
#  SCOPE EVENTS API (audit log)
# ════════════════════════════════════════════════════════════════

@app.get("/api/scope/events")
async def scope_events_list(limit: int = 100):
    """List scope guard events."""
    try:
        data = list_scope_events(limit=limit)
        return JSONResponse({"ok": True, "data": data or []})
    except Exception as e:
        logger.error("[scope events list] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.post("/api/scope/events")
async def scope_events_save(event: dict):
    """Log a scope guard event."""
    try:
        row = await asyncio.to_thread(save_scope_event, event)
        return JSONResponse({"ok": True, "data": row}) if row else JSONResponse(
            {"ok": False, "error": "Save failed"}, status_code=503)
    except Exception as e:
        logger.error("[scope events save] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.delete("/api/scope/events")
async def scope_events_clear():
    """Clear all scope events."""
    ok = clear_scope_events()
    if ok is None:
        return JSONResponse({"ok": False, "error": "DB unavailable"}, status_code=503)
    return JSONResponse({"ok": ok})


# ════════════════════════════════════════════════════════════════
#  SWARM SESSIONS API
# ════════════════════════════════════════════════════════════════

@app.get("/api/swarm/sessions")
async def swarm_sessions_list(limit: int = 20):
    """List swarm sessions."""
    try:
        data = list_swarm_sessions(limit=limit)
        return JSONResponse({"ok": True, "data": data or []})
    except Exception as e:
        logger.error("[swarm sessions list] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.get("/api/swarm/sessions/{session_id}")
async def swarm_sessions_get(session_id: str):
    """Get a single swarm session."""
    row = get_swarm_session(session_id)
    if not row:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    return JSONResponse({"ok": True, "data": row})


class SwarmSessionSaveRequest(BaseModel):
    target: str = ""
    mode: str = "auto"
    status: str = "running"
    phases: list = []
    total_findings: int = 0
    error: str = ""


@app.post("/api/swarm/sessions")
async def swarm_sessions_save(req: SwarmSessionSaveRequest):
    """Save a swarm session."""
    try:
        row = await asyncio.to_thread(save_swarm_session, req.model_dump())
        return JSONResponse({"ok": True, "data": row}) if row else JSONResponse(
            {"ok": False, "error": "Save failed"}, status_code=503)
    except Exception as e:
        logger.error("[swarm sessions save] %s", e)
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)


@app.delete("/api/swarm/sessions/{session_id}")
async def swarm_sessions_delete(session_id: str):
    """Delete a swarm session."""
    ok = delete_swarm_session(session_id)
    if ok is None:
        return JSONResponse({"ok": False, "error": "DB unavailable"}, status_code=503)
    return JSONResponse({"ok": ok})


# ════════════════════════════════════════════════════════════════
#  APP CREDENTIALS API (encrypted secrets)
# ════════════════════════════════════════════════════════════════

@app.get("/api/credentials/secrets/{key}")
async def secret_get(key: str):
    """Retrieve a stored credential (use only for server-side reads)."""
    value = get_app_credential(key)
    if value is None:
        return JSONResponse({"ok": False, "error": "Not found"}, status_code=404)
    # Never return the actual value to the frontend — only confirm existence
    return JSONResponse({"ok": True, "stored": True})


class SecretSaveRequest(BaseModel):
    key: str
    value: str
    description: str = ""


@app.post("/api/credentials/secrets")
async def secret_save(req: SecretSaveRequest):
    """Store a credential. WARNING: value is stored as-is (not encrypted)."""
    ok = save_app_credential(req.key, req.value, req.description)
    if not ok:
        return JSONResponse({"ok": False, "error": "DB unavailable"}, status_code=503)
    return JSONResponse({"ok": True})


@app.delete("/api/credentials/secrets/{key}")
async def secret_delete(key: str):
    """Delete a stored credential."""
    ok = delete_app_credential(key)
    if ok is None:
        return JSONResponse({"ok": False, "error": "DB unavailable"}, status_code=503)
    return JSONResponse({"ok": ok})


# ════════════════════════════════════════════════════════════════
#  Direct execution: python main.py   or   python backend/main.py
# ════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import uvicorn

    # Detect where we're running from to build the correct module path
    this_dir = os.path.basename(os.path.dirname(os.path.abspath(__file__)))
    cwd_dir = os.path.basename(os.path.abspath(os.getcwd()))

    if cwd_dir == "backend":
        # We're inside backend/ — use relative module name
        app_str = "main:app"
        print("[*] Running from backend/ directory — using 'main:app'")
    else:
        # We're at project root or elsewhere — use fully qualified name
        app_str = "backend.main:app"

    port = int(os.getenv("PORT", "8000"))
    mode_str = "PRODUCTION" if PRODUCTION else "DEVELOPMENT"
    print("=" * 50)
    print(f"  VulnForge — Red Team Dashboard ({mode_str})")
    print(f"  Version {VERSION}")
    print(f"  -> http://localhost:{port}")
    if PRODUCTION:
        print(f"  -> Remote: https://vulnforge.YOUR-DOMAIN.com")
    print("=" * 50)
    uvicorn.run(app_str, host="0.0.0.0", port=port, reload=(port == 8000))
