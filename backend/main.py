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
import urllib.request
import urllib.error
from datetime import datetime

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

app = FastAPI()

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
    provider: str = "openai"       # openai | gemini | anthropic | openrouter
    api_key: str = ""
    model: str = ""
    target: str = ""
    findings: str = ""
    history: list = []              # list of {"role":"user"/"assistant","content":"..."}
    system_prompt: str = ""

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
    if provider == "openai" or provider == "openrouter":
        base = "https://api.openai.com/v1" if provider == "openai" else "https://openrouter.ai/api/v1"
        if not model: model = "gpt-4o-mini"
        url = f"{base}/chat/completions"
        body = json.dumps({
            "model": model,
            "messages": messages,
            "temperature": 0.3,
            "max_tokens": 1024
        }).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("Authorization", f"Bearer {api_key}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", str(data))
            return str(data)

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
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data.get("content", [])
            if content:
                return content[0].get("text", str(data))
            return str(data)

    else:
        raise ValueError(f"Unknown provider: {provider}")

@app.post("/api/suggest")
async def suggest_next_step(req: SuggestRequest):
    """AI-powered suggestion for the next penetration testing step."""
    try:
        if not req.api_key:
            return JSONResponse({"ok": False, "error": "API key is required"}, status_code=400)

        # Build messages
        system = req.system_prompt or _build_suggest_prompt(req.target, req.findings)
        messages = [{"role": "system", "content": system}]

        # Add history
        for h in req.history:
            messages.append({"role": h.get("role", "user"), "content": h.get("content", "")})

        # Add current context as user message
        user_msg = f"Target: {req.target}\n\nCurrent findings:\n{req.findings if req.findings else 'None yet'}\n\nWhat should I do next?"
        messages.append({"role": "user", "content": user_msg})

        result = await asyncio.to_thread(
            _call_llm_sync, req.provider, req.api_key, req.model, messages, 60
        )

        return JSONResponse({"ok": True, "suggestion": result})

    except urllib.error.HTTPError as e:
        return JSONResponse({"ok": False, "error": f"API error {e.code}: {e.read().decode('utf-8', errors='replace')[:500]}"}, status_code=502)
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)}, status_code=500)

# ════════════════════════════════════════════════════════════════
#  SUPABASE API ENDPOINTS
# ════════════════════════════════════════════════════════════════

@app.get("/api/health")
async def api_health():
    """Check if Supabase is configured and reachable."""
    ok = db.is_available()
    return JSONResponse({
        "status": "ok" if ok else "degraded",
        "supabase": ok,
        "database": "supabase" if ok else "localstorage (fallback)",
        "version": "1.0"
    })

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
                                await websocket.send_text(f"[+] Re-connected as {_user[0]}@{_ip[0]}")
                                continue
                            if cmd.get("type") == "resize":
                                _ch[0].resize_pty(
                                    width=cmd.get("width", 120),
                                    height=cmd.get("height", 40)
                                )
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

    print("=" * 50)
    print("  VulnForge — Red Team Dashboard")
    print(f"  -> http://localhost:8000")
    print("=" * 50)
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app_str, host="0.0.0.0", port=port, reload=(port == 8000))
