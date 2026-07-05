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
from fastapi.staticfiles import StaticFiles
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
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
app.mount("/css", StaticFiles(directory=os.path.join(frontend_dir, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(frontend_dir, "js")), name="js")

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


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # Variables de conexión (se rellenan vía JSON auth)
    ssh_ip = ssh_user = ssh_pass = None

    try:
        # ── Wait for authentication JSON ──
        await websocket.send_text("[*] Awaiting authentication... Send JSON: {\"type\":\"auth\",\"ip\":\"...\",\"user\":\"...\",\"pass\":\"...\"}")

        first_msg = await websocket.receive_text()

        # Parse mandatory JSON auth
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

        ssh_ip = auth_data.get("ip")
        ssh_user = auth_data.get("user")
        ssh_pass = auth_data.get("pass")

        if not ssh_ip or not ssh_user or not ssh_pass:
            await websocket.send_text(
                json.dumps({"type": "error", "message": "Auth JSON must include ip, user, and pass"})
            )
            await websocket.close(code=1008)
            return

        await websocket.send_text(
            json.dumps({"type": "connected", "message": f"Authenticating as {ssh_user}@{ssh_ip}..."})
        )

        # ── Connect SSH ──
        await websocket.send_text(f"[*] Connecting to {ssh_user}@{ssh_ip} via SSH...")
        await asyncio.to_thread(ssh.connect, ssh_ip, username=ssh_user, password=ssh_pass, timeout=8)
        await websocket.send_text(f"[+] Connected to {ssh_user}@{ssh_ip}\n")

        # ── Command loop ──
        while True:
            command = await websocket.receive_text()

            # Allow re-auth at any time
            try:
                reauth = json.loads(command)
                if isinstance(reauth, dict) and reauth.get("type") == "auth":
                    new_ip = reauth.get("ip", ssh_ip)
                    new_user = reauth.get("user", ssh_user)
                    new_pass = reauth.get("pass", ssh_pass)
                    ssh.close()
                    await websocket.send_text("[*] Reconnecting with new credentials...")
                    await asyncio.to_thread(ssh.connect, new_ip, username=new_user, password=new_pass, timeout=8)
                    ssh_ip, ssh_user, ssh_pass = new_ip, new_user, new_pass
                    await websocket.send_text(f"[+] Re-connected as {ssh_user}@{ssh_ip}")
                    continue
            except json.JSONDecodeError:
                pass

            # Normal command execution
            prompt = f"{ssh_user}@{ssh_ip}:~$ "
            await websocket.send_text(f"{prompt}{command}")

            stdin, stdout, stderr = ssh.exec_command(command)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")

            if out:
                await websocket.send_text(out)
            if err:
                await websocket.send_text(f"[STDERR]: {err}")

    except WebSocketDisconnect:
        print("[*] WebSocket client disconnected")
    except paramiko.AuthenticationException:
        await websocket.send_text(f"[!] SSH authentication failed for {ssh_user or '?'}@{ssh_ip or '?'}")
    except paramiko.SSHException as e:
        await websocket.send_text(f"[!] SSH connection error: {str(e)}")
    except Exception as e:
        await websocket.send_text(f"[!] Error: {str(e)}")
    finally:
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
