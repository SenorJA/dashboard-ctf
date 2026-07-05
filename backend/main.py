"""
VulnForge — Backend Server
FastAPI + WebSocket + Paramiko (Dynamic SSH)
"""

import json
import os
import sys
import asyncio
import urllib.request
import urllib.error

# ── Fix path: allow import from project root even when run from backend/ ──
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import paramiko

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
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

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


@app.get("/")
async def read_index():
    return FileResponse(os.path.join(frontend_dir, "index.html"))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    # ── Default credentials (fallback) ──
    ssh_ip = "192.168.214.142"
    ssh_user = "javi"
    ssh_pass = "javi"

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        # ── Wait for initial auth message or first command ──
        await websocket.send_text("[*] Awaiting authentication...")

        first_msg = await websocket.receive_text()
        pending_first_command = None  # flag: first message was a command, not auth

        # Try to parse as JSON auth
        try:
            auth_data = json.loads(first_msg)
            if isinstance(auth_data, dict) and auth_data.get("type") == "auth":
                ssh_ip = auth_data.get("ip", ssh_ip)
                ssh_user = auth_data.get("user", ssh_user)
                ssh_pass = auth_data.get("pass", ssh_pass)
                await websocket.send_text(
                    json.dumps({"type": "connected", "message": f"Authenticating as {ssh_user}@{ssh_ip}..."})
                )
            else:
                await websocket.send_text(
                    json.dumps({"type": "error", "message": "Invalid auth format, using defaults"})
                )
                pending_first_command = first_msg
                await websocket.send_text("[*] Using default credentials (Kali).")
        except json.JSONDecodeError:
            # Not JSON — treat as first command
            pending_first_command = first_msg
            await websocket.send_text("[*] Using default credentials (Kali).")

        # ── Connect SSH ──
        await websocket.send_text(f"[*] Connecting to {ssh_user}@{ssh_ip} via SSH...")
        await asyncio.to_thread(ssh.connect, ssh_ip, username=ssh_user, password=ssh_pass, timeout=8)
        await websocket.send_text(f"[+] Connected to {ssh_user}@{ssh_ip}\n")

        # If first message was a command (not auth), execute it now
        if pending_first_command is not None:
            prompt = f"{ssh_user}@{ssh_ip}:~$ "
            await websocket.send_text(f"{prompt}{pending_first_command}")
            stdin, stdout, stderr = ssh.exec_command(pending_first_command)
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            if out:
                await websocket.send_text(out)
            if err:
                await websocket.send_text(f"[STDERR]: {err}")

        # ── Command loop ──
        while True:
            command = await websocket.receive_text()

            # Allow re-auth at any time
            try:
                reauth = json.loads(command)
                if isinstance(reauth, dict) and reauth.get("type") == "auth":
                    ssh_ip = reauth.get("ip", ssh_ip)
                    ssh_user = reauth.get("user", ssh_user)
                    ssh_pass = reauth.get("pass", ssh_pass)
                    ssh.close()
                    await websocket.send_text("[*] Reconnecting with new credentials...")
                    await asyncio.to_thread(ssh.connect, ssh_ip, username=ssh_user, password=ssh_pass, timeout=8)
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
        await websocket.send_text(f"[!] SSH authentication failed for {ssh_user}@{ssh_ip}")
    except paramiko.SSHException as e:
        await websocket.send_text(f"[!] SSH connection error: {str(e)}")
    except Exception as e:
        await websocket.send_text(f"[!] Error: {str(e)}")
    finally:
        try:
            ssh.close()
        except:
            pass
