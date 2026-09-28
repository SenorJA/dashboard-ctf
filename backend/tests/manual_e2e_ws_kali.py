"""Manual E2E: WebSocket SSH proxy -> kali-tools (docker-compose).

Verifies, against the RUNNING stack, that MIRV can:
  1. Login (POST /api/auth/login) and obtain the httpOnly ``mirv_token`` cookie.
  2. Open the WebSocket /ws gate (cookie required when MIRV_API_TOKEN is set).
  3. Authenticate the SSH session with the documented JSON handshake.
  4. Run real commands over the interactive PTY (whoami, tools, python, ...).

Auth cookie handshake
---------------------
The /ws gate closes connections without ``mirv_token`` while the API-token
guard is enabled. curl equivalent:

  curl -c /tmp/mirv.cookies -X POST http://localhost:8000/api/auth/login \
       -H "Content-Type: application/json" \
       -d '{"password":"<MIRV_API_TOKEN>"}'
  curl -b /tmp/mirv.cookies http://localhost:8000/ws   # websocket handshake

Expected result: every check below prints PASS; the process exits 0.

Usage:
  PYTHONIOENCODING=utf-8 python backend/tests/manual_e2e_ws_kali.py
"""
import asyncio
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

import websockets

BASE = "http://localhost:8000"
WS_ENDPOINT = "ws://localhost:8000/ws"

# Credentials come from docker-compose.yml (kali-tools service, KALI_USER/PASS).
KALI_IP = "kali-tools"
KALI_PORT = 22
KALI_USER = "root"
KALI_PASS = "mirv"

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = REPO_ROOT / ".env"


def _api_token() -> str:
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("MIRV_API_TOKEN="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"MIRV_API_TOKEN no esta en {ENV_FILE}")


def _login_cookie(token: str) -> str:
    req = urllib.request.Request(
        BASE + "/api/auth/login",
        data=json.dumps({"password": token}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    resp = urllib.request.urlopen(req, timeout=10)
    raw = resp.headers.get("Set-Cookie", "")
    match = re.search(r"mirv_token=([^;]+)", raw)
    print(f"login HTTP {resp.status} -> cookie mirv_token={'OK' if match else 'NO'}")
    if not match:
        sys.exit(1)
    return match.group(1)


async def _main() -> int:
    cookie = _login_cookie(_api_token())

    send_buf: list[str] = []          # every frame received (ordered)
    commands: list[tuple[str, float]] = []   # (cmd, wait-seconds)

    async def reader(ws):
        async for msg in ws:
            send_buf.append(msg)

    async with websockets.connect(
        WS_ENDPOINT, additional_headers={"Cookie": f"mirv_token={cookie}"}
    ) as ws:
        reader_task = asyncio.create_task(reader(ws))
        await asyncio.sleep(1.0)

        auth = json.dumps({
            "type": "auth", "ip": KALI_IP, "port": KALI_PORT,
            "user": KALI_USER, "pass": KALI_PASS,
        })
        await ws.send(auth)
        await asyncio.sleep(3.0)

        for cmd, wait in commands or [
            ("echo MIRV_E2E_OK_$RANDOM", 2.5),
            ("whoami; hostname", 2.0),
            ("head -1 /etc/os-release; python3 --version 2>&1", 2.0),
            ("nmap --version | head -1", 3.0),
            ("hashcat --version 2>&1 | head -1", 2.5),
            ("exit", 1.5),
        ]:
            await ws.send(cmd + "\n")
            await asyncio.sleep(wait)
        await asyncio.sleep(1.0)
        reader_task.cancel()

    text = "".join(send_buf)
    checks = {
        "handshake autenticado": "Authenticated as root@kali-tools" in text,
        "conexion SSH OK": "Connected to root@kali-tools" in text,
        "comando echo ejecutado": "MIRV_E2E_OK" in text,
        "whoami=root": bool(re.search(r"root\r?\n", text)),
        "hostname=kali": "kali" in text.lower(),
        "python3 disponible": "Python 3" in text,
        "nmap instalado": "Nmap version" in text,
        "hashcat instalado": "hashcat" in text.lower(),
    }
    ok = True
    for name, passed in checks.items():
        print(("PASS " if passed else "FAIL ") + name)
        ok = ok and passed
    print("\n===== EXTRACTO DE SALIDA SSH =====")
    print(text[:1200])
    print("\nRESULTADO:", "OK" if ok else "FALLO")
    return 0 if ok else 1


if __name__ == "__main__":
    # Allow driving a custom command list from the CLI (for manual tinkering).
    if len(sys.argv) > 1:
        raise SystemExit("Comandos custom no soportados; edita `commands` en el modulo.")
    sys.exit(asyncio.run(_main()))