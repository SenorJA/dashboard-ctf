"""
Manual end-to-end check for the Code Agent (opencode) bridge.

Requires the real `opencode` CLI on PATH (or MIRV_OPENCODE_BIN). Runs
against a live FastAPI app via TestClient. Use when verifying Pack 10:

    cd backend
    PYTHONIOENCODING=utf-8 python tests/manual_e2e_opencode.py

Exit 0 = all checks passed.
"""
import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import app  # noqa: E402  (matches conftest import style)

_OK = 0


def check(label: str, cond: bool) -> None:
    global _OK
    status = "PASS" if cond else "FAIL"
    if not cond:
        _OK = 1
    print(f"[{status}] {label}")


def main() -> int:
    c = TestClient(app)
    headers = {}
    if os.environ.get("MIRV_API_TOKEN"):
        headers["X-MIRV-Token"] = os.environ["MIRV_API_TOKEN"]

    print("── Code Agent status ──")
    r = c.get("/api/opencode/status", headers=headers)
    check("status returns 200", r.status_code == 200)
    body = r.json()
    check("backend detects opencode installed", body.get("installed") is True)
    check("version surfaced", bool(body.get("version")))
    check("allowed agents public", set(body.get("allowed_agents", [])) == {"build", "plan", "general"})

    print("── Phishing sim basics (untouched) ──")
    r = c.get("/api/phishing/stats", headers=headers)
    check("phishing stats 200", r.status_code == 200)
    r = c.get("/phishing/does-not-exist")
    check("ended landing returns 410", r.status_code == 410)

    print("── Code Agent run (live opencode) ──")
    r = c.post("/api/opencode/run", headers=headers,
               json={"prompt": "responde solo OK", "agent": "plan", "pure": True, "timeout": 60})
    check("run returns 200", r.status_code == 200)
    body = r.json()
    check("run ok", body.get("ok") is True and body.get("exit_code") == 0)
    out = (body.get("stdout") or body.get("stderr") or "").strip()
    check("run produced output", bool(out))
    secret_probe = "AKIA1111111111111111" in out
    check("output redacted / no fake-aws leak", not secret_probe)

    print(f"\nResult: {'ALL PASS' if _OK == 0 else 'FAILURES PRESENT'}")
    return _OK


if __name__ == "__main__":
    sys.exit(main())