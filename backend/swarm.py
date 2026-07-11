"""
VulnForge — Swarm Coordinator

Manages multi-operator attack pipelines:
  Recon → Scanner → Exploiter → Report

Each swarm session runs as an asyncio background task.
"""

import asyncio
import uuid
import paramiko
from datetime import datetime
from typing import Optional

from backend.operators import (
    ReconOperator,
    ScannerOperator,
    ExploiterOperator,
    ReportOperator,
)


# ── In-memory session store ──
_sessions = {}  # session_id -> SwarmCoordinator


def get_session(session_id: str) -> Optional["SwarmCoordinator"]:
    return _sessions.get(session_id)


def list_sessions() -> list:
    return [
        {
            "session_id": sid,
            "target": s.target,
            "status": s.status,
            "progress": s.progress,
            "current_operator": s.current_operator,
            "created_at": s.created_at,
        }
        for sid, s in _sessions.items()
    ]


class SwarmCoordinator:
    """
    Coordinates the multi-operator pipeline.
    Runs operators in sequence, collects findings, manages SSH.
    """

    def __init__(self, target: str, ssh_ip: str, ssh_user: str, ssh_pass: str,
                 ssh_port: int = 22):
        self.session_id = str(uuid.uuid4())
        self.target = target
        self.ssh_config = {
            "ip": ssh_ip,
            "port": ssh_port,
            "user": ssh_user,
            "pass": ssh_pass,
        }
        self.status = "pending"  # pending | running | completed | error | cancelled
        self.progress = 0
        self.current_operator = None
        self.created_at = datetime.utcnow().isoformat()
        self.completed_at = None
        self.logs = []
        self.findings = []
        self.operators = []
        self.ssh = None
        self._cancel = False
        self._task = None

    # ── Logging ──

    def add_log(self, message: str):
        ts = datetime.utcnow().strftime("%H:%M:%S")
        self.logs.append(f"[{ts}] {message}")

    def add_finding(self, finding: dict):
        self.findings.append(finding)

    def get_operator_findings(self, name: str) -> list:
        """Get findings from a specific operator."""
        return [f for f in self.findings if f.get("source", "").endswith(f":{name}")]

    def get_all_findings(self) -> list:
        return list(self.findings)

    # ── SSH ──

    async def connect_ssh(self) -> bool:
        """Open SSH connection to the Kali target."""
        try:
            self.add_log(f"Connecting to {self.ssh_config['user']}@{self.ssh_config['ip']}...")
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            await asyncio.to_thread(
                self.ssh.connect,
                self.ssh_config["ip"],
                port=self.ssh_config["port"],
                username=self.ssh_config["user"],
                password=self.ssh_config["pass"],
                timeout=10,
                look_for_keys=False,
                allow_agent=False,
            )
            self.add_log("SSH connected successfully")
            return True
        except Exception as e:
            self.add_log(f"⚠ SSH connection failed: {e}")
            self.status = "error"
            return False

    async def exec_command(self, command: str, timeout: int = 60):
        """
        Execute a command via SSH exec_command.
        Returns (stdin, stdout, stderr) as open file-like objects.
        """
        if not self.ssh:
            raise RuntimeError("SSH not connected")

        chan = self.ssh.get_transport().open_session()
        chan.settimeout(timeout)
        chan.exec_command(command)
        return chan.makefile("rb"), chan.makefile("rb"), chan.makefile_stderr("rb")

    async def close_ssh(self):
        """Close SSH connection."""
        if self.ssh:
            try:
                self.ssh.close()
            except Exception:
                pass
            self.ssh = None

    # ── Pipeline ──

    async def run_pipeline(self):
        """Run the full operator pipeline."""
        if self.status != "pending":
            return

        self.status = "running"
        self._cancel = False

        # Connect SSH
        if not await self.connect_ssh():
            return

        try:
            # Define operators
            self.operators = [
                ReconOperator(),
                ScannerOperator(),
                ExploiterOperator(),
                ReportOperator(),
            ]

            total_operators = len(self.operators)

            for i, operator in enumerate(self.operators):
                if self._cancel:
                    self.add_log("⏹ Swarm cancelled by user")
                    self.status = "cancelled"
                    return

                self.current_operator = operator.name
                operator.status = "running"

                self.add_log(f"▶ Starting operator: {operator.display_name}")

                try:
                    await operator.run(self)
                except Exception as e:
                    operator.status = "error"
                    operator.error = str(e)
                    self.add_log(f"⚠ Operator {operator.display_name} failed: {e}")
                    # Continue with next operator instead of stopping
                    continue

                # Update progress (each operator = 25%)
                self.progress = min(100, int(((i + 1) / total_operators) * 100))

            # Mark as completed
            if self.status != "cancelled":
                self.status = "completed"
                self.completed_at = datetime.utcnow().isoformat()
                self.current_operator = None
                self.progress = 100
                self.add_log(
                    f"✅ Swarm complete — {len(self.findings)} total findings"
                )

        except Exception as e:
            self.status = "error"
            self.add_log(f"⚠ Swarm error: {e}")
        finally:
            await self.close_ssh()

    def start(self):
        """Start the pipeline as a background task."""
        self._task = asyncio.create_task(self.run_pipeline())
        # Register in global sessions
        _sessions[self.session_id] = self

    def cancel(self):
        """Request cancellation."""
        self._cancel = True
        self.status = "cancelled"

    # ── Status ──

    def to_dict(self) -> dict:
        """Serialize session state for the API."""
        return {
            "session_id": self.session_id,
            "target": self.target,
            "status": self.status,
            "progress": self.progress,
            "current_operator": self.current_operator,
            "created_at": self.created_at,
            "completed_at": self.completed_at,
            "operators": [
                {
                    "name": op.name,
                    "display_name": op.display_name,
                    "status": op.status,
                    "commands_run": op.commands_run,
                    "findings_count": len(op.findings),
                    "error": op.error,
                }
                for op in self.operators
            ],
            "logs": self.logs[-200:],  # Last 200 log entries
            "findings": self.findings,
        }
