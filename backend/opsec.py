"""
M.I.R.V. — OPSEC Levels Backend
==============================

Operations Security layer for command modification before SSH dispatch.

This module exposes a pure-function helper
`apply_opsec(tool, command, level, target=None)`
that decides whether a given tool command is:
  - **blocked**  -> too noisy for the requested OPSEC level (silent/covert)
  - **modified** -> rewritten with stealth flags appropriate to the level
  - **passthrough** -> left unchanged (loud / unknown tool / unknown level)

Attack vectors mitigated
------------------------
- **Excessive noise on target (IDS/SIEM evasion):** Silent/Covert strip
  aggressive flags (-A, -O, -T4, masscan --rate=1000) that always trigger
  alerts on the defender side. Reduces the chance of early blue-team
  detection during active reconnaissance.
- **Denial-of-Service to target:** Silent/Covert enforce rate limits so
  the scanner cannot saturate a fragile target (avoids crashing customer
  infra during pentests).
- **Credential lockout (hydra):** Silent blocks online bruteforce
  completely; Covert forces single-thread + wait, preventing account
  lockout policies from triggering and locking out the customer's users.
- **Accidental loud scans in production:** Level is a hard contract — if
  the operator selects Silent, masscan/nikto/nuclei/wpscan/hydra cannot
  be launched at all, removing the risk of forgetting to pass `--stealthy`.
- **Target loss during command rewrite:** Modifiers are *flags-only* — we
  append them to the operator's command so the already-substituted target
  IP/host is never dropped. The `target` parameter is retained for
  backward-compat with full-replacement modifiers (rare; see notes below).
- **Auditable intent:** Every modification returns a human-readable
  `reason`, so the MCP server / AI suggest loop can explain to the
  operator *why* a command was rewritten, instead of silently mutating it.

Design notes
------------
- This module is intentionally **pure** (no I/O, no imports beyond stdlib).
  It can be unit-tested deterministically and safely imported by MCP,
  the AI suggest endpoint, n8n triggers, and the WebSocket dispatcher.
- `BLOCKED` is a sentinel string distinct from `None`:
    * `None`        -> level has no opinion (use the command as supplied)
    * `BLOCKED`     -> level explicitly forbids this tool
    * any other str -> stealth flags to apply (all modifiers are flags-only)
- **All modifiers are flags-only.** This is critical: `launchTool` in the
  frontend has already substituted the target (`{target}` → real host)
  into the command template. If a modifier were a full command like
  `nmap -sS ...`, the original `nmap -A <TARGET>` would be replaced and
  the target would be silently dropped — nmap would then scan localhost.
- `apply_opsec` never mutates its inputs and never raises.
"""

from __future__ import annotations

# ── OPSEC level constants ──────────────────────────────────────────────
LEVEL_SILENT = "silent"
LEVEL_COVERT = "covert"
LEVEL_LOUD = "loud"

# Sentinel signalling "tool is forbidden at this level"
_BLOCKED = "BLOCKED"

# ── Public level descriptor (consumed by /api/opsec/levels) ────────────
LEVELS_INFO = [
    {
        "id": LEVEL_SILENT,
        "name": "Silent",
        "color": "#3b8f8a",
        "emoji": "🟢",
        "description": (
            "Only passive / low-noise tools. Active tools are rewritten "
            "with stealth flags; the noisiest scanners are blocked."
        ),
    },
    {
        "id": LEVEL_COVERT,
        "name": "Covert",
        "color": "#d4a843",
        "emoji": "🟡",
        "description": (
            "Active tools allowed but rate-limited and timed-down. "
            "Loud-only scanners produce a warning but are permitted."
        ),
    },
    {
        "id": LEVEL_LOUD,
        "name": "Loud",
        "color": "#dc2828",
        "emoji": "🔴",
        "description": (
            "Everything allowed at maximum speed. Default behaviour, "
            "no command rewriting is performed."
        ),
    },
]

# ── Per-tool modifier map ─────────────────────────────────────────────
# Every modifier value is **flags-only** (it never starts with the tool
# name). Reasons:
#   * `launchTool` already substituted the target into the command,
#     so a full-replacement modifier would silently drop the target.
#   * Appending flags lets the last-occurrence-wins semantics of most
#     CLI tools blend stealth flags with the operator's command.
#
# Level -> modifier:
#   - flags-only string    → append to the operator's command
#   - None                 → leave command unchanged
#   - _BLOCKED             → forbid the launch
TOOL_MODIFIERS: dict[str, dict[str, str | None]] = {
    # ── Recon / port scan ───────────────────────────────────────────
    "nmap": {
        LEVEL_SILENT: "-sS -T2 -n --max-rate 50 -sV --data-length 24 -g 53",
        LEVEL_COVERT: "-sS -T3 -n --max-rate 200 -sV",
        LEVEL_LOUD:   None,
    },
    "masscan": {
        LEVEL_SILENT: _BLOCKED,                                      # too noisy
        LEVEL_COVERT: "--rate=100 --wait 5",                         # operator supplies -p<range> <target>
        LEVEL_LOUD:   None,
    },
    # ── Web dir brute ───────────────────────────────────────────────
    "gobuster": {
        LEVEL_SILENT: "--delay 500ms -t 5 -q",                       # fixed: --delay, not -delay
        LEVEL_COVERT: "-t 20 -q",
        LEVEL_LOUD:   None,
    },
    "ffuf": {
        LEVEL_SILENT: "-t 2 -rate 10",
        LEVEL_COVERT: "-t 10 -rate 50",
        LEVEL_LOUD:   None,
    },
    "dirb": {
        LEVEL_SILENT: "-r -S",                                       # flags-only: recursive off, silent
        LEVEL_COVERT: "-r",
        LEVEL_LOUD:   None,
    },
    # ── Web vuln scanners ───────────────────────────────────────────
    "nikto": {
        LEVEL_SILENT: _BLOCKED,                                      # too noisy
        LEVEL_COVERT: "-evasion 1 -timeout 5",
        LEVEL_LOUD:   None,
    },
    "nuclei": {
        LEVEL_SILENT: _BLOCKED,                                      # too noisy
        LEVEL_COVERT: "--rate-limit 10 --concurrency 5",             # fixed: --rate-limit + --concurrency
        LEVEL_LOUD:   None,
    },
    "whatweb": {
        LEVEL_SILENT: "-a 1",                                        # passive, single request
        LEVEL_COVERT: None,                                          # default -a 3
        LEVEL_LOUD:   None,
    },
    "wpscan": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "--stealthy",
        LEVEL_LOUD:   "--enumerate u,vp",
    },
    # ── Bruteforce ──────────────────────────────────────────────────
    "hydra": {
        LEVEL_SILENT: _BLOCKED,                                      # prevents account lockout
        LEVEL_COVERT: "-t 1 -W 5 -f",                                # 1 thread, 5s wait, stop on first hit
        LEVEL_LOUD:   "-t 4",
    },
    # ── New tools identified by the security expert ─────────────────
    "wfuzz": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "--hc 404 --hl 0 -t 5",
        LEVEL_LOUD:   None,
    },
    "feroxbuster": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "-t 5 --depth 2 --rate 10 --quiet",
        LEVEL_LOUD:   None,
    },
    "sqlmap": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "--batch --random-agent --delay 2 --risk 1 --level 1",
        LEVEL_LOUD:   None,
    },
    "xsstrike": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "--delay 2 --timeout 5",
        LEVEL_LOUD:   None,
    },
    "dalfox": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "--delay 2 --only-poc r",
        LEVEL_LOUD:   None,
    },
    "cewl": {
        LEVEL_SILENT: "-d 1 -m 5",
        LEVEL_COVERT: "-d 2 -m 5",
        LEVEL_LOUD:   None,
    },
    "netcat": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "-zv -w 2",
        LEVEL_LOUD:   None,
    },
    "enum4linux": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "-s -M -l",
        LEVEL_LOUD:   None,
    },
    "smbclient": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "-N -l",
        LEVEL_LOUD:   None,
    },
    "smbmap": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "-R . --depth 1",
        LEVEL_LOUD:   None,
    },
    "ldapsearch": {
        LEVEL_SILENT: "-x -s base",
        LEVEL_COVERT: "-x -s sub -z 100",
        LEVEL_LOUD:   None,
    },
    "bloodhound": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "-c Group,Computers --2025collection",
        LEVEL_LOUD:   None,
    },
    "responder": {
        LEVEL_SILENT: _BLOCKED,                                      # extremely noisy (LLMNR/NBT-NS poisoner)
        LEVEL_COVERT: _BLOCKED,
        LEVEL_LOUD:   None,
    },
    "testssl": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: "--quiet --fast --parallel 1",
        LEVEL_LOUD:   None,
    },
    "wafw00f": {
        LEVEL_SILENT: "-b",
        LEVEL_COVERT: None,
        LEVEL_LOUD:   "-a",
    },
    "cors-check": {
        LEVEL_SILENT: _BLOCKED,
        LEVEL_COVERT: None,
        LEVEL_LOUD:   None,
    },
    "dnsrecon": {
        LEVEL_SILENT: "-d --type std",
        LEVEL_COVERT: None,
        LEVEL_LOUD:   "-a",
    },
    "curl": {
        LEVEL_SILENT: "-s -I -L --user-agent 'Mozilla/5.0'",
        LEVEL_COVERT: None,
        LEVEL_LOUD:   None,
    },
    # Passive / lookup tools — never noisy, so Silent is a no-op
    "searchsploit": {
        LEVEL_SILENT: None,
        LEVEL_COVERT: None,
        LEVEL_LOUD:   None,
    },
    "evil-winrm": {
        LEVEL_SILENT: None,                                          # interactive shell, single session
        LEVEL_COVERT: None,
        LEVEL_LOUD:   None,
    },
}


def _normalise_tool(tool: str) -> str:
    """Return a lowercase, trimmed tool identifier.

    The frontend arsenal passes tool ids such as ``'nmap-fast'`` or
    ``'gobuster-dir'``. We extract the leading tool name so the modifier
    table lookup still matches.
    """
    if not tool:
        return ""
    t = tool.strip().lower()
    # Strip known suffixes used in arsenal ids (e.g. 'nmap-fast' -> 'nmap')
    for sep in ("-", "/"):
        if sep in t:
            head = t.split(sep, 1)[0]
            if head in TOOL_MODIFIERS:
                return head
    return t


def apply_opsec(tool: str, command: str, level: str, target: str | None = None) -> dict:
    """Apply OPSEC transformations to a tool command.

    Parameters
    ----------
    tool : str
        The tool identifier (e.g. ``"nmap"``, ``"gobuster"``,
        ``"nmap-fast"``). Case-insensitive.
    command : str
        The original command string the operator intends to launch.
        By the time this function is called, the frontend has already
        substituted the target host/IP into the command template.
    level : str
        One of ``LEVEL_SILENT``, ``LEVEL_COVERT``, ``LEVEL_LOUD``.
        Unknown levels fall through to "loud" (passthrough).
    target : str, optional
        The target host/IP. Retained for backward compatibility with
        full-replacement modifiers — see Notes. When the modifier is
        flags-only (the default and the recommended style), ``target``
        is **not** used: the stealth flags are appended to ``command``
        so the already-substituted target survives untouched.

    Returns
    -------
    dict
        ``{"blocked": bool, "reason": str, "modified_command": str}``

        - When ``blocked`` is ``True``, ``modified_command`` is the
          empty string and ``reason`` explains why the tool is forbidden
          at this level.
        - When ``blocked`` is ``False``, ``modified_command`` is the
          (possibly rewritten) command ready to be sent over SSH, and
          ``reason`` describes the transformation (empty string when the
          command is left untouched).

    Notes
    -----
    * The function is total — it never raises, even on garbage input.
      An unknown tool or level degrades to "passthrough" so the operator
      can always proceed.
    * **All shipped modifiers are flags-only** (they never start with
      the tool name). This guarantees the target already substituted
      into ``command`` is preserved — fixing the P0 bug where nmap in
      Silent mode would scan localhost because the whole `nmap ...`
      command was replaced.
    * The legacy "full-replacement" path is kept for external callers /
      MCP integrations that may still pass a full-command modifier: if
      a modifier starts with the tool name, we honour it by appending
      the supplied ``target``. If ``target`` is empty/falsy, we fall back
      to passthrough (safer than scanning localhost) and emit a reason
      so the operator is alerted.

    Attack vectors mitigated
    ------------------------
    See module docstring. In short: IDS evasion, DoS on fragile targets,
    credential-lockout prevention, target-preservation during stealth
    rewriting, and auditable stealth-mode intent.
    """
    tool_id = _normalise_tool(tool)
    level_id = (level or "").strip().lower() or LEVEL_LOUD

    if not command:
        return {"blocked": False, "reason": "", "modified_command": ""}

    modifiers = TOOL_MODIFIERS.get(tool_id)
    if not modifiers:
        # Unknown tool — never block, never modify: preserve operator intent.
        return {"blocked": False, "reason": "", "modified_command": command}

    modifier = modifiers.get(level_id)
    if modifier is _BLOCKED:
        return {
            "blocked": True,
            "reason": (
                f"{tool_id} is blocked in {level_id} OPSEC mode "
                f"(too noisy — switch to Covert/Loud to allow)"
            ),
            "modified_command": "",
        }
    if modifier is None:
        # Level has no opinion: pass through unchanged (loud default).
        return {"blocked": False, "reason": "", "modified_command": command}

    # Non-empty modifier string
    tokens = modifier.split()
    first_token = tokens[0] if tokens else ""
    if first_token == tool_id:
        # Legacy full-replacement path. The original command (with its
        # already-substituted target) would be dropped, so we MUST
        # re-append the target. If no target was supplied, fall back to
        # passthrough rather than risk scanning localhost.
        clean_target = (target or "").strip()
        if not clean_target:
            return {
                "blocked": False,
                "reason": (
                    f"OPSEC {level_id}: full-replace modifier requires a "
                    f"target — passthrough to avoid scanning localhost"
                ),
                "modified_command": command,
            }
        modified = f"{modifier} {clean_target}"
    else:
        # Flags-only suffix (the default/recommended style): append to
        # the operator's command. The already-substituted target inside
        # `command` is preserved untouched.
        modified = f"{command} {modifier}"

    return {
        "blocked": False,
        "reason": f"OPSEC {level_id}: applied '{modifier}'",
        "modified_command": modified,
    }