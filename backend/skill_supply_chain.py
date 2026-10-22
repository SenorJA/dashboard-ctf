"""
Skill supply-chain guard — permissions of playbooks, audited.

``skill_playbooks.py`` loads ``SKILL.md`` files from disk and trusts their
``allowed_tools`` frontmatter: a skill whose list is *empty* may invoke
**every** hook (``if info.manifest.allowed_tools and hook_name not in ...``).
A remote or half-reviewed playbook that widens its own permissions would
therefore be loaded silently.

This module is the linter that fails the build when somebody *widens*
permissions.  It is a direct translation of the supply-chain guards used by
``ai-job-search`` (``tools/security_guards.py``, MIT — see
``backend/ATTRIBUTION.md``):

======================================  ==========================================
Upstream check                          MIRV translation
======================================  ==========================================
``allowed-tools`` in a reviewed list    every ``allowed_tools`` entry must be a
                                        **real** tool id (arsenal) or a
                                        reviewed external binary
no wildcards (``Bash(*)``)              no ``*`` / ``?`` / ``**`` in
                                        ``allowed_tools`` nor ``requires_scope``
no lifecycle scripts in ``package.json`` no ``preinstall`` / ``install`` /
                                        ``postinstall`` / ``prepare`` /
                                        ``prepack`` under ``backend/skills/``
``.gitignore`` covers personal data     ``backend/data/``, ``*.env`` and
                                        ``backend/logs/`` stay ignored
agents with explicit ``tools:``         the 39 vendored personas must declare
                                        their tools and never get free-form
                                        ``edit`` / ``write`` / ``bash``
======================================  ==========================================

Design rules
------------
* **stdlib only** — no third-party dependency, hermetic, offline.
* **Severity, not exceptions** — every check returns a list of *issues*
  (``code`` / ``severity`` / ``message``); the caller decides what to do.
  ``ERROR`` blocks installation, ``INFO`` is advisory.
* **Reusable by the remote installer** — :func:`audit_payload` audits an
  in-memory ``{path: content}`` mapping, so the same rules apply to a skill
  downloaded from the internet (see ``framework/EXTERNAL_INTEGRATION_PLAN.md``
  §3.2.2 / §3.5) without touching the filesystem.

Attribution
-----------
The check design was adapted from ``tools/security_guards.py`` of
`MadsLorentzen/ai-job-search <https://github.com/MadsLorentzen/ai-job-search>`_
(MIT License). See ``backend/ATTRIBUTION.md``.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

__all__ = [
    "ARSENAL_TOOL_IDS",
    "REVIEWED_TOOL_BINARIES",
    "ALLOWED_TOOLS",
    "PERSONA_ALLOWED_TOOLS",
    "PERSONA_FORBIDDEN_TOOLS",
    "LIFECYCLE_SCRIPTS",
    "SEVERITY_ERROR",
    "SEVERITY_INFO",
    "audit_allowed_tools",
    "audit_skill_markdown",
    "audit_persona_markdown",
    "audit_payload",
    "has_blocking_issues",
    "summarize",
]

SEVERITY_ERROR = "error"
SEVERITY_INFO = "info"

# ════════════════════════════════════════════════════════════════
#  Allowlists
# ════════════════════════════════════════════════════════════════

#: The 65 tool ids served by the frontend arsenal (``ARSENAL_GROUPS`` in
#: ``frontend/js/main.v2.js``).  ``test_skill_supply_chain.py`` asserts this
#: set matches the frontend, so the two cannot drift apart.
ARSENAL_TOOL_IDS: frozenset[str] = frozenset({
    "7z-extract", "api-scanner", "b64-decode", "b64-encode", "bbot",
    "bloodhound", "bunzip2", "burpsuite", "cewl", "chisel-client",
    "cors-check", "curl", "dalfox", "dirb", "dns-lookup", "dnsrecon",
    "enum4linux", "evil-winrm", "feroxbuster", "ffuf", "gobuster", "gunzip",
    "hash-crack", "hashcat", "headers-scan", "hydra-ftp", "hydra-ssh",
    "impacket", "infoooze", "john", "jwt-decode", "ldapsearch", "ligolo",
    "linkedin2user", "masscan", "mr-holmes", "nc-listener", "netcat",
    "news-scraper", "nikto", "nmap", "nuclei", "port-scan", "proxychains",
    "responder", "searchsploit", "secrets-scan", "smbclient", "smbmap",
    "socat", "spiderfoot", "sqlmap", "stego-tool", "subdomain-scan",
    "tar-gz", "tar-xz", "testssl", "theharvester", "unrar", "unzip",
    "wafw00f", "wfuzz", "whatweb", "wpscan", "xsstrike",
})

#: Reviewed external binaries referenced by the bundled playbooks.  These are
#: *not* arsenal modules but real command line tools a skill may invoke.
#: Adding a name here is a reviewed decision — it widens the permissions the
#: whole skill tree is allowed to ask for.
REVIEWED_TOOL_BINARIES: frozenset[str] = frozenset({
    "aapt2", "adb", "angr", "apkid", "apksigner", "apktool", "autoruns",
    "aws-cli", "az-cli", "azure-cli", "beacon", "binaryninja", "bindiff",
    "binwalk", "bitcode_strip", "bn", "capa", "capstone", "cdpx", "cdxgen",
    "censys", "certipy", "certutil", "chainsaw", "checksec", "chisel",
    "chromedriver", "chromium", "class-dump", "class_dump", "cosign",
    "crackmapexec", "crowbar", "de4dot", "diaphora", "dig", "dnspy",
    "dotnet", "electron", "exif", "file", "frida", "garak", "gdb", "ghidra",
    "git", "grpcurl", "grype", "hash_cracker", "hashcat-utils", "havoc",
    "hayabusa", "hex-rays", "holehe", "hydra", "hyperdbg", "ida", "idapro",
    "idat", "idevice_id", "ildasm", "ilspy", "instagram", "ipatool",
    "iproxy", "jadx", "java", "js-beautify", "jtool2", "jwt_tool", "kAPE",
    "kube-bench", "kubectl", "kubiscan", "ldd", "libimobiledevice", "lime",
    "lipo", "mailheader", "medusa", "metasploit", "mimikatz", "mitmproxy",
    "mobsf", "mona", "mono", "monodis", "mxtoolbox", "ncrack", "neo4j",
    "nm", "node", "npm", "ntlmrelayx", "objdump", "objection", "ophcrack",
    "otool", "patator", "patch", "patchelf", "pe-bear", "pe-sieve",
    "pe-sieve64", "pedump", "pip", "playwright", "powershell", "promptfoo",
    "protoc", "prowler", "puppeteer", "pwntools", "python", "python3",
    "pywinauto", "qiling", "r2", "rabin2", "radare2", "radiff2",
    "rainbowcrack", "rasm2", "readelf", "ropper", "rubeus", "scout",
    "selenium", "sha256sum", "sharphound", "shodan", "sliver",
    "slsa-verifier", "sn", "splunk", "strace", "strings", "suricata", "syft",
    "syslog", "sysmon", "tcpdump", "tcpflow", "theHarvester", "trivy",
    "tshark", "uiautomation", "velharness", "vol3", "volatility3", "whois",
    "windbg", "winreg", "wireshark", "x64dbg", "yara", "zeek", "zipalign",
    "zlib-flate",
})

#: Everything a skill may declare in ``allowed_tools``.
ALLOWED_TOOLS: frozenset[str] = ARSENAL_TOOL_IDS | REVIEWED_TOOL_BINARIES

#: Tools a vendored AI persona may declare.  Read-only by design: a persona
#: is a *voice*, not an executor.
PERSONA_ALLOWED_TOOLS: frozenset[str] = frozenset({
    "read", "grep", "glob", "list_dir", "search", "web_fetch", "report",
})

#: Never acceptable in a persona: free-form editing, writing or shell access.
PERSONA_FORBIDDEN_TOOLS: frozenset[str] = frozenset({
    "edit", "write", "write_file", "bash", "shell", "sh", "zsh", "exec",
    "execute", "run", "spawn", "system", "sudo", "rm", "chmod", "chown",
    "eval", "powershell", "python", "python3", "pip", "npm", "curl", "wget",
})

#: npm lifecycle hooks that execute code on install — forbidden in a skill.
LIFECYCLE_SCRIPTS: frozenset[str] = frozenset({
    "preinstall", "install", "postinstall", "prepare", "prepack",
})

#: Shell patterns that pipe a download straight into an interpreter.
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|k|da|fi)?sh\b"
    r"|(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?python[0-9.]*\b",
    re.IGNORECASE,
)

#: Gitignore entries that must stay in place (personal / secret data).
REQUIRED_GITIGNORE_PATTERNS: tuple[str, ...] = (
    "backend/data/",
    "*.env",
    "backend/logs/",
)


# ════════════════════════════════════════════════════════════════
#  Issue helpers
# ════════════════════════════════════════════════════════════════

def _issue(code: str, severity: str, message: str, **extra: Any) -> Dict[str, Any]:
    issue: Dict[str, Any] = {
        "code": code,
        "severity": severity,
        "message": message,
    }
    for key, value in extra.items():
        if value is not None:
            issue[key] = value
    return issue


def _normalize_tool(value: str) -> str:
    return str(value or "").strip().strip("'\"").strip()


def _split_tools(raw: Any) -> List[str]:
    """Flatten the frontmatter shapes into a list of tool names."""
    if raw is None:
        return []
    if isinstance(raw, str):
        parts = re.split(r"[,\s]+", raw)
    elif isinstance(raw, (list, tuple, set)):
        parts = []
        for item in raw:
            parts.extend(_split_tools(item))
    else:
        parts = []
    return [p for p in (_normalize_tool(p) for p in parts) if p]


def _has_wildcard(value: str) -> bool:
    return any(token in value for token in ("*", "?", "[", "]", "{", "}"))


def _near_miss(tool: str) -> Optional[str]:
    """
    Return an arsenal id that looks like *tool* but is spelled differently.

    Two flavours are detected: a pure case/underscore drift
    (``hash_cracker`` vs ``hash-crack``) and a single character typo
    (``nmap ``/``nmpa`` vs ``nmap``).
    """
    normalized = tool.lower().replace("_", "-")
    for candidate in ARSENAL_TOOL_IDS:
        if candidate.lower() == normalized and candidate != tool:
            return candidate
    if len(normalized) < 4:
        return None
    for candidate in ARSENAL_TOOL_IDS:
        if _edit_distance_at_most_one(normalized, candidate.lower()):
            return candidate
    return None


def _edit_distance_at_most_one(a: str, b: str) -> bool:
    """True when *a* and *b* differ by at most one edit (typo tolerance)."""
    if a == b:
        return False
    la, lb = len(a), len(b)
    if la == lb:
        diff = sum(1 for x, y in zip(a, b) if x != y)
        if diff == 1:
            return True
        if diff == 2:
            # adjacent transposition (``nmpa`` -> ``nmap``)
            for i in range(la - 1):
                if a[i] == b[i + 1] and a[i + 1] == b[i]:
                    if a[:i] == b[:i] and a[i + 2:] == b[i + 2:]:
                        return True
        return False
    if abs(la - lb) > 1:
        return False
    shorter, longer = (a, b) if la < lb else (b, a)
    i = j = 0
    skipped = False
    while i < len(shorter) and j < len(longer):
        if shorter[i] == longer[j]:
            i += 1
            j += 1
            continue
        if skipped:
            return False
        skipped = True
        j += 1
    return True


# ════════════════════════════════════════════════════════════════
#  Public API
# ════════════════════════════════════════════════════════════════

def audit_allowed_tools(
    raw_tools: Any,
    *,
    where: Optional[str] = None,
    require_non_empty: bool = True,
) -> List[Dict[str, Any]]:
    """
    Audit a skill's ``allowed_tools`` declaration.

    Returns the list of issues (empty when the declaration is safe).  An
    *empty* declaration is an error: ``skill_playbooks`` treats it as
    "every hook allowed", which is exactly the widening we want to catch.
    """
    issues: List[Dict[str, Any]] = []
    tools = _split_tools(raw_tools)

    if not tools:
        if require_non_empty:
            issues.append(_issue(
                "empty_allowed_tools", SEVERITY_ERROR,
                "allowed_tools is empty: an empty list means 'every tool is "
                "allowed' in skill_playbooks.check_hook()",
                where=where,
            ))
        return issues

    seen: set[str] = set()
    for tool in tools:
        if tool in seen:
            continue
        seen.add(tool)
        if _has_wildcard(tool):
            issues.append(_issue(
                "wildcard_tool", SEVERITY_ERROR,
                f"wildcard in allowed_tools: {tool!r}",
                where=where, tool=tool,
            ))
            continue
        if tool in ALLOWED_TOOLS:
            continue
        near = _near_miss(tool)
        if near:
            issues.append(_issue(
                "near_miss_tool", SEVERITY_INFO,
                f"{tool!r} is not the canonical id (expected {near!r})",
                where=where, tool=tool, expected=near,
            ))
            continue
        issues.append(_issue(
            "unknown_tool", SEVERITY_ERROR,
            f"unknown tool in allowed_tools: {tool!r}",
            where=where, tool=tool,
        ))
    return issues


def audit_skill_markdown(
    name: str,
    content: str,
    *,
    frontmatter: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Audit one ``SKILL.md`` document.

    When *frontmatter* is omitted the (tiny, dependency free) parser of
    ``skill_playbooks`` is used, so the audit sees exactly what the runtime
    will see.
    """
    issues: List[Dict[str, Any]] = []
    where = f"skill:{name}"

    if frontmatter is None:
        from backend.skill_playbooks import _parse_skill_md  # local import: no cycle
        frontmatter, _body = _parse_skill_md(content)

    if not isinstance(frontmatter, dict) or not frontmatter:
        issues.append(_issue(
            "missing_frontmatter", SEVERITY_ERROR,
            "SKILL.md has no parseable frontmatter",
            where=where,
        ))
        return issues

    issues.extend(audit_allowed_tools(
        frontmatter.get("allowed_tools"), where=where, require_non_empty=True,
    ))

    scope = frontmatter.get("requires_scope")
    if scope is not None and _has_wildcard(str(scope)):
        issues.append(_issue(
            "wildcard_scope", SEVERITY_ERROR,
            f"wildcard in requires_scope: {scope!r}",
            where=where,
        ))
    return issues


def audit_persona_markdown(name: str, content: str) -> List[Dict[str, Any]]:
    """
    Audit a vendored AI persona (``backend/agents/**.md``).

    A persona must declare its tools explicitly and must never ask for
    free-form ``edit`` / ``write`` / ``bash``.
    """
    issues: List[Dict[str, Any]] = []
    where = f"persona:{name}"

    from backend.agency_agents import _parse_frontmatter  # local import: no cycle
    frontmatter, _body = _parse_frontmatter(content)

    raw_tools = frontmatter.get("tools")
    if raw_tools is None or not _split_tools(raw_tools):
        issues.append(_issue(
            "persona_missing_tools", SEVERITY_ERROR,
            "persona does not declare an explicit 'tools:' list",
            where=where,
        ))
        return issues

    for tool in _split_tools(raw_tools):
        if _has_wildcard(tool):
            issues.append(_issue(
                "persona_wildcard_tool", SEVERITY_ERROR,
                f"wildcard in persona tools: {tool!r}",
                where=where, tool=tool,
            ))
            continue
        if tool.lower() in PERSONA_FORBIDDEN_TOOLS:
            issues.append(_issue(
                "persona_forbidden_tool", SEVERITY_ERROR,
                f"persona requests a forbidden tool: {tool!r}",
                where=where, tool=tool,
            ))
            continue
        if tool not in PERSONA_ALLOWED_TOOLS:
            issues.append(_issue(
                "persona_unknown_tool", SEVERITY_ERROR,
                f"persona requests a non-reviewed tool: {tool!r}",
                where=where, tool=tool,
            ))
    return issues


def audit_package_json(path: str, content: str) -> List[Dict[str, Any]]:
    """Reject npm lifecycle hooks (they execute code on install)."""
    issues: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        issues.append(_issue(
            "invalid_package_json", SEVERITY_ERROR,
            "package.json is not valid JSON",
            where=path,
        ))
        return issues

    if not isinstance(data, dict):
        issues.append(_issue(
            "invalid_package_json", SEVERITY_ERROR,
            "package.json root is not an object",
            where=path,
        ))
        return issues

    scripts = data.get("scripts")
    if isinstance(scripts, dict):
        for hook in sorted(set(scripts) & LIFECYCLE_SCRIPTS):
            issues.append(_issue(
                "lifecycle_script", SEVERITY_ERROR,
                f"package.json declares the {hook!r} lifecycle hook",
                where=path, hook=hook,
            ))
    return issues


def audit_script_file(path: str, content: str) -> List[Dict[str, Any]]:
    """
    Reject scripts that pipe a download into an interpreter.

    Only *executed* pipe-to-shell is a problem: a line that merely prints
    the official install command (``echo "curl … | bash"``) is documentation
    and is ignored, as are comments.
    """
    issues: List[Dict[str, Any]] = []
    for raw_line in (content or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _PIPE_TO_SHELL.search(line)
        if not match:
            continue
        prefix = line[:match.start()]
        # A printed suggestion (``echo "curl … | bash"``, possibly inside a
        # ``case`` arm) is documentation, not an executed download.
        if re.search(r"\becho\b", prefix):
            continue
        issues.append(_issue(
            "pipe_to_shell", SEVERITY_ERROR,
            "script pipes a download into a shell/interpreter",
            where=path,
        ))
        break
    return issues


def audit_payload(files: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Audit an in-memory skill payload ``{relative_path: content}``.

    Used by the remote installer (F5) *before* a downloaded skill is written
    to disk or enabled.
    """
    issues: List[Dict[str, Any]] = []
    for path, content in sorted((files or {}).items()):
        lowered = path.lower()
        if lowered.endswith("package.json"):
            issues.extend(audit_package_json(path, content))
        elif lowered.endswith(".sh") or lowered.endswith(".bash"):
            issues.extend(audit_script_file(path, content))
        elif lowered.endswith("skill.md") or lowered.endswith("skill.md"):
            issues.extend(audit_skill_markdown(path, content))
    return issues


def has_blocking_issues(issues: Iterable[Dict[str, Any]]) -> bool:
    """True when at least one issue has ``error`` severity."""
    return any(i.get("severity") == SEVERITY_ERROR for i in issues or [])


def summarize(issues: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate issues into a compact, storable report."""
    items = list(issues or [])
    errors = [i for i in items if i.get("severity") == SEVERITY_ERROR]
    infos = [i for i in items if i.get("severity") == SEVERITY_INFO]
    return {
        "ok": not errors,
        "errors": len(errors),
        "infos": len(infos),
        "total": len(items),
        "issues": items,
    }
