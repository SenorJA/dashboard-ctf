/**
 * ============================================================
 *  CTF Dashboard — Frontend Controller
 *  WebSocket + SSH + Arsenal Tool Launcher
 * ============================================================
 */

let ws;

document.addEventListener('DOMContentLoaded', () => {

    // ============================================================
    //  REFERENCIAS DOM
    // ============================================================
    const output        = document.getElementById('terminal-output');
    const statusInd     = document.getElementById('status-indicator');
    const statusText    = document.getElementById('status-text');
    const cmdInput      = document.getElementById('cmd-input');
    const btnConnect    = document.getElementById('btn-connect');
    const btnDisconnect = document.getElementById('btn-disconnect');
    const btnSend       = document.getElementById('btn-send');
    const targetInput   = document.getElementById('target-ip');

    // ============================================================
    //  SALIDA EN TERMINAL (global para acceso desde HTML)
    // ============================================================
    window.appendOutput = function (text) {
        output.textContent += text + (text.endsWith('\n') ? '' : '\n');
        requestAnimationFrame(() => {
            output.scrollTop = output.scrollHeight;
        });
    };

    // ============================================================
    //  WEBSOCKET — CONEXIÓN / DESCONEXIÓN
    // ============================================================
    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[!] Ya estás conectado.');
            return;
        }

        appendOutput('[*] Iniciando conexión WebSocket...');
        ws = new WebSocket('ws://localhost:8000/ws');

        ws.onopen = () => {
            statusInd.classList.replace('bg-red-500', 'bg-emerald-500');
            statusInd.classList.replace(
                'shadow-[0_0_8px_rgba(239,68,68,0.6)]',
                'shadow-[0_0_8px_rgba(16,185,129,0.6)]'
            );
            statusText.textContent = 'Conectado';
            statusText.classList.replace('text-slate-400', 'text-emerald-400');
        };

        ws.onmessage = (event) => {
            appendOutput(event.data);
        };

        ws.onclose = () => {
            statusInd.classList.replace('bg-emerald-500', 'bg-red-500');
            statusInd.classList.replace(
                'shadow-[0_0_8px_rgba(16,185,129,0.6)]',
                'shadow-[0_0_8px_rgba(239,68,68,0.6)]'
            );
            statusText.textContent = 'Desconectado';
            statusText.classList.replace('text-emerald-400', 'text-slate-400');
            appendOutput('\n[!] Conexión SSH cerrada.');
            ws = null;
        };
    }

    function disconnectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[*] Forzando cierre de conexión...');
            ws.close();
        } else {
            appendOutput('[!] No hay ninguna conexión activa.');
        }
    }

    // ============================================================
    //  ENVÍO DE COMANDO DESDE EL INPUT MANUAL
    // ============================================================
    window.sendCommand = function () {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput('[!] Error: Conecta a Kali primero.');
            return;
        }
        const cmd = cmdInput.value.trim();
        if (!cmd) return;
        ws.send(cmd);
        cmdInput.value = '';
    };

    // ============================================================
    //  LANZADOR DE COMANDOS PREDEFINIDOS (módulos Arsenal)
    // ============================================================
    window.sendPredefinedCmd = function (cmd) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput('[!] Error: Conecta a Kali primero antes de lanzar módulos.');
            return;
        }
        appendOutput(`\n[*] Lanzando módulo automático: ${cmd}`);
        ws.send(cmd);
    };

    // ============================================================
    //  🚀 LANZADOR DE HERRAMIENTAS DEL ARSENAL (FUNCIÓN NUEVA)
    // ============================================================
    window.launchTool = function (tool) {
        // 1. Leer el target del input global
        const target = targetInput.value.trim();

        // 2. Validar que no esté vacío
        if (!target) {
            alert('⚠️  Introduce una IP o dominio en el campo "Objetivo CTF" de la barra lateral antes de lanzar una herramienta.');
            targetInput.focus();
            return;
        }

        // 3. Construir el comando según la herramienta seleccionada
        let command = '';
        let description = '';

        switch (tool) {
            // ── Web Recon ──
            case 'gobuster':
                command = `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -t 50 -q`;
                description = 'Gobuster — Directorios web';
                break;

            case 'dirb':
                command = `dirb http://${target} /usr/share/wordlists/dirb/common.txt`;
                description = 'Dirb — Fuerza bruta de directorios';
                break;

            case 'wfuzz':
                command = `wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://${target}/FUZZ`;
                description = 'Wfuzz — Fuzzing web parametrizado';
                break;

            case 'ffuf':
                command = `ffuf -w /usr/share/wordlists/dirb/common.txt -u http://${target}/FUZZ`;
                description = 'Ffuf — Fuzzer web ultrarrápido';
                break;

            case 'nikto':
                command = `nikto -h http://${target}`;
                description = 'Nikto — Escáner de vulnerabilidades web';
                break;

            case 'whatweb':
                command = `whatweb ${target}`;
                description = 'WhatWeb — Fingerprinting de tecnologías';
                break;

            case 'wpscan':
                command = `wpscan --url http://${target} --no-update --disable-tls-checks`;
                description = 'Wpscan — Escáner WordPress';
                break;

            // ── Network ──
            case 'nmap':
                command = `nmap -p- -sV -sC -O -A --min-rate=1000 -T4 ${target}`;
                description = 'Nmap — Escaneo agresivo completo';
                break;

            case 'masscan':
                command = `masscan -p1-65535 --rate=1000 ${target}`;
                description = 'Masscan — Escaneo masivo 65535 puertos';
                break;

            case 'netcat':
                command = `nc -zv ${target} 21 22 23 25 53 80 110 139 143 443 445 993 995 1433 1521 2049 3306 3389 5432 5900 5985 5986 8080 8443`;
                description = 'Netcat — Escaneo TCP rápido (24 puertos)';
                break;

            case 'dnsrecon':
                command = `dnsrecon -d ${target}`;
                description = 'Dnsrecon — Enumeración DNS';
                break;

            // ── SMB / Windows ──
            case 'enum4linux':
                command = `enum4linux -a ${target}`;
                description = 'Enum4linux — Enumeración SMB completa';
                break;

            case 'smbclient':
                command = `smbclient -L //${target} -N`;
                description = 'Smbclient — Listar shares SMB (null session)';
                break;

            // ── Exploitation / Brute Force ──
            case 'hydra-ssh':
                command = `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://${target} -t 4`;
                description = 'Hydra SSH — Fuerza bruta SSH (rockyou)';
                break;

            case 'hydra-ftp':
                command = `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://${target} -t 4`;
                description = 'Hydra FTP — Fuerza bruta FTP (rockyou)';
                break;

            case 'sqlmap':
                command = `sqlmap -u http://${target} --batch --random-agent`;
                description = 'Sqlmap — Detección automática SQLi';
                break;

            case 'searchsploit':
                command = `searchsploit ${target} 2>/dev/null || echo "[!] No se encontraron resultados en Searchsploit para: ${target}"`;
                description = 'Searchsploit — Buscar exploits relacionados';
                break;

            default:
                appendOutput(`[!] Herramienta desconocida: "${tool}"`);
                return;
        }

        // 4. Mostrar en terminal y enviar
        appendOutput(`\n${'='.repeat(56)}`);
        appendOutput(`  🚀 ${description}`);
        appendOutput(`  🎯 Target: ${target}`);
        appendOutput(`  💻 Comando: ${command}`);
        appendOutput(`${'='.repeat(56)}`);

        window.sendPredefinedCmd(command);
    };

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

    // Permitir Enter en el campo target-ip para lanzar Gobuster por defecto
    targetInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            window.launchTool('gobuster');
        }
    });

});
