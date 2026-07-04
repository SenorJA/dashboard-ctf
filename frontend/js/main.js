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
            case 'gobuster':
                command = `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -t 50 -q`;
                description = 'Gobuster — Directorios web';
                break;

            case 'nmap':
                command = `nmap -p- -sV -sC -O -A --min-rate=1000 -T4 ${target}`;
                description = 'Nmap — Escaneo agresivo completo';
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
