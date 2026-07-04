// Hacemos que ws sea global para poder llamarlo desde el HTML (onclick)
let ws;

document.addEventListener('DOMContentLoaded', () => {

    // Referencias al DOM
    const output = document.getElementById('terminal-output');
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const cmdInput = document.getElementById('cmd-input');
    const btnConnect = document.getElementById('btn-connect');
    const btnDisconnect = document.getElementById('btn-disconnect');
    const btnSend = document.getElementById('btn-send');

    // Función mejorada para el output con scroll perfecto
    window.appendOutput = function (text) {
        output.textContent += text + (text.endsWith('\n') ? '' : '\n');
        requestAnimationFrame(() => {
            output.scrollTop = output.scrollHeight;
        });
    }

    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput("[!] Ya estás conectado.");
            return;
        }

        appendOutput("[*] Iniciando conexión...");
        ws = new WebSocket("ws://localhost:8000/ws");

        ws.onopen = () => {
            statusIndicator.classList.replace('bg-red-500', 'bg-emerald-500');
            statusIndicator.classList.replace('shadow-[0_0_8px_rgba(239,68,68,0.6)]', 'shadow-[0_0_8px_rgba(16,185,129,0.6)]');
            statusText.textContent = "Conectado";
            statusText.classList.replace('text-slate-400', 'text-emerald-400');
        };

        ws.onmessage = (event) => {
            appendOutput(event.data);
        };

        ws.onclose = () => {
            statusIndicator.classList.replace('bg-emerald-500', 'bg-red-500');
            statusIndicator.classList.replace('shadow-[0_0_8px_rgba(16,185,129,0.6)]', 'shadow-[0_0_8px_rgba(239,68,68,0.6)]');
            statusText.textContent = "Desconectado";
            statusText.classList.replace('text-emerald-400', 'text-slate-400');
            appendOutput("\n[!] Conexión SSH cerrada.");
            ws = null;
        };
    }

    function disconnectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput("[*] Forzando cierre de conexión...");
            ws.close();
        } else {
            appendOutput("[!] No hay ninguna conexión activa.");
        }
    }

    window.sendCommand = function () {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput("[!] Error: Conecta a Kali primero.");
            return;
        }
        const cmd = cmdInput.value;
        if (cmd) {
            ws.send(cmd);
            cmdInput.value = '';
        }
    }

    // Función para los botones del Sidebar
    window.sendPredefinedCmd = function (cmd) {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput("[!] Error: Conecta a Kali primero antes de lanzar módulos.");
            return;
        }
        appendOutput(`\n[*] Lanzando módulo automático: ${cmd}`);
        ws.send(cmd);
    }

    // Listeners
    btnConnect.addEventListener('click', connectWS);
    btnDisconnect.addEventListener('click', disconnectWS);
    btnSend.addEventListener('click', window.sendCommand);

    cmdInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            window.sendCommand();
        }
    });
});