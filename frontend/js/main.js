document.addEventListener('DOMContentLoaded', () => {
    let ws;

    // Referencias a los elementos del DOM
    const output = document.getElementById('terminal-output');
    const statusIndicator = document.getElementById('status-indicator');
    const statusText = document.getElementById('status-text');
    const cmdInput = document.getElementById('cmd-input');
    const btnConnect = document.getElementById('btn-connect');
    const btnSend = document.getElementById('btn-send');

    // Función para añadir texto a la consola
    function appendOutput(text) {
        output.textContent += text + (text.endsWith('\n') ? '' : '\n');
        output.scrollTop = output.scrollHeight;
    }

    // Lógica de conexión WebSocket
    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput("[!] Ya estás conectado.");
            return;
        }

        appendOutput("[*] Iniciando conexión WebSocket con el backend...");
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
            appendOutput("\n[!] Conexión cerrada.");
        };
    }

    // Lógica para enviar comandos
    function sendCommand() {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput("[!] Error: No estás conectado a Kali. Pulsa 'Conectar' primero.");
            return;
        }
        const cmd = cmdInput.value;
        if (cmd) {
            ws.send(cmd);
            cmdInput.value = '';
        }
    }

    // Event Listeners
    btnConnect.addEventListener('click', connectWS);
    btnSend.addEventListener('click', sendCommand);

    // Soporte para tecla "Enter" en el input
    cmdInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
            sendCommand();
        }
    });

    // Función para desconectar
    function disconnectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput("[*] Cerrando conexión con Kali...");
            ws.close();
        } else {
            appendOutput("[!] No hay ninguna conexión activa.");
        }
    }

    // Añade el listener a los otros que ya tienes abajo
    const btnDisconnect = document.getElementById('btn-disconnect');
    btnDisconnect.addEventListener('click', disconnectWS);

    function appendOutput(text) {
        output.textContent += text + (text.endsWith('\n') ? '' : '\n');
        // Usamos requestAnimationFrame para asegurar que el navegador ha pintado el texto antes de hacer scroll
        requestAnimationFrame(() => {
            output.scrollTop = output.scrollHeight;
        });
    }

});