// ════════════════════════════════════════════════════════════════
//  VulnForge — Swarm UI (Multi-Operator Pipeline)
// ════════════════════════════════════════════════════════════════

// ── State ──
let swarmSessionId = null;
let swarmPollInterval = null;
let swarmFindings = [];

// ── Start Swarm ──
window.swarmStart = async function () {
    const target = document.getElementById('swarm-target').value.trim();
    if (!target) {
        if (typeof appendOutput === 'function') appendOutput('⚠ Enter a target first');
        if (typeof showToast === 'function') showToast('⚠ Enter a target first');
        return;
    }

    const btn = document.getElementById('btn-swarm-start');
    const btnCancel = document.getElementById('btn-swarm-cancel');
    btn.disabled = true;
    btn.textContent = '⏳ Starting...';
    btnCancel.classList.remove('hidden');

    try {
        const resp = await fetch('/api/swarm/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target })
        });
        const data = await resp.json();
        if (!data.ok) throw new Error(data.error || 'Failed to start swarm');

        swarmSessionId = data.session_id;
        document.getElementById('swarm-progress').classList.remove('hidden');
        document.getElementById('swarm-findings').classList.remove('hidden');
        document.getElementById('swarm-logs').classList.remove('hidden');

        // Start polling
        if (swarmPollInterval) clearInterval(swarmPollInterval);
        swarmPollInterval = setInterval(swarmPoll, 2000);
        swarmPoll(); // Immediate first poll

        if (typeof showToast === 'function') showToast('🐝 Swarm started');
    } catch (e) {
        if (typeof appendOutput === 'function') appendOutput(`⚠ Swarm error: ${e.message}`);
        if (typeof showToast === 'function') showToast(`⚠ Swarm: ${e.message}`);
        btn.disabled = false;
        btn.textContent = '🚀 Start Swarm';
        btnCancel.classList.add('hidden');
    }
};

// ── Poll ──
window.swarmPoll = async function () {
    if (!swarmSessionId) return;
    try {
        const resp = await fetch(`/api/swarm/${swarmSessionId}`);
        const data = await resp.json();
        if (!data.ok || !data.data) return;
        const s = data.data;
        swarmRender(s);
    } catch (e) {
        // Silently retry on next interval
    }
};

// ── Render ──
window.swarmRender = function (s) {
    // Progress
    const progressBar = document.getElementById('swarm-progress-bar');
    const progressPct = document.getElementById('swarm-progress-pct');
    const progressLabel = document.getElementById('swarm-progress-label');
    const statusMsg = document.getElementById('swarm-status-msg');
    const btnCancel = document.getElementById('btn-swarm-cancel');

    progressBar.style.width = s.progress + '%';
    progressPct.textContent = s.progress + '%';

    if (s.status === 'completed') {
        progressLabel.textContent = '✅ Completed';
    } else if (s.status === 'error') {
        progressLabel.textContent = '⚠ Error';
    } else if (s.status === 'cancelled') {
        progressLabel.textContent = '⏹ Cancelled';
    } else if (s.current_operator) {
        progressLabel.textContent = `▶ Running: ${s.current_operator}`;
    } else {
        progressLabel.textContent = '⏳ Starting...';
    }

    statusMsg.textContent =
        s.status === 'completed' ? `All operators finished. ${(s.findings || []).length} findings.` :
        s.status === 'error' ? 'An operator encountered an error. Check logs.' : '';

    // Operator cards
    const container = document.getElementById('swarm-operators');
    const opIcons = { recon: '🔍', scanner: '🛡️', exploiter: '💥', report: '📄' };
    const opLabels = { recon: 'Reconnaissance', scanner: 'Vulnerability Scanner', exploiter: 'Exploit Researcher', report: 'Report Generator' };
    const opDesc = {
        recon: 'Port scanning, web tech detection, DNS enumeration',
        scanner: 'Vulnerability scanning (nikto, wpscan, nuclei)',
        exploiter: 'Exploit research (searchsploit)',
        report: 'Compile findings into final report'
    };

    container.innerHTML = s.operators.map(op => {
        const icon = opIcons[op.name] || '⚙️';
        const label = opLabels[op.name] || op.name;
        const desc = opDesc[op.name] || '';
        const statusIcon = op.status === 'completed' ? '✅' :
                           op.status === 'running' ? '🔄' :
                           op.status === 'error' ? '❌' : '⏳';
        const statusClass = op.status === 'completed' ? 'text-green-400' :
                            op.status === 'running' ? 'text-cyber' :
                            op.status === 'error' ? 'text-blood' : 'text-gray-700';
        const findings = op.findings_count || 0;
        const commands = (op.commands_run || []).length;

        return `<div class="bg-deep/50 border border-gray-800 rounded p-2 ${op.status === 'running' ? 'border-cyber/50' : ''}">
            <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-1.5">
                    <span>${icon}</span>
                    <span class="text-[11px] text-gray-300 font-semibold">${label}</span>
                </div>
                <div class="flex items-center gap-2">
                    <span class="text-[9px] text-gray-700">${commands} cmds</span>
                    <span class="text-[9px] text-gray-700">${findings} findings</span>
                    <span class="text-[11px] ${statusClass}">${statusIcon}</span>
                </div>
            </div>
            <p class="text-[9px] text-gray-700">${desc}</p>
            ${op.error ? `<p class="text-[9px] text-blood mt-1">⚠ ${op.error}</p>` : ''}
        </div>`;
    }).join('');

    // Findings
    if (s.findings && s.findings.length) {
        swarmFindings = s.findings;
        const list = document.getElementById('swarm-findings-list');
        const sevColors = { critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-blue-400', info: 'text-gray-500' };
        list.innerHTML = s.findings.slice(-50).reverse().map(f => {
            const sevClass = sevColors[f.severity] || 'text-gray-500';
            const sevLabel = (f.severity || 'info').toUpperCase();
            return `<div class="text-[10px] text-gray-400 flex items-start gap-1.5">
                <span class="${sevClass} font-semibold shrink-0 w-12">[${sevLabel}]</span>
                <span class="text-gray-500">${f.tool || ''}</span>
                <span class="text-gray-300">${f.title || ''}</span>
            </div>`;
        }).join('');
    }

    // Logs
    if (s.logs && s.logs.length) {
        const logsEl = document.getElementById('swarm-logs-content');
        logsEl.innerHTML = s.logs.map(l => `<div>${l}</div>`).join('');
        logsEl.scrollTop = logsEl.scrollHeight;
    }

    // Status: stop polling when done
    if (s.status === 'completed' || s.status === 'error' || s.status === 'cancelled') {
        const btn = document.getElementById('btn-swarm-start');
        btn.disabled = false;
        btn.textContent = '🚀 Start Swarm';
        btnCancel.classList.add('hidden');
        if (swarmPollInterval) {
            clearInterval(swarmPollInterval);
            swarmPollInterval = null;
        }
        // Auto-refresh sessions list
        swarmListSessions();
    }
};

// ── Cancel ──
window.swarmCancel = async function () {
    if (!swarmSessionId) return;
    try {
        await fetch(`/api/swarm/${swarmSessionId}/cancel`, { method: 'POST' });
        if (typeof appendOutput === 'function') appendOutput('⏹ Swarm cancelled');
        if (typeof showToast === 'function') showToast('⏹ Swarm cancelled');
    } catch (e) {
        if (typeof appendOutput === 'function') appendOutput(`⚠ Cancel error: ${e.message}`);
    }
};

// ── Refresh (manual poll) ──
window.swarmRefresh = function () {
    swarmPoll();
    swarmListSessions();
};

// ── Clear ──
window.swarmClear = function () {
    swarmSessionId = null;
    swarmFindings = [];
    if (swarmPollInterval) {
        clearInterval(swarmPollInterval);
        swarmPollInterval = null;
    }
    document.getElementById('swarm-progress').classList.add('hidden');
    document.getElementById('swarm-findings').classList.add('hidden');
    document.getElementById('swarm-logs').classList.add('hidden');
    document.getElementById('swarm-operators').innerHTML = '';
    document.getElementById('swarm-findings-list').innerHTML = '';
    document.getElementById('swarm-logs-content').innerHTML = '';
    document.getElementById('swarm-progress-bar').style.width = '0%';
    document.getElementById('swarm-progress-pct').textContent = '0%';
    document.getElementById('swarm-status-msg').textContent = '';
    document.getElementById('btn-swarm-start').disabled = false;
    document.getElementById('btn-swarm-start').textContent = '🚀 Start Swarm';
    document.getElementById('btn-swarm-cancel').classList.add('hidden');
};

// ── List sessions ──
window.swarmListSessions = async function () {
    try {
        const resp = await fetch('/api/swarm/list');
        const data = await resp.json();
        if (!data.ok || !data.data) return;
        const sessions = data.data;

        const sessionsEl = document.getElementById('swarm-sessions');
        const listEl = document.getElementById('swarm-sessions-list');

        if (sessions.length === 0) {
            sessionsEl.classList.add('hidden');
            return;
        }

        sessionsEl.classList.remove('hidden');
        listEl.innerHTML = sessions.slice(-5).reverse().map(s => {
            const statusIcon = s.status === 'completed' ? '✅' :
                               s.status === 'running' ? '🔄' :
                               s.status === 'error' ? '❌' : '⏹';
            return `<div class="text-[10px] text-gray-600 flex items-center gap-2 cursor-pointer hover:text-gray-400 transition-colors"
                        onclick="swarmResume('${s.session_id}')">
                <span>${statusIcon}</span>
                <span class="font-mono">${s.target}</span>
                <span>— ${s.progress || 0}%</span>
                <span class="text-gray-700">(${s.status})</span>
            </div>`;
        }).join('');
    } catch (e) {
        // Silently fail
    }
};

// ── Resume a previous session ──
window.swarmResume = function (sessionId) {
    swarmSessionId = sessionId;
    document.getElementById('swarm-progress').classList.remove('hidden');
    document.getElementById('swarm-findings').classList.remove('hidden');
    document.getElementById('swarm-logs').classList.remove('hidden');
    if (swarmPollInterval) clearInterval(swarmPollInterval);
    swarmPollInterval = setInterval(swarmPoll, 2000);
    swarmPoll();
};
