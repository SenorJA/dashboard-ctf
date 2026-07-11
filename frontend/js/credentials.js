// ── Credential Store ──

let credentials = [];

window.credLoad = async function () {
    try {
        const resp = await fetch('/api/credentials');
        const data = await resp.json();
        if (!data.ok) return;
        credentials = data.data || [];
        credRender();
    } catch (e) {
        console.error('Cred load error:', e);
    }
};

window.credRender = function () {
    const list = document.getElementById('cred-list');
    if (!list) return;

    if (credentials.length === 0) {
        list.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-4">No credentials saved yet</div>';
        document.getElementById('cred-count').textContent = '0';
        return;
    }

    document.getElementById('cred-count').textContent = credentials.length;

    const typeIcons = { password: '🔑', hash: '#️⃣', token: '🎫', key: '🗝️', certificate: '📜', other: '📦' };

    list.innerHTML = credentials.map(c => {
        const icon = typeIcons[c.type] || '🔑';
        const date = (c.created_at || '').slice(0, 10);
        return `<div class="bg-deep/50 border border-gray-800 rounded p-2 text-[10px]">
            <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-1.5">
                    <span>${icon}</span>
                    <span class="text-gray-300 font-semibold">${c.username || c.service || '?'}</span>
                    <span class="text-gray-700">@ ${c.target || '?'}</span>
                    ${c.port ? `<span class="text-gray-700">:${c.port}</span>` : ''}
                </div>
                <div class="flex items-center gap-2">
                    <span class="text-gray-700">${date}</span>
                    <span class="text-gray-600">${c.service || ''}</span>
                    <button onclick="credDelete('${c.uuid}')" class="text-gray-700 hover:text-blood transition-colors">✕</button>
                </div>
            </div>
            ${c.password ? `<div class="text-gray-500 ml-5"><span class="text-gray-700">password:</span> <span class="text-gray-400" id="cred-pw-${c.uuid}">••••••••</span> <button onclick="credTogglePw('${c.uuid}')" class="text-gray-700 hover:text-gray-400 text-[9px]">👁</button></div>` : ''}
            ${c.hash ? `<div class="text-gray-500 ml-5"><span class="text-gray-700">hash:</span> <span class="text-gray-400 font-mono">${c.hash.slice(0, 60)}${c.hash.length > 60 ? '...' : ''}</span> <button onclick="credAnalyzeHash('${c.uuid}')" class="text-[9px] text-amber-500/70 hover:text-amber-400 transition-colors" title="Analyze hash with AI">🤖</button></div>` : ''}
            ${c.token ? `<div class="text-gray-500 ml-5"><span class="text-gray-700">token:</span> <span class="text-gray-400 font-mono">${c.token.slice(0, 40)}...</span></div>` : ''}
            ${c.notes ? `<div class="text-gray-600 ml-5 italic">${c.notes}</div>` : ''}
        </div>`;
    }).join('');
};

window.credDelete = async function (uuid) {
    try {
        await fetch(`/api/credentials/${uuid}`, { method: 'DELETE' });
        await credLoad();
    } catch (e) {
        console.error('Cred delete error:', e);
    }
};

window.credTogglePw = function (uuid) {
    const el = document.getElementById(`cred-pw-${uuid}`);
    if (!el) return;
    const cred = credentials.find(c => c.uuid === uuid);
    if (!cred) return;
    if (el.textContent === '••••••••') {
        el.textContent = cred.password;
    } else {
        el.textContent = '••••••••';
    }
};

window.credAdd = async function () {
    const data = {
        type: document.getElementById('cred-type').value,
        target: document.getElementById('cred-target').value.trim(),
        username: document.getElementById('cred-username').value.trim(),
        password: document.getElementById('cred-password').value,
        hash: document.getElementById('cred-hash').value.trim(),
        token: document.getElementById('cred-token').value.trim(),
        service: document.getElementById('cred-service').value.trim(),
        port: document.getElementById('cred-port').value.trim(),
        source: document.getElementById('cred-source').value.trim(),
        notes: document.getElementById('cred-notes').value.trim(),
    };

    if (!data.target && !data.username && !data.service) {
        showToast('⚠ Enter at least target, username, or service');
        return;
    }

    try {
        const resp = await fetch('/api/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
        const result = await resp.json();
        if (result.ok) {
            showToast('✅ Credential saved');
            // Reset form
            document.getElementById('cred-target').value = '';
            document.getElementById('cred-username').value = '';
            document.getElementById('cred-password').value = '';
            document.getElementById('cred-hash').value = '';
            document.getElementById('cred-token').value = '';
            document.getElementById('cred-notes').value = '';
            await credLoad();
        } else {
            showToast('⚠ Error: ' + (result.error || 'unknown'));
        }
    } catch (e) {
        showToast('⚠ Network error: ' + e.message);
    }
};

window.credClearAll = async function () {
    if (!confirm('Delete ALL saved credentials?')) return;
    try {
        await fetch('/api/credentials', { method: 'DELETE' });
        await credLoad();
        showToast('🧹 All credentials cleared');
    } catch (e) {
        showToast('⚠ Error: ' + e.message);
    }
};

// ── 🤖 AI Analysis ──
window.credAnalyzeHash = async function (uuid) {
    const cred = credentials.find(c => c.uuid === uuid);
    if (!cred || !cred.hash) { showToast('⚠ No hash to analyze'); return; }
    showToast('🤖 Analyzing hash...');
    const systemPrompt = `You are a password cracking and hash analysis expert. For a given hash, identify:
1. Hash type / algorithm (with confidence)
2. Suggested hashcat mode (-m)
3. Recommended attack strategy (mask, wordlist, rules)
4. Estimated cracking time
5. Online resources for lookup
Be concise and specific.`;
    const result = await window.aiChat(systemPrompt, `Hash: ${cred.hash}\nContext: service=${cred.service || '?'}, target=${cred.target || '?'}, username=${cred.username || '?'}`);
    if (result) {
        const existing = document.getElementById('cred-ai-overlay');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'cred-ai-overlay';
        overlay.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/60';
        overlay.innerHTML = `<div class="bg-deep border border-amber-500/30 rounded-lg max-w-xl w-full mx-4 max-h-[70vh] overflow-y-auto p-4 shadow-2xl">
            <div class="flex items-center justify-between mb-3">
                <span class="text-amber-400 font-bold text-[11px] tracking-wider">🤖 Hash Analysis</span>
                <button onclick="this.closest('#cred-ai-overlay').remove()" class="text-gray-600 hover:text-gray-400 text-[18px] leading-none">&times;</button>
            </div>
            <div class="text-[9px] text-gray-300 mb-2 font-mono">${cred.hash.slice(0, 80)}</div>
            <div class="text-[10px] text-gray-300 leading-relaxed whitespace-pre-wrap">${result}</div>
            <div class="mt-3 pt-2 border-t border-gray-800 flex justify-end">
                <button onclick="this.closest('#cred-ai-overlay').remove()" class="text-[9px] text-gray-600 hover:text-gray-400">Close</button>
            </div>
        </div>`;
        document.body.appendChild(overlay);
    }
};

window.credAskAI = async function () {
    const input = document.getElementById('cred-ai-question');
    if (!input || !input.value.trim()) return;
    const question = input.value.trim();
    input.disabled = true;
    const answerBox = document.getElementById('cred-ai-answer');
    if (answerBox) answerBox.textContent = '⏳ Thinking...';
    const ctx = `There are ${credentials.length} stored credentials.`;
    const systemPrompt = `You are a credential security expert. Help with: hash identification, password cracking strategy (hashcat/john), password policy analysis, credential stuffing defense, and authentication security. Be concise.`;
    try {
        const result = await window.aiChat(systemPrompt, `Context: ${ctx}\n\nQuestion: ${question}`);
        if (answerBox) answerBox.textContent = result || '(no response)';
    } catch (e) {
        if (answerBox) answerBox.textContent = 'Error: ' + e.message;
    } finally {
        input.disabled = false;
        input.focus();
    }
};

window.credAskAIEnter = function (e) { if (e.key === 'Enter') credAskAI(); };
