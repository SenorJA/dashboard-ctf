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
            ${c.hash ? `<div class="text-gray-500 ml-5"><span class="text-gray-700">hash:</span> <span class="text-gray-400 font-mono">${c.hash.slice(0, 60)}${c.hash.length > 60 ? '...' : ''}</span></div>` : ''}
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
