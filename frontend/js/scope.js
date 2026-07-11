// ── Scope Guard UI ──

window.scopeModalOpen = function () {
    document.getElementById('scope-modal').classList.remove('hidden');
    scopeLoadConfig();
    scopeLoadHistory();
};

window.scopeModalClose = function () {
    document.getElementById('scope-modal').classList.add('hidden');
};

// Close on Escape
document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') scopeModalClose();
});

// Close on backdrop click
document.addEventListener('click', function (e) {
    const modal = document.getElementById('scope-modal');
    if (e.target === modal) scopeModalClose();
});

window.scopeLoadConfig = async function () {
    try {
        const resp = await fetch('/api/scope');
        const data = await resp.json();
        if (!data.ok || !data.data) return;

        const cfg = data.data;
        document.getElementById('scope-enabled').checked = cfg.enabled;
        document.getElementById('scope-mode').value = cfg.mode;
        document.getElementById('scope-targets').value = (cfg.targets || []).join('\n');
        document.getElementById('scope-blocked-count').textContent = cfg.blocked_count || 0;

        // Update indicator
        scopeUpdateIndicator(cfg);
    } catch (e) {
        console.error('Scope load error:', e);
    }
};

window.scopeSaveConfig = async function () {
    const enabled = document.getElementById('scope-enabled').checked;
    const mode = document.getElementById('scope-mode').value;
    const targetsText = document.getElementById('scope-targets').value;
    const targets = targetsText.split('\n')
        .map(t => t.trim())
        .filter(t => t.length > 0 && !t.startsWith('#'));

    try {
        const resp = await fetch('/api/scope', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled, mode, targets })
        });
        const data = await resp.json();
        if (data.ok) {
            showToast('✅ Scope config saved');
            scopeLoadConfig();
        } else {
            showToast('⚠ Error saving scope: ' + (data.error || 'unknown'));
        }
    } catch (e) {
        showToast('⚠ Network error: ' + e.message);
    }
};

window.scopeLoadHistory = async function () {
    try {
        const resp = await fetch('/api/scope/history');
        const data = await resp.json();
        if (!data.ok) return;

        const list = document.getElementById('scope-history-list');
        const entries = data.data || [];
        if (entries.length === 0) {
            list.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-4">No blocked commands</div>';
            return;
        }

        list.innerHTML = entries.slice(-50).reverse().map(e => {
            const ts = (e.timestamp || '').slice(11, 19) || '--:--:--';
            const icon = e.mode === 'block' ? '🔒' : '⚠';
            const color = e.mode === 'block' ? 'text-blood' : 'text-yellow-500';
            return `<div class="text-[10px] font-mono flex items-start gap-1.5 border-b border-gray-900 pb-1">
                <span class="${color} shrink-0">${icon}</span>
                <span class="text-gray-700 shrink-0">[${ts}]</span>
                <span class="text-gray-500">${e.message || e.command || ''}</span>
            </div>`;
        }).join('');
    } catch (e) {
        console.error('Scope history error:', e);
    }
};

window.scopeClearHistory = async function () {
    try {
        await fetch('/api/scope/history/clear', { method: 'POST' });
        document.getElementById('scope-history-list').innerHTML =
            '<div class="text-[10px] text-gray-700 text-center py-4">Cleared</div>';
        showToast('🧹 History cleared');
    } catch (e) {
        showToast('⚠ Error: ' + e.message);
    }
};

function scopeUpdateIndicator(cfg) {
    const badge = document.getElementById('scope-badge');
    if (!badge) return;
    if (cfg.enabled) {
        badge.textContent = '🔒 ' + (cfg.mode === 'block' ? 'Block' : 'Warn');
        badge.className = 'text-[10px] px-1.5 py-0.5 rounded border ' +
            (cfg.mode === 'block'
                ? 'text-blood border-blood/30 bg-blood/10'
                : 'text-yellow-500 border-yellow-500/30 bg-yellow-500/10');
    } else {
        badge.textContent = '🔓 Scope off';
        badge.className = 'text-[10px] text-gray-700 px-1.5 py-0.5 rounded border border-gray-800';
    }
}

// Show toast notification (reuse existing or create fallback)
if (typeof showToast !== 'function') {
    window.showToast = function (msg) {
        const t = document.createElement('div');
        t.className = 'fixed bottom-4 right-4 bg-deep border border-gray-800 text-gray-300 text-[11px] px-4 py-2 rounded z-[9999]';
        t.textContent = msg;
        document.body.appendChild(t);
        setTimeout(() => t.remove(), 3000);
    };
}
