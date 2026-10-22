// ── Interactive Permission Requests (F0) ──
// Backend gate (backend/main.py, WebSocket "permission_request") creates a
// pending request and blocks the command until the operator decides.
// Endpoints: GET /api/permissions/pending, POST /api/permissions/{id}/decide
//
// UX: one request at a time; extra requests are queued. A 4s poll is kept as
// a fallback so a request raised outside the WebSocket (or after a reconnect)
// still surfaces in the UI.

(function () {
    const _queue = [];
    let _active = null;
    let _pollTimer = null;
    let _tickTimer = null;

    function el(id) {
        return document.getElementById(id);
    }

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function notify(msg) {
        if (typeof window.showToast === 'function') {
            try { window.showToast(msg); return; } catch (e) { /* fall through */ }
        }
        if (typeof window.appendOutput === 'function') window.appendOutput('\n' + msg + '\n');
    }

    function out(text) {
        if (typeof window.appendOutput === 'function') window.appendOutput(text);
    }

    // ── Public API ───────────────────────────────────────────────

    // Called from the WebSocket handler when the backend raises a request.
    window.permissionShow = function (req) {
        if (!req || !req.id) return;
        if (_active && _active.id === req.id) return;
        for (let i = 0; i < _queue.length; i++) {
            if (_queue[i].id === req.id) return;
        }
        _queue.push(req);
        render();
    };

    // Called when the backend reports the request was denied/expired.
    window.permissionDenied = function (info) {
        const msg = (info && info.message) ? info.message : 'Command not executed';
        out('\n🚫 Permission ' + ((info && info.status) || 'denied') + ' — ' + msg + '\n');
    };

    window.permissionClose = function () {
        const modal = el('permission-modal');
        if (modal) modal.classList.add('hidden');
    };

    // Record the operator decision and release the pending command.
    window.permissionDecide = async function (id, decision) {
        if (!id) return;
        try {
            const resp = await fetch('/api/permissions/' + encodeURIComponent(id) + '/decide', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ decision: decision, user: 'operator' })
            });
            const data = await resp.json().catch(() => ({}));
            if (!resp.ok || data.ok === false) {
                notify('⚠ ' + (data.error || ('HTTP ' + resp.status)));
                return;
            }
            if (_active && _active.id === id) _active = null;
            const labels = {
                'allow-once': '✅ Allowed once',
                'allow-session': '♻️ Allowed for session',
                'deny': '🚫 Denied'
            };
            notify(labels[decision] || '✔ ' + decision);
            render();
            // The next queued request may now be shown.
            setTimeout(render, 60);
        } catch (e) {
            notify('⚠ Network error: ' + e.message);
        }
    };

    // Fallback poll: surface requests created outside the WebSocket.
    window.refreshPermissions = async function () {
        try {
            const resp = await fetch('/api/permissions/pending');
            const data = await resp.json().catch(() => ({}));
            if (!data || data.ok === false || !Array.isArray(data.pending)) return;
            data.pending.forEach(window.permissionShow);
        } catch (e) { /* offline — ignore */ }
    };

    // ── Internals ────────────────────────────────────────────────

    function render() {
        const modal = el('permission-modal');
        if (!modal) return;

        if (!_active && _queue.length) _active = _queue.shift();
        if (!_active) {
            modal.classList.add('hidden');
            stopTick();
            return;
        }

        const req = _active;
        const idEl = el('permission-modal-id');
        if (idEl) idEl.textContent = req.id || '';
        const cmdEl = el('permission-modal-cmd');
        if (cmdEl) cmdEl.textContent = req.command || '';

        const tgtWrap = el('permission-modal-target-wrap');
        const tgtEl = el('permission-modal-target');
        if (req.target) {
            if (tgtEl) tgtEl.textContent = req.target;
            if (tgtWrap) tgtWrap.classList.remove('hidden');
        } else if (tgtWrap) {
            tgtWrap.classList.add('hidden');
        }

        const list = el('permission-modal-reasons');
        if (list) {
            const lines = String(req.detail || '')
                .split('\n')
                .map(function (s) { return s.trim(); })
                .filter(Boolean);
            if (!lines.length && req.summary) lines.push(req.summary);
            if (!lines.length) lines.push('No risk pattern matched');
            list.innerHTML = lines.map(function (l) {
                return '<li>• ' + esc(l) + '</li>';
            }).join('');
        }

        modal.classList.remove('hidden');
        startTick();
    }

    function updateExpiry() {
        const exp = el('permission-modal-expiry');
        if (!exp || !_active) return;
        if (!_active.expires_at) { exp.textContent = '—'; return; }
        const ts = Date.parse(_active.expires_at);
        if (isNaN(ts)) { exp.textContent = _active.expires_at; return; }
        const secs = Math.max(0, Math.round((ts - Date.now()) / 1000));
        exp.textContent = _active.expires_at + ' (' + secs + 's)';
    }

    function startTick() {
        if (_tickTimer) return;
        updateExpiry();
        _tickTimer = setInterval(updateExpiry, 1000);
    }

    function stopTick() {
        if (_tickTimer) { clearInterval(_tickTimer); _tickTimer = null; }
    }

    function startPoll() {
        if (_pollTimer) return;
        _pollTimer = setInterval(window.refreshPermissions, 4000);
    }

    // ── Wiring ───────────────────────────────────────────────────

    function bind() {
        const once = el('permission-btn-once');
        const session = el('permission-btn-session');
        const deny = el('permission-btn-deny');
        if (once) {
            once.addEventListener('click', function () {
                if (_active) window.permissionDecide(_active.id, 'allow-once');
            });
        }
        if (session) {
            session.addEventListener('click', function () {
                if (_active) window.permissionDecide(_active.id, 'allow-session');
            });
        }
        if (deny) {
            deny.addEventListener('click', function () {
                if (_active) window.permissionDecide(_active.id, 'deny');
            });
        }

        // Escape must NOT silently dismiss a pending approval: the command
        // would stay blocked until the TTL expires. Deny explicitly instead.
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            const modal = el('permission-modal');
            if (modal && !modal.classList.contains('hidden') && _active) {
                e.stopPropagation();
                window.permissionDecide(_active.id, 'deny');
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { bind(); startPoll(); });
    } else {
        bind();
        startPoll();
    }
})();
