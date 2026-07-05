/**
 * ============================================================
 *  VulnForge — DataService
 *  Abstract storage layer: Supabase API | localStorage fallback
 * ============================================================
 * 
 * Usage:
 *   DataService.init().then(() => { ... });
 *   DataService.available  → boolean (true = Supabase online)
 *   DataService.saveReport(data)   → Promise<report>
 *   DataService.listReports()      → Promise<report[]>
 *   etc.
 */

const DataService = {
    available: false,
    _ready: false,
    _initPromise: null,

    _api(path) {
        return (window.API_URL || '') + path;
    },

    /** Initialize: check if the backend has Supabase configured. */
    init() {
        if (this._initPromise) return this._initPromise;
        this._initPromise = this._checkHealth();
        return this._initPromise;
    },

    async _checkHealth() {
        try {
            const resp = await fetch(this._api('/api/health'));
            const data = await resp.json();
            this.available = data.supabase === true;
            this._ready = true;
            console.log(`[DataService] Supabase ${this.available ? 'ONLINE' : 'OFFLINE — using localStorage'}`);
        } catch (e) {
            this.available = false;
            this._ready = true;
            console.log('[DataService] Backend unreachable, using localStorage');
        }
        return this.available;
    },

    // ============================================================
    //  GENERIC FETCH HELPERS
    // ============================================================

    async _get(path) {
        try {
            const r = await fetch(this._api(path));
            const d = await r.json();
            return d.ok ? d.data : [];
        } catch { return null; }
    },

    async _post(path, body) {
        try {
            const r = await fetch(this._api(path), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body)
            });
            return await r.json();
        } catch { return { ok: false }; }
    },

    async _delete(path) {
        try {
            const r = await fetch(this._api(path), { method: 'DELETE' });
            return (await r.json()).ok === true;
        } catch { return false; }
    },

    // ============================================================
    //  REPORTS
    // ============================================================

    async listReports() {
        if (!this.available) return null;
        return this._get('/api/reports');
    },

    async saveReport(report) {
        if (!this.available) return null;
        const r = await this._post('/api/reports', report);
        return r.ok ? r.data : null;
    },

    async deleteReport(id) {
        if (!this.available) return false;
        return this._delete(`/api/reports/${id}`);
    },

    // ============================================================
    //  SCRIPTS
    // ============================================================

    async listScripts() {
        if (!this.available) return null;
        return this._get('/api/scripts');
    },

    async saveScript(script) {
        if (!this.available) return null;
        const r = await this._post('/api/scripts', script);
        return r.ok ? r.data : null;
    },

    async deleteScript(id) {
        if (!this.available) return false;
        return this._delete(`/api/scripts/${id}`);
    },

    // ============================================================
    //  SSH CONNECTIONS
    // ============================================================

    async listConnections() {
        if (!this.available) return null;
        return this._get('/api/connections');
    },

    async saveConnection(conn) {
        if (!this.available) return null;
        const r = await this._post('/api/connections', conn);
        return r.ok ? r.data : null;
    },

    async deleteConnection(id) {
        if (!this.available) return false;
        return this._delete(`/api/connections/${id}`);
    },

    // ============================================================
    //  HAK5 PAYLOADS
    // ============================================================

    async listPayloads(device) {
        if (!this.available) return null;
        const q = device ? `?device=${device}` : '';
        return this._get(`/api/payloads${q}`);
    },

    async savePayload(payload) {
        if (!this.available) return null;
        const r = await this._post('/api/payloads', payload);
        return r.ok ? r.data : null;
    },

    async deletePayload(id) {
        if (!this.available) return false;
        return this._delete(`/api/payloads/${id}`);
    },

    // ============================================================
    //  FILE UPLOAD + LIST
    // ============================================================

    async listFiles() {
        if (!this.available) return null;
        return this._get('/api/files');
    },

    async uploadFile(file) {
        if (!this.available) return null;
        const formData = new FormData();
        formData.append('file', file);
        try {
            const r = await fetch(this._api('/api/upload'), { method: 'POST', body: formData });
            const d = await r.json();
            return d.ok ? d.data : null;
        } catch { return null; }
    },

    // ============================================================
    //  SETTINGS
    // ============================================================

    async getSetting(key) {
        if (!this.available) return null;
        try {
            const r = await fetch(this._api(`/api/settings/${encodeURIComponent(key)}`));
            const d = await r.json();
            return d.ok ? d.value : null;
        } catch { return null; }
    },

    async setSetting(key, value) {
        if (!this.available) return null;
        const r = await this._post('/api/settings', { key, value });
        return r.ok;
    },

    // ============================================================
    //  PDF GENERATION
    // ============================================================

    async generatePdf(content, title) {
        if (!this.available) return null;
        try {
            const r = await fetch(this._api('/api/generate-pdf'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ content, title, author: 'VulnForge' })
            });
            if (!r.ok) return null;
            const blob = await r.blob();
            return blob;
        } catch { return null; }
    },

    // ── Download helper ──
    downloadBlob(blob, filename) {
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 5000);
    }
};

// Auto-init on load
DataService.init();
