// ── 🔍 Forensics Lab ──

let forensicsItems = [];

window.forensicsLoad = async function () {
    try {
        const resp = await fetch('/api/forensics/list');
        const json = await resp.json();
        if (json.ok) forensicsItems = json.data || [];
        forensicsRenderList();
    } catch (e) {
        console.error('Forensics load error:', e);
    }
};

window.forensicsRenderList = function () {
    const list = document.getElementById('forensics-list');
    if (!list) return;
    if (forensicsItems.length === 0) {
        list.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-8">No evidence analyzed yet. Upload a file to begin.</div>';
        return;
    }
    const catIcons = { file: '📄', disk: '💿', image: '🖼️', memory: '🧠', network: '🌐', pcap: '🌐', stego: '🖼️' };
    list.innerHTML = forensicsItems.map(e => {
        const s = e.summary || {};
        const total = (s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0)+(s.info||0);
        const icon = catIcons[e.category] || '📄';
        const sizeStr = e.size ? (e.size/1024/1024).toFixed(1)+' MB' : '';
        return `<div class="bg-deep/50 border border-gray-800 rounded p-3 mb-2 text-[10px] cursor-pointer hover:border-gray-700 transition-all"
                    onclick="forensicsOpen('${e.id}')">
            <div class="flex items-center justify-between">
                <div class="flex items-center gap-2">
                    <span>${icon}</span>
                    <span class="text-gray-200 font-bold">${e.filename}</span>
                    <span class="text-gray-700">${e.file_type ? e.file_type.slice(0,40) : ''}</span>
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-gray-700">${sizeStr}</span>
                    <span class="text-gray-600">${s.critical||0}🔴 ${s.high||0}🟠</span>
                    <span class="text-gray-600">${total} total</span>
                    <button onclick="event.stopPropagation(); forensicsDelete('${e.id}')"
                        class="text-gray-700 hover:text-blood transition-colors">✕</button>
                </div>
            </div>
            <div class="text-[9px] text-gray-700 mt-1">${e.category || ''} | ${e.file_type ? e.file_type.slice(0,60) : ''}</div>
        </div>`;
    }).join('');
};

window.forensicsUpload = async function () {
    const input = document.getElementById('forensics-file-input');
    const file = input.files[0];
    const category = document.getElementById('forensics-category').value;
    if (!file) { showToast('⚠ Select a file first'); return; }

    const btn = document.getElementById('forensics-upload-btn');
    btn.disabled = true; btn.textContent = '⏳ Analyzing...';

    const fd = new FormData();
    fd.append('file', file);
    fd.append('category', category);

    try {
        const resp = await fetch('/api/forensics/upload', { method: 'POST', body: fd });
        const json = await resp.json();
        if (json.ok) {
            showToast('✅ Analysis complete: ' + file.name);
            input.value = '';
            await forensicsLoad();
            if (json.data.id) forensicsOpen(json.data.id);
        } else {
            showToast('⚠ Error: ' + (json.error || 'Unknown'));
        }
    } catch (e) {
        showToast('⚠ Network error: ' + e.message);
    } finally {
        btn.disabled = false; btn.textContent = '📤 Upload & Analyze';
    }
};

window.forensicsOpen = async function (evId) {
    const container = document.getElementById('forensics-analysis');
    container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-8">Loading analysis...</div>';

    try {
        const resp = await fetch('/api/forensics/analyze/' + evId);
        const json = await resp.json();
        if (!json.ok || !json.data) {
            container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-4">Error loading analysis</div>';
            return;
        }
        forensicsRenderAnalysis(json.data, container);
    } catch (e) {
        container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-4">Error: ' + e.message + '</div>';
    }
};

function forensicsRenderAnalysis(data, container) {
    const findings = data.findings || [];
    const analysis = data.analysis || {};
    const summary = data.summary || {};
    const sevOrder = ['critical','high','medium','low','info'];
    const sevIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' };
    const grouped = {};
    for (const f of findings) {
        const s = f.severity || 'info';
        if (!grouped[s]) grouped[s] = [];
        grouped[s].push(f);
    }

    let html = `<div class="bg-deep/50 border border-gray-800 rounded p-3 mb-3 text-[10px]">
        <div class="flex items-center justify-between mb-2">
            <div>
                <span class="text-gray-200 font-bold text-xs">${data.filename}</span>
                <span class="text-gray-700 ml-2">${data.file_type || ''}</span>
                <span class="text-gray-700 ml-2">${data.category || ''}</span>
            </div>
            <div class="flex items-center gap-2">
                <button onclick="forensicsRunTool('${data.id}','strings')" class="text-[9px] text-cyber hover:text-cyber/80 border border-cyber/30 rounded px-2 py-0.5">🔎 Strings</button>
                <button onclick="forensicsRunTool('${data.id}','exiftool')" class="text-[9px] text-cyber hover:text-cyber/80 border border-cyber/30 rounded px-2 py-0.5">📋 Exif</button>
                <button onclick="forensicsRunTool('${data.id}','hexdump')" class="text-[9px] text-cyber hover:text-cyber/80 border border-cyber/30 rounded px-2 py-0.5">📝 Hex</button>
                ${data.category === 'disk' || data.category === 'image' ? `<button onclick="forensicsRunTool('${data.id}','binwalk')" class="text-[9px] text-cyber hover:text-cyber/80 border border-cyber/30 rounded px-2 py-0.5">📦 Binwalk</button>` : ''}
                ${data.category === 'stego' || data.category === 'image' ? `<button onclick="forensicsRunTool('${data.id}','zsteg')" class="text-[9px] text-cyber hover:text-cyber/80 border border-cyber/30 rounded px-2 py-0.5">🖼️ Zsteg</button>` : ''}
                <button onclick="document.getElementById('forensics-analysis').innerHTML = '<div class=\\'text-[10px] text-gray-700 text-center py-8\\'>Select evidence to view analysis</div>'"
                    class="text-gray-700 hover:text-gray-400">✕</button>
            </div>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-2">
            <div><span class="text-gray-700">Size:</span> <span class="text-gray-300">${data.size ? (data.size/1024/1024).toFixed(1)+' MB' : '?'}</span></div>
            <div><span class="text-gray-700">MD5:</span> <span class="text-gray-500 font-mono text-[9px]">${(data.md5||'').slice(0,16)}...</span></div>
            <div><span class="text-gray-700">SHA256:</span> <span class="text-gray-500 font-mono text-[9px]">${(data.sha256||'').slice(0,16)}...</span></div>
            ${analysis.strings ? `<div><span class="text-gray-700">Strings:</span> <span class="text-gray-300">${analysis.strings.total || 0}</span></div>` : ''}
        </div>
    </div>`;

    // Findings by severity
    if (findings.length === 0) {
        html += '<div class="text-[10px] text-gray-700 text-center py-4">No significant findings.</div>';
    } else {
        for (const sev of sevOrder) {
            const items = grouped[sev] || [];
            if (items.length === 0) continue;
            const colors = { critical: 'text-blood', high: 'text-orange-400', medium: 'text-yellow-500', low: 'text-green-500', info: 'text-blue-400' };
            html += `<div class="mb-2">
                <div class="flex items-center gap-2 mb-1">
                    <span class="${colors[sev]||'text-gray-500'} font-bold text-[10px] uppercase">${sevIcons[sev]||'•'} ${sev.toUpperCase()} (${items.length})</span>
                </div>`;
            for (const f of items) {
                const fEnc = encodeURIComponent(JSON.stringify(f));
                html += `<div class="bg-deep/30 border border-gray-800 rounded p-2 mb-1 text-[10px] ml-2">
                    <div class="flex items-center justify-between">
                        <span class="text-gray-200 font-semibold">${f.title}</span>
                        <div class="flex items-center gap-2">
                            <span class="text-gray-700 text-[9px]">${f.category || ''}</span>
                            <button onclick="forensicsExplainFinding('${fEnc}')" class="text-[9px] text-amber-500/70 hover:text-amber-400 transition-colors" title="Explain with AI">🤖</button>
                        </div>
                    </div>
                    <div class="text-gray-400 mt-0.5">${f.description}</div>
                </div>`;
            }
            html += '</div>';
        }
    }

    // Analysis details
    if (analysis.metadata) {
        html += `<details class="mt-2"><summary class="text-gray-600 cursor-pointer hover:text-gray-400 text-[10px]">📋 Metadata</summary>
            <pre class="text-[9px] text-gray-500 font-mono mt-1 max-h-40 overflow-y-auto bg-void/50 rounded p-2">${analysis.metadata.slice(0,3000)}</pre></details>`;
    }
    if (analysis.binwalk) {
        html += `<details class="mt-1"><summary class="text-gray-600 cursor-pointer hover:text-gray-400 text-[10px]">📦 Binwalk</summary>
            <pre class="text-[9px] text-gray-500 font-mono mt-1 max-h-40 overflow-y-auto bg-void/50 rounded p-2">${analysis.binwalk.slice(0,3000)}</pre></details>`;
    }
    if (analysis.network) {
        const n = analysis.network;
        html += `<div class="bg-deep/30 border border-gray-800 rounded p-2 mt-2 text-[10px]">
            <span class="text-gray-600">🌐 HTTP requests: ${n.http_requests || 0} | DNS queries: ${n.dns_queries || 0} | Potential creds: ${n.potential_creds || 0}</span>
        </div>`;
    }

    // Tool output area
    html += `<div id="forensics-tool-output" class="mt-2">
        <div class="text-[10px] text-gray-700 text-center py-2">Click a tool button above to run analysis</div>
    </div>`;

    container.innerHTML = html;
}

window.forensicsRunTool = async function (evId, tool) {
    const output = document.getElementById('forensics-tool-output');
    if (!output) return;
    output.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-2">⏳ Running ' + tool + '...</div>';

    try {
        const resp = await fetch('/api/forensics/analyze/' + evId + '/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tool }),
        });
        const json = await resp.json();
        if (json.ok && json.data) {
            const d = json.data;
            let content = '';
            if (d.output) content = d.output.slice(0,5000);
            else if (d.metadata) content = d.metadata.slice(0,5000);
            else if (d.hexdump) content = d.hexdump.slice(0,5000);
            else if (d.findings) {
                content = d.findings.map(f => `[${f.severity}] ${f.title}: ${f.description}`).join('\n');
            }
            else content = JSON.stringify(d, null, 2).slice(0,5000);
            output.innerHTML = `<pre class="text-[9px] text-gray-400 font-mono bg-void border border-gray-800 rounded p-2 max-h-60 overflow-y-auto">${content}</pre>`;
        } else {
            output.innerHTML = '<div class="text-[10px] text-red-500">Error: ' + (json.error || 'Unknown') + '</div>';
        }
    } catch (e) {
        output.innerHTML = '<div class="text-[10px] text-red-500">Network error: ' + e.message + '</div>';
    }
};

window.forensicsDelete = async function (evId) {
    if (!confirm('Delete this evidence?')) return;
    try {
        await fetch('/api/forensics/' + evId, { method: 'DELETE' });
        const container = document.getElementById('forensics-analysis');
        if (container) container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-8">Select evidence to view analysis</div>';
        await forensicsLoad();
    } catch (e) {
        showToast('⚠ Error: ' + e.message);
    }
};

// ── 🤖 AI Assistant ──

window.forensicsExplainFinding = async function (encodedFinding) {
    try {
        const finding = JSON.parse(decodeURIComponent(encodedFinding));
        const systemPrompt = `You are a digital forensics expert. Explain this forensic finding in simple terms. Include:
1. What this finding means in context of digital forensics
2. Why it's significant (evidentiary value)
3. What an investigator should do next
4. Related forensic artifacts to check
Keep it concise, max 3 paragraphs.`;

        const userMessage = `Analyze this forensic finding:
- Title: ${finding.title}
- Severity: ${finding.severity}
- Description: ${finding.description}
- Category: ${finding.category}`;

        showToast('🤖 Asking AI...');
        const result = await window.aiChat(systemPrompt, userMessage);
        if (result) {
            const existing = document.getElementById('forensics-ai-overlay');
            if (existing) existing.remove();

            const overlay = document.createElement('div');
            overlay.id = 'forensics-ai-overlay';
            overlay.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/60';
            overlay.innerHTML = `<div class="bg-deep border border-amber-500/30 rounded-lg max-w-xl w-full mx-4 max-h-[70vh] overflow-y-auto p-4 shadow-2xl">
                <div class="flex items-center justify-between mb-3">
                    <span class="text-amber-400 font-bold text-[11px] tracking-wider">🤖 AI Forensics Analysis</span>
                    <button onclick="this.closest('#forensics-ai-overlay').remove()" class="text-gray-600 hover:text-gray-400 text-[18px] leading-none">&times;</button>
                </div>
                <div class="text-[10px] text-gray-300 leading-relaxed whitespace-pre-wrap">${result}</div>
                <div class="mt-3 pt-2 border-t border-gray-800 flex justify-end">
                    <button onclick="this.closest('#forensics-ai-overlay').remove()" class="text-[9px] text-gray-600 hover:text-gray-400">Close</button>
                </div>
            </div>`;
            document.body.appendChild(overlay);
        }
    } catch (e) {
        showToast('⚠ AI error: ' + e.message);
    }
};

window.forensicsAskAI = async function () {
    const input = document.getElementById('forensics-ai-question');
    if (!input || !input.value.trim()) return;
    const question = input.value.trim();
    input.disabled = true;
    const answerBox = document.getElementById('forensics-ai-answer');
    if (answerBox) answerBox.textContent = '⏳ Thinking...';

    const fnameEl = document.querySelector('#forensics-analysis .text-gray-200.font-bold');
    const fname = fnameEl ? fnameEl.textContent : 'Unknown file';

    const systemPrompt = `You are a digital forensics expert assistant integrated into VulnForge CTF dashboard.
The user is analyzing a forensic artifact (${fname}). Answer their question concisely and helpfully.
Be specific to digital forensics, incident response, and CTF challenges.`;

    try {
        const result = await window.aiChat(systemPrompt, `Regarding forensic artifact "${fname}": ${question}`);
        if (answerBox) answerBox.textContent = result || '(no response)';
        else showToast('🤖 ' + (result || 'Done'));
    } catch (e) {
        if (answerBox) answerBox.textContent = 'Error: ' + e.message;
        showToast('⚠ AI error: ' + e.message);
    } finally {
        input.disabled = false;
        input.focus();
    }
};

window.forensicsAskAIEnter = function (e) {
    if (e.key === 'Enter') forensicsAskAI();
};
