// -- KnowledgeBase (CVE / MITRE) --

window.kbSearch = async function () {
    const q = document.getElementById('kb-query').value.trim();
    const container = document.getElementById('kb-results');
    container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-4">Searching...</div>';

    try {
        const resp = await fetch('/api/knowledgebase/search?query=' + encodeURIComponent(q));
        const data = await resp.json();
        if (!data.ok || !data.data) {
            container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-4">Error loading data</div>';
            return;
        }
        kbRender(data.data, container);
    } catch (e) {
        container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-4">Network error: ' + e.message + '</div>';
    }
};

window.kbSearchEnter = function (e) {
    if (e.key === 'Enter') kbSearch();
};

function kbRender(data, container) {
    const cves = data.cves || [];
    const mitre = data.mitre || [];

    if (cves.length === 0 && mitre.length === 0) {
        container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-4">No results</div>';
        return;
    }

    let html = '';

    if (cves.length > 0) {
        html += '<div class="text-[9px] text-gray-600 uppercase tracking-wider mb-1 mt-2">CVEs (' + cves.length + ')</div>';
        html += cves.map(c => {
            const severity = c.cvss >= 9 ? 'text-blood' : c.cvss >= 7 ? 'text-orange-400' : c.cvss >= 4 ? 'text-yellow-500' : 'text-gray-500';
            return '<div class="bg-deep/50 border border-gray-800 rounded p-2 mb-1 text-[10px]">' +
                '<div class="flex items-center justify-between">' +
                    '<div class="flex items-center gap-2">' +
                        '<span class="text-gray-200 font-bold">' + c.id + '</span>' +
                        '<span class="' + severity + ' font-mono">' + c.cvss + '</span>' +
                        '<button onclick="kbExplainCVE(\'' + c.id + '\')" class="text-[9px] text-amber-500/70 hover:text-amber-400 transition-colors" title="Explain with AI">🤖</button>' +
                    '</div>' +
                    '<span class="text-gray-700 text-[9px]">' + (c.tools || []).join(', ') + '</span>' +
                '</div>' +
                '<div class="text-gray-400 mt-0.5">' + c.description + '</div>' +
                '<div class="text-gray-700 text-[9px]">Affects: ' + c.affected + (c.exploit_available ? ' | Exploit available' : '') + '</div>' +
            '</div>';
        }).join('');
    }

    if (mitre.length > 0) {
        html += '<div class="text-[9px] text-gray-600 uppercase tracking-wider mb-1 mt-3">MITRE ATT&CK (' + mitre.length + ')</div>';
        html += mitre.map(t => {
            return '<div class="bg-deep/50 border border-gray-800 rounded p-2 mb-1 text-[10px]">' +
                '<div class="flex items-center justify-between">' +
                    '<div class="flex items-center gap-2">' +
                        '<span class="text-gray-200 font-bold">' + t.id + '</span>' +
                        '<span class="text-gray-300">' + t.name + '</span>' +
                    '</div>' +
                    '<span class="text-cyber text-[9px]">' + t.tactic + '</span>' +
                '</div>' +
                '<div class="text-gray-400 mt-0.5">' + t.description + '</div>' +
                (t.examples ? '<div class="text-gray-700 text-[9px] mt-0.5">Examples: ' + t.examples.join(', ') + '</div>' : '') +
            '</div>';
        }).join('');
    }

    container.innerHTML = html;
}

// ── 🤖 AI Functions ──
window.kbExplainCVE = async function (cveId) {
    showToast('🤖 Fetching CVE explanation...');
    const systemPrompt = `You are a vulnerability research expert. For a given CVE, provide:
1. What the vulnerability is (in simple terms)
2. Attack vector and preconditions
3. Impact (CVSS breakdown)
4. Exploit availability and maturity
5. Remediation steps
6. Related CVEs or MITRE techniques
Be concise and technical.`;

    const result = await window.aiChat(systemPrompt, `Explain CVE: ${cveId}\nProvide detailed technical analysis.`);
    if (result) {
        const existing = document.getElementById('kb-ai-overlay');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'kb-ai-overlay';
        overlay.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/60';
        overlay.innerHTML = `<div class="bg-deep border border-cyan-500/30 rounded-lg max-w-xl w-full mx-4 max-h-[70vh] overflow-y-auto p-4 shadow-2xl">
            <div class="flex items-center justify-between mb-3">
                <span class="text-cyan-400 font-bold text-[11px] tracking-wider">🤖 ${cveId}</span>
                <button onclick="this.closest('#kb-ai-overlay').remove()" class="text-gray-600 hover:text-gray-400 text-[18px] leading-none">&times;</button>
            </div>
            <div class="text-[10px] text-gray-300 leading-relaxed whitespace-pre-wrap">${result}</div>
            <div class="mt-3 pt-2 border-t border-gray-800 flex justify-end">
                <button onclick="this.closest('#kb-ai-overlay').remove()" class="text-[9px] text-gray-600 hover:text-gray-400">Close</button>
            </div>
        </div>`;
        document.body.appendChild(overlay);
    }
};

window.kbAskAI = async function () {
    const input = document.getElementById('kb-ai-question');
    if (!input || !input.value.trim()) return;
    const q = input.value.trim();
    input.disabled = true;
    const answer = document.getElementById('kb-ai-answer');
    if (answer) answer.textContent = '⏳ Thinking...';
    const systemPrompt = `You are a cybersecurity knowledge base expert specializing in CVEs and MITRE ATT&CK. Help with vulnerability analysis, exploitation techniques, mitigation strategies, and threat intelligence. Be concise.`;
    try {
        const result = await window.aiChat(systemPrompt, `Question: ${q}`);
        if (answer) answer.textContent = result || '(no response)';
    } catch (e) {
        if (answer) answer.textContent = 'Error: ' + e.message;
    } finally {
        input.disabled = false;
        input.focus();
    }
};

window.kbAskAIEnter = function (e) { if (e.key === 'Enter') kbAskAI(); };
