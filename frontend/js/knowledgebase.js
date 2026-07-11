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
