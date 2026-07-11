// ── 📱 Mobile Lab ──

let mobileApks = [];

window.mobileLoad = async function () {
    try {
        const resp = await fetch('/api/mobile/apks');
        const json = await resp.json();
        if (json.ok) mobileApks = json.data || [];
        mobileRenderList();
    } catch (e) {
        console.error('Mobile load error:', e);
    }
};

window.mobileRenderList = function () {
    const list = document.getElementById('mobile-apk-list');
    if (!list) return;
    if (mobileApks.length === 0) {
        list.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-8">No APKs analyzed yet. Upload one to begin.</div>';
        return;
    }
    list.innerHTML = mobileApks.map(a => {
        const s = a.summary || {};
        const total = (s.critical||0) + (s.high||0) + (s.medium||0) + (s.low||0) + (s.info||0);
        const critical = s.critical || 0;
        const high = s.high || 0;
        const sizeStr = a.size ? (a.size / 1024 / 1024).toFixed(1) + ' MB' : '';
        return `<div class="bg-deep/50 border border-gray-800 rounded p-3 mb-2 text-[10px] cursor-pointer hover:border-gray-700 transition-all"
                    onclick="mobileOpenAnalysis('${a.apk_id}')">
            <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-2">
                    <span class="text-gray-200 font-bold">${a.package || a.filename}</span>
                    ${a.version_name ? `<span class="text-gray-700">v${a.version_name}</span>` : ''}
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-gray-700">${sizeStr}</span>
                    ${critical > 0 ? `<span class="text-blood font-bold">${critical} critical</span>` : ''}
                    ${high > 0 ? `<span class="text-orange-400 font-bold">${high} high</span>` : ''}
                    <span class="text-gray-600">${total} total</span>
                    <button onclick="event.stopPropagation(); mobileDelete('${a.apk_id}')"
                        class="text-gray-700 hover:text-blood transition-colors">✕</button>
                </div>
            </div>
        </div>`;
    }).join('');
};

window.mobileUpload = async function () {
    const input = document.getElementById('mobile-file-input');
    const file = input.files[0];
    if (!file) {
        showToast('⚠ Select an APK file first');
        return;
    }
    if (!file.name.endsWith('.apk')) {
        showToast('⚠ Only .apk files are supported');
        return;
    }

    const btn = document.getElementById('mobile-upload-btn');
    btn.disabled = true;
    btn.textContent = '⏳ Analyzing...';

    const formData = new FormData();
    formData.append('file', file);

    try {
        const resp = await fetch('/api/mobile/upload', { method: 'POST', body: formData });
        const json = await resp.json();
        if (json.ok) {
            showToast('✅ APK analyzed: ' + (json.data.package || file.name));
            input.value = '';
            await mobileLoad();
            if (json.data.apk_id) {
                mobileOpenAnalysis(json.data.apk_id);
            }
        } else {
            showToast('⚠ Error: ' + (json.error || 'Unknown'));
        }
    } catch (e) {
        showToast('⚠ Network error: ' + e.message);
    } finally {
        btn.disabled = false;
        btn.textContent = '📤 Upload & Analyze';
    }
};

window.mobileOpenAnalysis = async function (apkId) {
    const container = document.getElementById('mobile-analysis');
    container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-8">Loading analysis...</div>';

    try {
        const resp = await fetch('/api/mobile/analyze/' + apkId);
        const json = await resp.json();
        if (!json.ok || !json.data) {
            container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-4">Error loading analysis</div>';
            return;
        }
        mobileRenderAnalysis(json.data, container);
    } catch (e) {
        container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-4">Error: ' + e.message + '</div>';
    }
};

function mobileRenderAnalysis(data, container) {
    const findings = data.findings || [];
    const summary = data.summary || {};
    const perms = data.permissions || [];
    const comps = data.components || {};
    const err = data.error;

    const sevIcons = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' };
    const sevOrder = ['critical', 'high', 'medium', 'low', 'info'];
    const grouped = {};
    for (const f of findings) {
        const s = f.severity || 'info';
        if (!grouped[s]) grouped[s] = [];
        grouped[s].push(f);
    }

    let html = `<div class="bg-deep/50 border border-gray-800 rounded p-3 mb-3 text-[10px]">
        <div class="flex items-center justify-between mb-2">
            <div>
                <span class="text-gray-200 font-bold text-xs">${data.package || data.apk_id}</span>
                ${data.version_name ? `<span class="text-gray-700 ml-2">v${data.version_name} (code ${data.version_code})</span>` : ''}
            </div>
            <button onclick="document.getElementById('mobile-analysis').innerHTML = '<div class=\\'text-[10px] text-gray-700 text-center py-8\\'>Select an APK to view analysis</div>'"
                class="text-gray-700 hover:text-gray-400">✕</button>
        </div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-2 mb-2">
            ${data.min_sdk ? `<div><span class="text-gray-700">Min SDK:</span> <span class="text-gray-300">${data.min_sdk}</span></div>` : ''}
            ${data.target_sdk ? `<div><span class="text-gray-700">Target SDK:</span> <span class="text-gray-300">${data.target_sdk}</span></div>` : ''}
            ${data.size ? `<div><span class="text-gray-700">Size:</span> <span class="text-gray-300">${(data.size/1024/1024).toFixed(1)} MB</span></div>` : ''}
            ${data.md5 ? `<div><span class="text-gray-700">MD5:</span> <span class="text-gray-500 font-mono text-[9px]">${data.md5.slice(0,16)}...</span></div>` : ''}
        </div>
        ${err ? `<div class="text-blood mb-2">⚠ Could not fully decompile: ${err}</div>` : ''}

        ${perms.length > 0 ? `<details class="mb-2">
            <summary class="text-gray-600 cursor-pointer hover:text-gray-400">🔑 Permissions (${perms.length})</summary>
            <div class="mt-1 max-h-32 overflow-y-auto text-gray-500 font-mono">${perms.map(p => `<div>• ${p}</div>`).join('')}</div>
        </details>` : ''}

        ${comps.activities || comps.services ? `<details class="mb-2">
            <summary class="text-gray-600 cursor-pointer hover:text-gray-400">📦 Components</summary>
            <div class="mt-1 grid grid-cols-2 gap-2 text-gray-500">
                ${comps.activities ? `<div><span class="text-gray-600">Activities:</span> ${comps.activities.filter(a => a.exported).length} exported / ${comps.activities.length} total</div>` : ''}
                ${comps.services ? `<div><span class="text-gray-600">Services:</span> ${comps.services.filter(s => s.exported).length} exported / ${comps.services.length} total</div>` : ''}
                ${comps.providers ? `<div><span class="text-gray-600">Providers:</span> ${comps.providers.filter(p => p.exported).length} exported / ${comps.providers.length} total</div>` : ''}
                ${comps.receivers ? `<div><span class="text-gray-600">Receivers:</span> ${comps.receivers.filter(r => r.exported).length} exported / ${comps.receivers.length} total</div>` : ''}
            </div>
        </details>` : ''}
    </div>`;

    // Findings by severity
    if (findings.length === 0) {
        html += '<div class="text-[10px] text-gray-700 text-center py-4">No findings. Clean APK!</div>';
    } else {
        for (const sev of sevOrder) {
            const items = grouped[sev] || [];
            if (items.length === 0) continue;
            const colorMap = { critical: 'text-blood', high: 'text-orange-400', medium: 'text-yellow-500', low: 'text-green-500', info: 'text-blue-400' };
            html += `<div class="mb-2">
                <div class="flex items-center gap-2 mb-1">
                    <span class="${colorMap[sev] || 'text-gray-500'} font-bold text-[10px] uppercase">${sevIcons[sev] || '•'} ${sev.toUpperCase()} (${items.length})</span>
                </div>`;
            for (const f of items) {
                html += `<div class="bg-deep/30 border border-gray-800 rounded p-2 mb-1 text-[10px] ml-2">
                    <div class="flex items-center justify-between">
                        <span class="text-gray-200 font-semibold">${f.title}</span>
                        <span class="text-gray-700 text-[9px]">${f.category || ''}</span>
                    </div>
                    <div class="text-gray-400 mt-0.5">${f.description}</div>
                    ${f.file ? `<div class="text-gray-700 text-[9px] mt-0.5 font-mono">${f.file}</div>` : ''}
                </div>`;
            }
            html += '</div>';
        }
    }

    container.innerHTML = html;
}

window.mobileDelete = async function (apkId) {
    if (!confirm('Delete this APK analysis?')) return;
    try {
        await fetch('/api/mobile/apks/' + apkId, { method: 'DELETE' });
        const container = document.getElementById('mobile-analysis');
        if (container) container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-8">Select an APK to view analysis</div>';
        await mobileLoad();
    } catch (e) {
        showToast('⚠ Error: ' + e.message);
    }
};

// ── ADB / Frida Dynamic ──

window.mobileListDevices = async function () {
    const container = document.getElementById('mobile-devices');
    if (!container) return;
    container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-2">Scanning...</div>';

    try {
        const resp = await fetch('/api/mobile/devices');
        const json = await resp.json();
        if (!json.ok || !json.data) {
            container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-2">Error connecting to ADB</div>';
            return;
        }
        const devices = json.data;
        if (devices.length === 0) {
            container.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-2">No devices connected. Plug in a device or start an emulator on Kali.</div>';
            return;
        }
        container.innerHTML = devices.map(d => `
            <div class="flex items-center justify-between bg-deep/30 border border-gray-800 rounded p-2 mb-1 text-[10px]">
                <div class="flex items-center gap-2">
                    <span class="text-green-500">●</span>
                    <span class="text-gray-300 font-mono">${d.serial}</span>
                    ${d.model ? `<span class="text-gray-700">${d.model}</span>` : ''}
                    ${d.device ? `<span class="text-gray-700">${d.device}</span>` : ''}
                </div>
                <span class="text-gray-600">${d.state}</span>
            </div>
        `).join('');
    } catch (e) {
        container.innerHTML = '<div class="text-[10px] text-red-500 text-center py-2">Error: ' + e.message + '</div>';
    }
};

window.mobileLoadFridaScripts = async function () {
    const select = document.getElementById('mobile-frida-script');
    if (!select) return;
    try {
        const resp = await fetch('/api/mobile/frida/scripts');
        const json = await resp.json();
        if (!json.ok || !json.data) return;
        select.innerHTML = json.data.map(s =>
            `<option value="${s.name}">${s.name} — ${s.description}</option>`
        ).join('');
    } catch (e) {
        console.error('Frida scripts error:', e);
    }
};

window.mobileRunFrida = async function () {
    const device = document.getElementById('mobile-frida-device')?.value?.trim() || '';
    const script = document.getElementById('mobile-frida-script')?.value || 'template.js';
    const target = document.getElementById('mobile-frida-target')?.value?.trim() || '';

    const output = document.getElementById('mobile-frida-output');
    if (!output) return;
    output.textContent = '⏳ Running Frida script...\n';

    try {
        const resp = await fetch('/api/mobile/frida/run', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ device_serial: device, script_name: script, target_process: target }),
        });
        const json = await resp.json();
        if (json.ok && json.data) {
            output.textContent = json.data.output || '(no output)';
        } else {
            output.textContent = 'Error: ' + (json.error || 'Unknown');
        }
    } catch (e) {
        output.textContent = 'Network error: ' + e.message;
    }
};

// Init
document.addEventListener('DOMContentLoaded', function () {
    setTimeout(() => {
        mobileLoad();
        mobileLoadFridaScripts();
    }, 1000);
});
