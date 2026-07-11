// ── CTF Mode ──

let ctfChallenges = [];

window.ctfLoad = async function () {
    try {
        const resp = await fetch('/api/ctf/challenges');
        const data = await resp.json();
        if (data.ok) ctfChallenges = data.data || [];
        await ctfLoadScore();
        ctfRender();
    } catch (e) {
        console.error('CTF load error:', e);
    }
};

window.ctfLoadScore = async function () {
    try {
        const resp = await fetch('/api/ctf/score');
        const data = await resp.json();
        if (!data.ok || !data.data) return;
        const s = data.data;
        document.getElementById('ctf-score-solved').textContent = s.solved || 0;
        document.getElementById('ctf-score-total').textContent = s.total || 0;
        document.getElementById('ctf-score-points').textContent = s.points || 0;
        document.getElementById('ctf-score-total-pts').textContent = s.total_points || 0;
        const pct = s.total > 0 ? Math.round((s.solved / s.total) * 100) : 0;
        const bar = document.getElementById('ctf-score-bar');
        if (bar) bar.style.width = pct + '%';
    } catch (e) {
        console.error('CTF score error:', e);
    }
};

window.ctfRender = function () {
    const list = document.getElementById('ctf-list');
    if (!list) return;
    if (ctfChallenges.length === 0) {
        list.innerHTML = '<div class="text-[10px] text-gray-700 text-center py-4">No challenges yet. Add your first CTF challenge!</div>';
        return;
    }
    const diffColors = { easy: 'text-green-500', medium: 'text-yellow-500', hard: 'text-blood', insane: 'text-purple-500' };
    list.innerHTML = ctfChallenges.map(c => {
        const diffColor = diffColors[c.difficulty] || 'text-gray-500';
        const solved = c.solved ? 'border-l-green-500 bg-green-500/5' : 'border-l-gray-800';
        return `<div class="border border-gray-800 border-l-2 ${solved} rounded p-3 mb-2 text-[10px]">
            <div class="flex items-center justify-between mb-1">
                <div class="flex items-center gap-2">
                    <span class="text-gray-200 font-bold">${c.title}</span>
                    <span class="${diffColor}">${c.difficulty}</span>
                    <span class="text-gray-700">${c.category}</span>
                </div>
                <div class="flex items-center gap-3">
                    <span class="text-cyber font-mono">+${c.points}pts</span>
                    ${c.solved ? '<span class="text-green-500">Solved</span>' : ''}
                    <button onclick="ctfDelete(${c.id})" class="text-gray-700 hover:text-blood transition-colors">X</button>
                </div>
            </div>
            <div class="text-gray-400 mb-1">${c.description}</div>
            ${c.target ? `<div class="text-gray-700 mb-1">Target: ${c.target}</div>` : ''}
            <div class="flex items-center gap-2 mt-1.5">
                ${c.solved ? '' : `<input id="ctf-flag-${c.id}" placeholder="Enter flag..." class="flex-1 bg-deep border border-gray-800 rounded px-2 py-1 text-[10px] text-gray-300 placeholder-gray-700 font-mono" onkeyup="if(event.key==='Enter')ctfSubmitFlag(${c.id})">
                <button onclick="ctfSubmitFlag(${c.id})" class="bg-cyber/10 hover:bg-cyber/20 text-cyber border border-cyber/30 px-3 py-1 rounded text-[10px] transition-all">Submit</button>`}
                ${c.hints ? `<button onclick="ctfShowHint('${c.hints.replace(/'/g, "\\'")}')" class="text-gray-700 hover:text-yellow-500 text-[9px]">Hint</button>` : ''}
                    <button onclick="ctfAIHint(${c.id})" class="text-amber-500/70 hover:text-amber-400 text-[9px] transition-colors" title="AI Hint">🤖</button>
            </div>
        </div>`;
    }).join('');
};

window.ctfAdd = async function () {
    const title = document.getElementById('ctf-title').value.trim();
    const category = document.getElementById('ctf-category').value;
    const difficulty = document.getElementById('ctf-difficulty').value;
    const points = parseInt(document.getElementById('ctf-points').value) || 100;
    const flags = document.getElementById('ctf-flags').value.trim();
    const target = document.getElementById('ctf-target').value.trim();
    const description = document.getElementById('ctf-description').value.trim();
    const hints = document.getElementById('ctf-hints').value.trim();

    if (!title || !flags) {
        alert('Title and at least one flag are required');
        return;
    }

    try {
        const resp = await fetch('/api/ctf/challenges', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ title, category, difficulty, points, flags, target, description, hints }),
        });
        const data = await resp.json();
        if (data.ok) {
            document.getElementById('ctf-title').value = '';
            document.getElementById('ctf-flags').value = '';
            document.getElementById('ctf-target').value = '';
            document.getElementById('ctf-description').value = '';
            document.getElementById('ctf-hints').value = '';
            await ctfLoad();
        } else {
            alert('Error: ' + (data.error || 'unknown'));
        }
    } catch (e) {
        alert('Network error: ' + e.message);
    }
};

window.ctfSubmitFlag = async function (challengeId) {
    const input = document.getElementById('ctf-flag-' + challengeId);
    if (!input || !input.value.trim()) return;
    const flag = input.value.trim();

    try {
        const resp = await fetch('/api/ctf/challenges/' + challengeId + '/solve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ flag }),
        });
        const data = await resp.json();
        input.value = '';
        if (data.ok) {
            await ctfLoad();
            showToast((data.message || 'Flag correct!'));
        } else {
            showToast((data.error || 'Incorrect flag'));
        }
    } catch (e) {
        showToast('Error: ' + e.message);
    }
};

window.ctfDelete = async function (challengeId) {
    if (!confirm('Delete this challenge?')) return;
    try {
        await fetch('/api/ctf/challenges/' + challengeId, { method: 'DELETE' });
        await ctfLoad();
    } catch (e) {
        console.error('CTF delete error:', e);
    }
};

window.ctfShowHint = function (hints) {
    showToast(hints);
};

// ── 🤖 AI Hint (doesn't reveal flag) ──
window.ctfAIHint = async function (challengeId) {
    const c = ctfChallenges.find(x => x.id === challengeId);
    if (!c) { showToast('⚠ Challenge not found'); return; }
    const points = parseInt(document.getElementById('ctf-points')?.value) || 0;
    showToast('🤖 Asking AI for a hint...');
    const systemPrompt = `You are a CTF coach. The user is solving a CTF challenge. Give a helpful hint that guides them toward the solution WITHOUT revealing the flag. Provide:
1. What to look for or analyze
2. Suggested tools or techniques
3. Common pitfalls to avoid
4. A nudge in the right direction
DO NOT give the flag or direct answer.`;
    const result = await window.aiChat(systemPrompt, `Challenge: ${c.title}\nCategory: ${c.category}\nDifficulty: ${c.difficulty}\nDescription: ${c.description}\nPoints: ${c.points}\nHints available: ${c.hints || 'none'}\n\nGive me a hint without revealing the flag.`);
    if (result) {
        const existing = document.getElementById('ctf-ai-overlay');
        if (existing) existing.remove();
        const overlay = document.createElement('div');
        overlay.id = 'ctf-ai-overlay';
        overlay.className = 'fixed inset-0 z-50 flex items-center justify-center bg-black/60';
        overlay.innerHTML = `<div class="bg-deep border border-purple-500/30 rounded-lg max-w-xl w-full mx-4 max-h-[70vh] overflow-y-auto p-4 shadow-2xl">
            <div class="flex items-center justify-between mb-3">
                <span class="text-purple-400 font-bold text-[11px] tracking-wider">🤖 Hint: ${c.title}</span>
                <button onclick="this.closest('#ctf-ai-overlay').remove()" class="text-gray-600 hover:text-gray-400 text-[18px] leading-none">&times;</button>
            </div>
            <div class="text-[10px] text-gray-300 leading-relaxed whitespace-pre-wrap">${result}</div>
            <div class="mt-3 pt-2 border-t border-gray-800 flex justify-end">
                <button onclick="this.closest('#ctf-ai-overlay').remove()" class="text-[9px] text-gray-600 hover:text-gray-400">Close</button>
            </div>
        </div>`;
        document.body.appendChild(overlay);
    }
};

window.ctfAskAI = async function () {
    const input = document.getElementById('ctf-ai-question');
    if (!input || !input.value.trim()) return;
    const q = input.value.trim();
    input.disabled = true;
    const answer = document.getElementById('ctf-ai-answer');
    if (answer) answer.textContent = '⏳ Thinking...';
    const ctx = ctfChallenges.slice(0, 5).map(c => `- ${c.title} (${c.difficulty}, ${c.category}, ${c.points}pts, solved=${c.solved})`).join('\n');
    const systemPrompt = `You are a CTF coach and challenge solver. The user is working on CTF challenges. Provide guidance, hints, methodology, and tool suggestions. DO NOT reveal flags. Help them learn the techniques.`;
    try {
        const result = await window.aiChat(systemPrompt, `Active challenges:\n${ctx}\n\nQuestion: ${q}`);
        if (answer) answer.textContent = result || '(no response)';
    } catch (e) {
        if (answer) answer.textContent = 'Error: ' + e.message;
    } finally {
        input.disabled = false;
        input.focus();
    }
};

window.ctfAskAIEnter = function (e) { if (e.key === 'Enter') ctfAskAI(); };

window.ctfAutoFillTarget = function () {
    const targetInput = document.getElementById('ctf-target');
    if (targetInput && window.lastScopedIp) {
        targetInput.value = window.lastScopedIp;
    }
};

document.addEventListener('DOMContentLoaded', function () {
    setTimeout(ctfAutoFillTarget, 500);
});
