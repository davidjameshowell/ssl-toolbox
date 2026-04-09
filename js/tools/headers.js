import { apiFetch } from '../utils/api.js';

const SECURITY_HEADERS = {
    'strict-transport-security': { label: 'HSTS', weight: 20 },
    'content-security-policy': { label: 'CSP', weight: 20 },
    'x-frame-options': { label: 'X-Frame-Options', weight: 15 },
    'x-content-type-options': { label: 'X-Content-Type-Options', weight: 15 },
    'referrer-policy': { label: 'Referrer-Policy', weight: 10 },
    'permissions-policy': { label: 'Permissions-Policy', weight: 10 },
    'x-xss-protection': { label: 'X-XSS-Protection', weight: 5 },
    'cross-origin-opener-policy': { label: 'COOP', weight: 5 },
};

function gradeHeader(name, value) {
    const key = name.toLowerCase();
    if (!SECURITY_HEADERS[key]) return null;
    return { ...SECURITY_HEADERS[key], present: !!value, value: value || 'Missing' };
}

function computeScore(headers) {
    let score = 0;
    let maxScore = 0;
    for (const [key, info] of Object.entries(SECURITY_HEADERS)) {
        maxScore += info.weight;
        const val = headers[key];
        if (val) score += info.weight;
    }
    return Math.round((score / maxScore) * 100);
}

function scoreColor(score) {
    if (score >= 80) return 'text-emerald-600';
    if (score >= 50) return 'text-amber-600';
    return 'text-red-600';
}

async function analyzeHeaders() {
    const url = document.getElementById('headersUrl').value.trim();
    const resultsDiv = document.getElementById('headersResults');
    const btn = document.getElementById('headersCheckBtn');

    if (!url) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter a URL.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Fetching headers...</p>';

    try {
        const data = await apiFetch(`/api/headers?url=${encodeURIComponent(url)}`);
        const headers = data.headers || {};
        const score = computeScore(headers);

        const secRows = Object.entries(SECURITY_HEADERS).map(([key, info]) => {
            const val = headers[key];
            const present = !!val;
            const cls = present ? 'bg-emerald-50' : 'bg-red-50';
            const icon = present ? '<span class="text-emerald-600">✓</span>' : '<span class="text-red-600">✗</span>';
            return `<tr class="${cls}"><td class="px-3 py-2 text-xs">${icon}</td><td class="px-3 py-2 text-xs font-semibold">${info.label}</td><td class="px-3 py-2 text-xs font-mono break-all">${escapeHtml(val || 'Not set')}</td></tr>`;
        }).join('');

        const allRows = Object.entries(headers).map(([k, v]) =>
            `<tr><td class="px-3 py-2 text-xs font-semibold text-slate-700">${escapeHtml(k)}</td><td class="px-3 py-2 text-xs font-mono break-all">${escapeHtml(v)}</td></tr>`
        ).join('');

        resultsDiv.innerHTML = `
            <div class="mb-4 text-center">
                <span class="text-4xl font-bold ${scoreColor(score)}">${score}</span>
                <span class="text-slate-400 text-sm">/100 Security Score</span>
            </div>
            <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Security Headers</h4>
            <div class="overflow-x-auto border border-slate-200 rounded-lg mb-6">
                <table class="min-w-full text-left divide-y divide-slate-200">
                    <tbody class="divide-y divide-slate-100">${secRows}</tbody>
                </table>
            </div>
            <details class="group">
                <summary class="flex items-center gap-2 cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-800 select-none w-max">
                    <svg class="w-4 h-4 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
                    All Response Headers (${Object.keys(headers).length})
                </summary>
                <div class="mt-3 overflow-x-auto border border-slate-200 rounded-lg">
                    <table class="min-w-full text-left divide-y divide-slate-200">
                        <tbody class="divide-y divide-slate-100">${allRows}</tbody>
                    </table>
                </div>
            </details>`;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ ${err.message}</p>`;
    } finally {
        btn.disabled = false;
    }
}

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function initHeadersTool() {
    document.getElementById('headersCheckBtn').addEventListener('click', analyzeHeaders);
}
