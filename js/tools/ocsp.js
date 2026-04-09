import { apiFetch } from '../utils/api.js';

async function checkOCSP() {
    const certPem = document.getElementById('ocspCert').value.trim();
    const issuerPem = document.getElementById('ocspIssuer').value.trim();
    const resultsDiv = document.getElementById('ocspResults');
    const btn = document.getElementById('ocspCheckBtn');

    if (!certPem) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Paste or load a certificate.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Checking revocation status...</p>';

    try {
        const data = await apiFetch('/api/ocsp', {
            method: 'POST',
            body: JSON.stringify({ cert: certPem, issuer: issuerPem || undefined }),
        });

        const statusMap = {
            good: { text: 'Good — Certificate is valid', cls: 'bg-emerald-50 border-emerald-200 text-emerald-800' },
            revoked: { text: 'Revoked', cls: 'bg-red-50 border-red-200 text-red-800' },
            unknown: { text: 'Unknown — OCSP responder could not determine status', cls: 'bg-amber-50 border-amber-200 text-amber-800' },
        };

        const s = statusMap[data.status] || statusMap.unknown;

        resultsDiv.innerHTML = `
            <div class="${s.cls} border rounded-lg p-4 mb-4">
                <p class="font-bold text-lg">${s.text}</p>
                ${data.revokedAt ? `<p class="text-sm mt-1">Revoked at: ${escapeHtml(data.revokedAt)}</p>` : ''}
                ${data.reason ? `<p class="text-sm">Reason: ${escapeHtml(data.reason)}</p>` : ''}
            </div>
            <div class="bg-white border border-slate-200 rounded-lg overflow-hidden text-sm">
                <dl class="divide-y divide-slate-100">
                    ${data.responderUrl ? `<div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">OCSP Responder</dt><dd class="text-slate-900 sm:col-span-2 text-xs break-all">${escapeHtml(data.responderUrl)}</dd></div>` : ''}
                    ${data.producedAt ? `<div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-slate-50"><dt class="font-medium text-slate-500">Produced At</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(data.producedAt)}</dd></div>` : ''}
                    ${data.thisUpdate ? `<div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">This Update</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(data.thisUpdate)}</dd></div>` : ''}
                    ${data.nextUpdate ? `<div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-slate-50"><dt class="font-medium text-slate-500">Next Update</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(data.nextUpdate)}</dd></div>` : ''}
                </dl>
            </div>`;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ ${err.message}</p>`;
    } finally {
        btn.disabled = false;
    }
}

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function initOcspTool() {
    document.getElementById('ocspCheckBtn').addEventListener('click', checkOCSP);
}
