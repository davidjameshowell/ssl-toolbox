import { apiFetch } from '../utils/api.js';
import { parseCertMetadata } from '../utils/cert.js';

async function checkSSL() {
    const host = document.getElementById('sslHost').value.trim();
    const port = document.getElementById('sslPort').value.trim() || '443';
    const resultsDiv = document.getElementById('sslResults');
    const btn = document.getElementById('sslCheckBtn');

    if (!host) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter a hostname.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Checking SSL/TLS...</p>';

    try {
        const data = await apiFetch(`/api/ssl?host=${encodeURIComponent(host)}&port=${encodeURIComponent(port)}`);

        let certHtml = '';
        if (data.certificates && data.certificates.length > 0) {
            certHtml = data.certificates.map((cert, i) => {
                const depth = i === 0 ? 'Leaf' : i === data.certificates.length - 1 ? 'Root' : 'Intermediate';
                return `
                    <div class="bg-white border border-slate-200 rounded-lg p-4 text-sm">
                        <h4 class="font-bold text-slate-700 mb-2">${depth} Certificate</h4>
                        <dl class="divide-y divide-slate-100">
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Subject</dt><dd class="text-slate-900 sm:col-span-2 break-all">${escapeHtml(cert.subject || '')}</dd></div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Issuer</dt><dd class="text-slate-900 sm:col-span-2 break-all">${escapeHtml(cert.issuer || '')}</dd></div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Valid From</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(cert.validFrom || '')}</dd></div>
                            <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Valid To</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(cert.validTo || '')}</dd></div>
                            ${cert.sans ? `<div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">SANs</dt><dd class="text-slate-900 sm:col-span-2 text-xs break-all">${escapeHtml(cert.sans)}</dd></div>` : ''}
                        </dl>
                    </div>`;
            }).join('');
        }

        resultsDiv.innerHTML = `
            <div class="space-y-4">
                <div class="bg-white border border-slate-200 rounded-lg p-4 text-sm">
                    <h4 class="font-bold text-slate-700 mb-2">Connection Details</h4>
                    <dl class="divide-y divide-slate-100">
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">TLS Version</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(data.tlsVersion || 'N/A')}</dd></div>
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Cipher Suite</dt><dd class="text-slate-900 sm:col-span-2 font-mono text-xs">${escapeHtml(data.cipher || 'N/A')}</dd></div>
                    </dl>
                </div>
                ${certHtml}
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

export function initSslcheckTool() {
    document.getElementById('sslCheckBtn').addEventListener('click', checkSSL);
}
