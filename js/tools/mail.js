import { apiFetch } from '../utils/api.js';

async function testMail() {
    const domain = document.getElementById('mailDomain').value.trim();
    const resultsDiv = document.getElementById('mailResults');
    const btn = document.getElementById('mailCheckBtn');

    if (!domain) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter a domain name.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Testing mail server...</p>';

    try {
        const data = await apiFetch(`/api/smtp?domain=${encodeURIComponent(domain)}`);

        const mxRows = (data.mx || []).map(mx =>
            `<tr><td class="px-3 py-2 text-xs">${mx.priority}</td><td class="px-3 py-2 text-xs font-mono">${escapeHtml(mx.host)}</td></tr>`
        ).join('') || '<tr><td colspan="2" class="px-3 py-2 text-xs text-amber-600">No MX records found</td></tr>';

        function statusBadge(pass) {
            if (pass === true) return '<span class="text-[10px] px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700 font-bold">PASS</span>';
            if (pass === false) return '<span class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-bold">FAIL</span>';
            return '<span class="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 text-slate-500 font-bold">N/A</span>';
        }

        resultsDiv.innerHTML = `
            <div class="space-y-4">
                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <h4 class="font-bold text-slate-700 text-sm mb-2">MX Records</h4>
                    <div class="overflow-x-auto border border-slate-200 rounded-lg">
                        <table class="min-w-full text-left divide-y divide-slate-200">
                            <thead class="bg-slate-100"><tr><th class="px-3 py-2 text-xs font-bold text-slate-600">Priority</th><th class="px-3 py-2 text-xs font-bold text-slate-600">Host</th></tr></thead>
                            <tbody class="divide-y divide-slate-100">${mxRows}</tbody>
                        </table>
                    </div>
                </div>

                ${data.smtp ? `
                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <h4 class="font-bold text-slate-700 text-sm mb-2">SMTP Check</h4>
                    <dl class="divide-y divide-slate-100 text-sm">
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Banner</dt><dd class="text-slate-900 sm:col-span-2 font-mono text-xs">${escapeHtml(data.smtp.banner || 'N/A')}</dd></div>
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">STARTTLS</dt><dd class="text-slate-900 sm:col-span-2">${data.smtp.starttls ? '✓ Supported' : '✗ Not supported'}</dd></div>
                        ${data.smtp.tlsVersion ? `<div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">TLS Version</dt><dd class="text-slate-900 sm:col-span-2">${escapeHtml(data.smtp.tlsVersion)}</dd></div>` : ''}
                    </dl>
                </div>` : ''}

                <div class="bg-white border border-slate-200 rounded-lg p-4">
                    <h4 class="font-bold text-slate-700 text-sm mb-2">Email Authentication</h4>
                    <dl class="divide-y divide-slate-100 text-sm">
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">SPF</dt><dd class="text-slate-900 sm:col-span-2">${statusBadge(data.spf?.found)} <span class="text-xs font-mono ml-2">${escapeHtml(data.spf?.record || '')}</span></dd></div>
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">DKIM</dt><dd class="text-slate-900 sm:col-span-2">${statusBadge(data.dkim?.found)} <span class="text-xs ml-2">${escapeHtml(data.dkim?.note || '')}</span></dd></div>
                        <div class="py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">DMARC</dt><dd class="text-slate-900 sm:col-span-2">${statusBadge(data.dmarc?.found)} <span class="text-xs font-mono ml-2">${escapeHtml(data.dmarc?.record || '')}</span></dd></div>
                    </dl>
                </div>
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

export function initMailTool() {
    document.getElementById('mailCheckBtn').addEventListener('click', testMail);
}
