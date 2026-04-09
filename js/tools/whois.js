import { apiFetch } from '../utils/api.js';

async function lookupWhois() {
    const domain = document.getElementById('whoisDomain').value.trim();
    const resultsDiv = document.getElementById('whoisResults');
    const btn = document.getElementById('whoisLookupBtn');

    if (!domain) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter a domain name.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Looking up...</p>';

    try {
        const data = await apiFetch(`/api/whois?domain=${encodeURIComponent(domain)}`);

        if (data.raw) {
            const fields = data.parsed || {};
            let parsedHtml = '';
            if (Object.keys(fields).length > 0) {
                const rows = Object.entries(fields).map(([k, v]) =>
                    `<div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500 text-xs">${escapeHtml(k)}</dt><dd class="text-slate-900 sm:col-span-2 text-xs break-all">${escapeHtml(v)}</dd></div>`
                ).join('');
                parsedHtml = `<div class="bg-white border border-slate-200 rounded-lg overflow-hidden text-sm mb-4"><dl class="divide-y divide-slate-100">${rows}</dl></div>`;
            }

            resultsDiv.innerHTML = `
                ${parsedHtml}
                <details class="group">
                    <summary class="flex items-center gap-2 cursor-pointer text-sm font-medium text-blue-600 hover:text-blue-800 select-none w-max">
                        <svg class="w-4 h-4 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
                        Raw WHOIS Response
                    </summary>
                    <pre class="mt-3 bg-slate-800 text-emerald-400 rounded-lg p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-words max-h-[400px] overflow-y-auto">${escapeHtml(data.raw)}</pre>
                </details>`;
        } else {
            resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">No WHOIS data returned.</p>';
        }
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ ${err.message}</p>`;
    } finally {
        btn.disabled = false;
    }
}

function escapeHtml(str) {
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

export function initWhoisTool() {
    document.getElementById('whoisLookupBtn').addEventListener('click', lookupWhois);
}
