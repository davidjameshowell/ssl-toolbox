import { apiFetch } from '../utils/api.js';

const RECORD_TYPES = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA', 'CAA'];

async function lookupDNS() {
    const domain = document.getElementById('dnsDomain').value.trim();
    const recordType = document.getElementById('dnsRecordType').value;
    const resultsDiv = document.getElementById('dnsResults');
    const btn = document.getElementById('dnsLookupBtn');

    if (!domain) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter a domain name.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Looking up...</p>';

    try {
        const data = await apiFetch(`/api/dns?domain=${encodeURIComponent(domain)}&type=${recordType}`);

        if (!data.answers || data.answers.length === 0) {
            resultsDiv.innerHTML = `<p class="text-amber-600 text-sm">No ${recordType} records found for ${domain}.</p>`;
            return;
        }

        const rows = data.answers.map(a => `
            <tr>
                <td class="px-3 py-2 text-xs font-mono">${escapeHtml(a.name || domain)}</td>
                <td class="px-3 py-2 text-xs">${a.type || recordType}</td>
                <td class="px-3 py-2 text-xs">${a.TTL || '-'}</td>
                <td class="px-3 py-2 text-xs font-mono break-all">${escapeHtml(a.data || '')}</td>
            </tr>`).join('');

        resultsDiv.innerHTML = `
            <div class="overflow-x-auto border border-slate-200 rounded-lg">
                <table class="min-w-full text-left divide-y divide-slate-200">
                    <thead class="bg-slate-100"><tr>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Name</th>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Type</th>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">TTL</th>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Data</th>
                    </tr></thead>
                    <tbody class="divide-y divide-slate-100">${rows}</tbody>
                </table>
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

export function initDnsTool() {
    document.getElementById('dnsLookupBtn').addEventListener('click', lookupDNS);

    const select = document.getElementById('dnsRecordType');
    RECORD_TYPES.forEach(t => {
        const opt = document.createElement('option');
        opt.value = t; opt.textContent = t;
        select.appendChild(opt);
    });
}
