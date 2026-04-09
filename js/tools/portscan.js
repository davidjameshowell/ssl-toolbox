import { apiFetch } from '../utils/api.js';

const COMMON_PRESETS = {
    web: [80, 443, 8080, 8443],
    mail: [25, 110, 143, 465, 587, 993, 995],
    database: [3306, 5432, 1433, 27017, 6379],
    remote: [22, 23, 3389, 5900],
};

async function scanPorts() {
    const host = document.getElementById('portscanHost').value.trim();
    const portsInput = document.getElementById('portscanPorts').value.trim();
    const resultsDiv = document.getElementById('portscanResults');
    const btn = document.getElementById('portscanBtn');

    if (!host) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter a hostname or IP.</p>'; return; }

    const ports = portsInput.split(',').map(p => parseInt(p.trim())).filter(p => p > 0 && p <= 65535);
    if (ports.length === 0) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter at least one valid port.</p>'; return; }
    if (ports.length > 20) { resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Maximum 20 ports per scan.</p>'; return; }

    btn.disabled = true;
    resultsDiv.innerHTML = '<p class="text-slate-500 text-sm animate-pulse">Scanning ports...</p>';

    try {
        const data = await apiFetch(`/api/portscan?host=${encodeURIComponent(host)}&ports=${ports.join(',')}`, { timeout: 60000 });

        const SERVICE_NAMES = { 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 465: 'SMTPS', 587: 'Submission', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 27017: 'MongoDB' };

        const rows = (data.results || []).map(r => {
            const statusCls = r.open ? 'bg-emerald-50 text-emerald-700' : 'bg-red-50 text-red-700';
            const statusText = r.open ? 'Open' : 'Closed';
            return `<tr class="${statusCls}"><td class="px-3 py-2 text-xs font-mono">${r.port}</td><td class="px-3 py-2 text-xs">${SERVICE_NAMES[r.port] || '-'}</td><td class="px-3 py-2 text-xs font-semibold">${statusText}</td><td class="px-3 py-2 text-xs font-mono">${escapeHtml(r.banner || '')}</td></tr>`;
        }).join('');

        const openCount = (data.results || []).filter(r => r.open).length;

        resultsDiv.innerHTML = `
            <p class="text-xs text-slate-500 mb-3">${openCount} open of ${(data.results || []).length} ports scanned on ${escapeHtml(host)}</p>
            <div class="overflow-x-auto border border-slate-200 rounded-lg">
                <table class="min-w-full text-left divide-y divide-slate-200">
                    <thead class="bg-slate-100"><tr>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Port</th>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Service</th>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Status</th>
                        <th class="px-3 py-2 text-xs font-bold text-slate-600">Banner</th>
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

export function initPortscanTool() {
    document.getElementById('portscanBtn').addEventListener('click', scanPorts);

    document.getElementById('portscanPreset').addEventListener('change', (e) => {
        const preset = COMMON_PRESETS[e.target.value];
        if (preset) {
            document.getElementById('portscanPorts').value = preset.join(', ');
        }
    });
}
