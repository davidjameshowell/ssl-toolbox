import { opensslCnf } from '../state.js';

async function loadCipherSuites() {
    const resultsDiv = document.getElementById('cipherResults');
    const btn = document.getElementById('cipherLoadBtn');
    btn.disabled = true;

    try {
        const module = await window.createOpenSSL();
        module.FS.writeFile('/openssl.cnf', opensslCnf);
        module.ENV.OPENSSL_CONF = '/openssl.cnf';

        let output = '';
        const origStdout = module.print;
        const lines = [];
        module.print = (text) => lines.push(text);

        try {
            module.callMain(['ciphers', '-v', 'ALL:eNULL:@SECLEVEL=0']);
        } catch {}

        module.print = origStdout;
        output = lines.join('\n');

        if (!output.trim()) {
            resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">No cipher output captured. This may be a WASM limitation.</p>';
            return;
        }

        const ciphers = output.trim().split('\n').map(line => {
            const parts = line.trim().split(/\s+/);
            return {
                name: parts[0] || '',
                protocol: parts[1] || '',
                kx: parts[2] || '',
                au: parts[3] || '',
                enc: parts[4] || '',
                mac: parts[5] || '',
            };
        }).filter(c => c.name);

        renderCipherTable(ciphers);
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ ${err.message}</p>`;
    } finally {
        btn.disabled = false;
    }
}

function renderCipherTable(ciphers) {
    const resultsDiv = document.getElementById('cipherResults');
    const search = document.getElementById('cipherSearch').value.toLowerCase();
    const filtered = search ? ciphers.filter(c => Object.values(c).some(v => v.toLowerCase().includes(search))) : ciphers;

    const weakPatterns = /RC4|MD5|DES-CBC|NULL|EXPORT|anon/i;

    const rows = filtered.map(c => {
        const isWeak = weakPatterns.test(c.name) || weakPatterns.test(c.enc) || weakPatterns.test(c.mac);
        const rowCls = isWeak ? 'bg-red-50' : '';
        const badge = isWeak ? '<span class="text-[10px] px-1.5 py-0.5 rounded bg-red-100 text-red-700 font-bold">WEAK</span>' : '';
        return `<tr class="${rowCls}"><td class="px-3 py-2 font-mono text-xs">${c.name} ${badge}</td><td class="px-3 py-2 text-xs">${c.protocol}</td><td class="px-3 py-2 text-xs">${c.kx}</td><td class="px-3 py-2 text-xs">${c.au}</td><td class="px-3 py-2 text-xs">${c.enc}</td><td class="px-3 py-2 text-xs">${c.mac}</td></tr>`;
    }).join('');

    resultsDiv.innerHTML = `
        <p class="text-xs text-slate-500 mb-3">${filtered.length} cipher suites${search ? ' matching filter' : ''}</p>
        <div class="overflow-x-auto border border-slate-200 rounded-lg">
            <table class="min-w-full text-left divide-y divide-slate-200">
                <thead class="bg-slate-100"><tr>
                    <th class="px-3 py-2 text-xs font-bold text-slate-600 uppercase">Name</th>
                    <th class="px-3 py-2 text-xs font-bold text-slate-600 uppercase">Protocol</th>
                    <th class="px-3 py-2 text-xs font-bold text-slate-600 uppercase">Kx</th>
                    <th class="px-3 py-2 text-xs font-bold text-slate-600 uppercase">Au</th>
                    <th class="px-3 py-2 text-xs font-bold text-slate-600 uppercase">Enc</th>
                    <th class="px-3 py-2 text-xs font-bold text-slate-600 uppercase">Mac</th>
                </tr></thead>
                <tbody class="divide-y divide-slate-100">${rows}</tbody>
            </table>
        </div>`;

    window._cipherData = ciphers;
}

export function initCiphersTool() {
    document.getElementById('cipherLoadBtn').addEventListener('click', loadCipherSuites);
    document.getElementById('cipherSearch').addEventListener('input', () => {
        if (window._cipherData) renderCipherTable(window._cipherData);
    });
}
