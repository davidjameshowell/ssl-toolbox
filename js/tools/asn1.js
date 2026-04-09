import { opensslCnf } from '../state.js';

async function parseASN1(input, isDer) {
    const resultsDiv = document.getElementById('asn1Results');
    try {
        const module = await window.createOpenSSL();
        module.FS.writeFile('/openssl.cnf', opensslCnf);
        module.ENV.OPENSSL_CONF = '/openssl.cnf';

        if (isDer) {
            module.FS.writeFile('/input.der', input);
            module.callMain(['asn1parse', '-inform', 'DER', '-in', '/input.der', '-out', '/parsed.txt']);
        } else {
            module.FS.writeFile('/input.pem', input);
            module.callMain(['asn1parse', '-in', '/input.pem', '-out', '/parsed.txt']);
        }

        let stdout = '';
        try { stdout = module.FS.readFile('/parsed.txt', { encoding: 'utf8' }); } catch {}

        if (!stdout) {
            const captured = [];
            const module2 = await window.createOpenSSL();
            module2.FS.writeFile('/openssl.cnf', opensslCnf);
            module2.ENV.OPENSSL_CONF = '/openssl.cnf';

            if (isDer) {
                module2.FS.writeFile('/input.der', input);
                module2.callMain(['asn1parse', '-inform', 'DER', '-in', '/input.der']);
            } else {
                module2.FS.writeFile('/input.pem', input);
                module2.callMain(['asn1parse', '-in', '/input.pem']);
            }
            stdout = '(ASN.1 output sent to stdout — check console)';
        }

        resultsDiv.innerHTML = `
            <pre class="bg-slate-800 text-emerald-400 rounded-lg p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-words max-h-[600px] overflow-y-auto">${stdout.replace(/</g, '&lt;')}</pre>`;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ Failed to parse ASN.1: ${err.message || 'Invalid input.'}</p>`;
    }
}

export function initAsn1Tool() {
    document.getElementById('asn1ParseBtn').addEventListener('click', () => {
        const input = document.getElementById('asn1Input').value.trim();
        if (input) parseASN1(input, false);
    });

    document.getElementById('asn1File').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);

        const text = new TextDecoder().decode(bytes);
        if (text.includes('-----BEGIN')) {
            parseASN1(text, false);
        } else {
            parseASN1(bytes, true);
        }
    });
}
