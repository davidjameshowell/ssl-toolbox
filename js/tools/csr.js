import { opensslCnf } from '../state.js';
import { saveToVault } from '../vault.js';
import { downloadFile } from '../utils/download.js';

async function generateCSR() {
    const status = document.getElementById('csrStatus');
    const resultsDiv = document.getElementById('csrResults');
    const btn = document.getElementById('csrGenerateBtn');

    const cn = document.getElementById('csrCN').value.trim();
    if (!cn) { status.textContent = '❌ Common Name is required.'; status.className = 'text-center font-medium mt-4 text-sm text-red-600'; status.classList.remove('hidden'); return; }

    const o = document.getElementById('csrO').value.trim();
    const ou = document.getElementById('csrOU').value.trim();
    const l = document.getElementById('csrL').value.trim();
    const st = document.getElementById('csrST').value.trim();
    const c = document.getElementById('csrC').value.trim();
    const sans = document.getElementById('csrSANs').value.trim();
    const keyType = document.getElementById('csrKeyType').value;

    const subjectParts = [];
    if (c) subjectParts.push(`/C=${c}`);
    if (st) subjectParts.push(`/ST=${st}`);
    if (l) subjectParts.push(`/L=${l}`);
    if (o) subjectParts.push(`/O=${o}`);
    if (ou) subjectParts.push(`/OU=${ou}`);
    subjectParts.push(`/CN=${cn}`);
    const subject = subjectParts.join('');

    btn.disabled = true;
    status.textContent = 'Generating key pair and CSR...';
    status.className = 'text-center font-medium mt-4 text-sm text-slate-500 animate-pulse';
    status.classList.remove('hidden');
    resultsDiv.classList.add('hidden');

    try {
        const module = await window.createOpenSSL();
        module.FS.writeFile('/openssl.cnf', opensslCnf);
        module.ENV.OPENSSL_CONF = '/openssl.cnf';

        let sanConf = '';
        if (sans) {
            const sanEntries = sans.split(',').map(s => s.trim()).filter(Boolean).map((s, i) => {
                if (/^\d+\.\d+\.\d+\.\d+$/.test(s)) return `IP.${i + 1} = ${s}`;
                return `DNS.${i + 1} = ${s}`;
            });
            sanConf = `[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\n[req_distinguished_name]\n[v3_req]\nsubjectAltName = @alt_names\n[alt_names]\n${sanEntries.join('\n')}\n`;
            module.FS.writeFile('/san.cnf', sanConf);
        }

        const args = ['req', '-new', '-nodes', '-out', '/csr.pem', '-keyout', '/key.pem', '-subj', subject];
        if (keyType.startsWith('rsa')) {
            const bits = keyType.replace('rsa', '');
            args.push('-newkey', `rsa:${bits}`);
        } else if (keyType.startsWith('ec')) {
            const curve = keyType === 'ecp256' ? 'prime256v1' : 'secp384r1';
            const keyModule = await window.createOpenSSL();
            keyModule.callMain(['ecparam', '-genkey', '-name', curve, '-noout', '-out', '/eckey.pem']);
            const ecKey = keyModule.FS.readFile('/eckey.pem', { encoding: 'utf8' });
            module.FS.writeFile('/key.pem', ecKey);
            args.push('-key', '/key.pem');
            const newkeyIdx = args.indexOf('-newkey');
            if (newkeyIdx !== -1) args.splice(newkeyIdx, 2);
        }

        if (sans) {
            args.push('-config', '/san.cnf');
        }

        module.callMain(args);

        const csrPem = module.FS.readFile('/csr.pem', { encoding: 'utf8' });
        const keyPem = module.FS.readFile('/key.pem', { encoding: 'utf8' });

        if (!csrPem || !csrPem.includes('BEGIN CERTIFICATE REQUEST')) {
            throw new Error('CSR generation failed');
        }

        document.getElementById('csrOutputCSR').textContent = csrPem.trim();
        document.getElementById('csrOutputKey').textContent = keyPem.trim();
        resultsDiv.classList.remove('hidden');

        status.textContent = '✓ CSR and private key generated successfully.';
        status.className = 'text-center font-medium mt-4 text-sm text-emerald-600';

        saveToVault(`${cn} (CSR)`, 'cert', csrPem);
        saveToVault(`${cn} (Key)`, 'key', keyPem);
    } catch (err) {
        status.textContent = `❌ Error: ${err.message || 'CSR generation failed.'}`;
        status.className = 'text-center font-medium mt-4 text-sm text-red-600';
    } finally {
        btn.disabled = false;
    }
}

async function decodeCSR() {
    const input = document.getElementById('csrDecodeInput').value.trim();
    const resultsDiv = document.getElementById('csrDecodeResults');
    if (!input) return;

    try {
        const module = await window.createOpenSSL();
        module.FS.writeFile('/input.csr', input);
        module.callMain(['req', '-in', '/input.csr', '-noout', '-text', '-out', '/decoded.txt']);
        const decoded = module.FS.readFile('/decoded.txt', { encoding: 'utf8' });

        resultsDiv.innerHTML = `<pre class="bg-slate-800 text-emerald-400 rounded-lg p-4 text-xs font-mono overflow-x-auto whitespace-pre-wrap break-words">${decoded.replace(/</g, '&lt;')}</pre>`;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ Failed to decode CSR: ${err.message || 'Invalid CSR format.'}</p>`;
    }
}

export function initCsrTool() {
    document.getElementById('csrGenerateBtn').addEventListener('click', generateCSR);
    document.getElementById('csrDecodeBtn').addEventListener('click', decodeCSR);

    document.getElementById('csrDownloadCSR').addEventListener('click', () => {
        const csr = document.getElementById('csrOutputCSR').textContent;
        if (csr) downloadFile(csr, 'request.csr');
    });
    document.getElementById('csrDownloadKey').addEventListener('click', () => {
        const key = document.getElementById('csrOutputKey').textContent;
        if (key) downloadFile(key, 'private.key');
    });
}
