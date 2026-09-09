import { opensslCnf } from '../state.js';

export function detectPemType(pem) {
    if (pem.includes('BEGIN CERTIFICATE REQUEST')) return 'req';
    if (pem.includes('BEGIN CERTIFICATE')) return 'x509';
    if (pem.includes('PRIVATE KEY')) return 'pkey';
    return null;
}

function resolveFactory(explicitFactory) {
    if (explicitFactory) return explicitFactory;
    if (typeof window !== 'undefined' && typeof window.createOpenSSL !== 'undefined') {
        return window.createOpenSSL;
    }
    throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
}

export async function extractPublicKey(pemText, password, inputName, explicitFactory = null) {
    const type = detectPemType(pemText);
    if (!type) {
        throw new Error(`${inputName}: Could not detect PEM type. Please ensure it is a valid Cert, CSR, or Private Key.`);
    }

    const factory = resolveFactory(explicitFactory);
    const module = await factory();
    module.FS.writeFile('/input.pem', pemText);
    module.FS.writeFile('/openssl.cnf', opensslCnf);
    module.ENV.OPENSSL_CONF = '/openssl.cnf';

    let args = [];
    if (type === 'x509') {
        args = ['x509', '-in', '/input.pem', '-pubkey', '-noout', '-out', '/out.pub'];
    } else if (type === 'req') {
        args = ['req', '-in', '/input.pem', '-pubkey', '-noout', '-out', '/out.pub', '-config', '/openssl.cnf'];
    } else if (type === 'pkey') {
        args = ['pkey', '-in', '/input.pem', '-pubout', '-out', '/out.pub'];
        if (password && password.trim() !== '') {
            module.FS.writeFile('/pass.txt', password);
            args.push('-passin', 'file:/pass.txt');
        }
    }

    try {
        module.callMain(args);
        const out = module.FS.readFile('/out.pub', { encoding: 'utf8' }).trim();
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        return out;
    } catch (err) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        if (type === 'pkey') {
            throw new Error(`${inputName}: Failed to read Private Key. If it is encrypted, ensure the password is correct.`);
        }
        throw new Error(`${inputName}: OpenSSL failed to parse the file.`);
    }
}

export function initMatcherTool() {
    document.getElementById('compareBtn').addEventListener('click', async () => {
        const input1 = document.getElementById('matchInput1').value.trim();
        const input2 = document.getElementById('matchInput2').value.trim();
        const pwd = document.getElementById('matchPass').value;
        const btn = document.getElementById('compareBtn');
        const resultBox = document.getElementById('matchResult');

        if (!input1 || !input2) {
            resultBox.className = 'result-error';
            resultBox.innerHTML = `
                <div>
                    <h4 class="font-bold">Missing input</h4>
                    <p class="text-sm opacity-90">Paste a certificate, key, or CSR into both Input 1 and Input 2 — or load them from the Vault.</p>
                </div>
            `;
            resultBox.classList.remove('hidden');
            return;
        }

        btn.disabled = true;
        btn.innerHTML = '<svg class="animate-spin h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24"><circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle><path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path></svg> Comparing...';
        resultBox.classList.add('hidden');

        try {
            const pubKey1 = await extractPublicKey(input1, pwd, 'Input 1');
            const pubKey2 = await extractPublicKey(input2, pwd, 'Input 2');

            if (pubKey1 === pubKey2 && pubKey1.length > 0) {
                resultBox.className = 'result-ok';
                resultBox.innerHTML = `
                    <div class="bg-emerald-100 dark:bg-emerald-500/15 p-2 rounded-full shrink-0"><svg class="w-6 h-6 text-emerald-600 dark:text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" /></svg></div>
                    <div>
                        <h4 class="font-bold">Match confirmed</h4>
                        <p class="text-sm opacity-90">The public keys for both items are identical. They belong to the same cryptographic pair.</p>
                    </div>
                `;
            } else {
                resultBox.className = 'result-mismatch';
                resultBox.innerHTML = `
                    <div class="bg-rose-100 dark:bg-rose-500/15 p-2 rounded-full shrink-0"><svg class="w-6 h-6 text-rose-600 dark:text-rose-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" /></svg></div>
                    <div>
                        <h4 class="font-bold">Keys do not match</h4>
                        <p class="text-sm opacity-90">The underlying public keys for these two items are different.</p>
                    </div>
                `;
            }
            resultBox.classList.remove('hidden');
        } catch (err) {
            resultBox.className = 'result-error';
            resultBox.innerHTML = `
                <div class="bg-amber-100 dark:bg-amber-500/15 p-2 rounded-full shrink-0"><svg class="w-6 h-6 text-amber-600 dark:text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg></div>
                <div>
                    <h4 class="font-bold">Extraction error</h4>
                    <p class="text-sm opacity-90">${err.message}</p>
                    </div>
            `;
            resultBox.classList.remove('hidden');
        } finally {
            btn.disabled = false;
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> Compare Inputs';
        }
    });
}
