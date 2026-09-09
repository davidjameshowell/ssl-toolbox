import { opensslCnf } from '../state.js';
import { decryptPrivateKey, inspectKeyInfo, isEncryptedKey, summarizeKeyInfo } from '../utils/decrypt.js';
import { downloadFile } from '../utils/download.js';
import { saveToVault } from '../vault.js';

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

function initDecryptSection() {
    const sourceSelect = document.getElementById('decryptSource');
    const fileInput = document.getElementById('decryptFile');
    const formatSelect = document.getElementById('decryptFormat');
    const decryptBtn = document.getElementById('decryptBtn');
    const outputArea = document.getElementById('decryptOutput');
    const statusDiv = document.getElementById('decryptStatus');
    const infoDiv = document.getElementById('decryptInfo');
    const copyBtn = document.getElementById('decryptCopy');
    const downloadBtn = document.getElementById('decryptDownload');
    const saveBtn = document.getElementById('decryptSaveVault');
    if (!sourceSelect || !decryptBtn || !outputArea) return;

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            const file = fileInput.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (evt) => {
                const text = String(evt.target.result || '');
                const targetId = sourceSelect.value === 'input2' ? 'matchInput2' : 'matchInput1';
                document.getElementById(targetId).value = text;
            };
            reader.readAsText(file);
        });
        sourceSelect.addEventListener('change', () => {
            fileInput.value = '';
        });
    }

    const setStatus = (kind, msg) => {
        if (!statusDiv) return;
        statusDiv.classList.remove('hidden');
        if (kind === 'ok') statusDiv.className = 'status-ok';
        else if (kind === 'warn') statusDiv.className = 'status-warn';
        else if (kind === 'error') statusDiv.className = 'status-error';
        else statusDiv.className = 'status-busy';
        statusDiv.innerText = msg;
    };

    decryptBtn.addEventListener('click', async () => {
        const targetId = sourceSelect.value === 'input2' ? 'matchInput2' : 'matchInput1';
        const pemText = (document.getElementById(targetId).value || '').trim();
        const password = document.getElementById('matchPass').value;
        const format = formatSelect ? formatSelect.value : 'auto';

        if (!pemText) {
            alert('Select a key source first (paste, load from Vault, or upload a file).');
            return;
        }

        decryptBtn.disabled = true;
        const originalLabel = decryptBtn.innerHTML;
        decryptBtn.innerHTML = 'Unlocking...';
        outputArea.value = '';
        if (infoDiv) infoDiv.classList.add('hidden');
        setStatus('busy', 'Unlocking key...');

        try {
            if (pemText.includes('OPENSSH PRIVATE KEY')) {
                throw new Error('OpenSSH key format is not supported. Convert with `ssh-keygen -p -m PEM -f <key>` first.');
            }
            if (!pemText.includes('PRIVATE KEY')) {
                throw new Error('Not a private key. Expected a PEM block containing "PRIVATE KEY".');
            }
            if (!isEncryptedKey(pemText)) {
                setStatus('warn', 'Note: key does not look encrypted — output will be a (re-encoded) copy.');
            }
            const decrypted = await decryptPrivateKey(pemText, password, { format });
            outputArea.value = decrypted;
            if (!isEncryptedKey(pemText)) {
                // keep warn note visible alongside output
            } else {
                setStatus('ok', 'Key unlocked successfully. Password was only used inside WASM memory.');
            }
            try {
                const info = await inspectKeyInfo(pemText, { password });
                const outLabel = format !== 'auto'
                    ? format
                    : (/BEGIN (RSA|EC) PRIVATE KEY/.test(decrypted) ? 'traditional' : 'pkcs8');
                if (infoDiv) {
                    infoDiv.textContent = summarizeKeyInfo(info, outLabel);
                    infoDiv.classList.remove('hidden');
                }
            } catch (infoErr) {
                // inspection is informational only — never fail the unlock
            }
        } catch (err) {
            setStatus('error', err.message);
        } finally {
            decryptBtn.disabled = false;
            decryptBtn.innerHTML = originalLabel;
        }
    });

    if (copyBtn) {
        copyBtn.addEventListener('click', async () => {
            if (!outputArea.value) return;
            try {
                await navigator.clipboard.writeText(outputArea.value);
                setStatus('ok', '✓ Copied to clipboard.');
            } catch (err) {
                outputArea.select();
                document.execCommand('copy');
            }
        });
    }
    if (downloadBtn) {
        downloadBtn.addEventListener('click', () => {
            if (!outputArea.value) return;
            downloadFile(outputArea.value, 'decrypted-key.pem');
        });
    }
    if (saveBtn) {
        saveBtn.addEventListener('click', () => {
            if (!outputArea.value) return;
            saveToVault('decrypted-key', 'key', outputArea.value);
        });
    }
}

export function initMatcherTool() {
    initDecryptSection();
    document.getElementById('compareBtn').addEventListener('click', async () => {
        const input1 = document.getElementById('matchInput1').value.trim();
        const input2 = document.getElementById('matchInput2').value.trim();
        const pwd = document.getElementById('matchPass').value;
        const btn = document.getElementById('compareBtn');
        const resultBox = document.getElementById('matchResult');

        if (!input1 || !input2) {
            alert('Please provide PEM data for both Input 1 and Input 2.');
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
