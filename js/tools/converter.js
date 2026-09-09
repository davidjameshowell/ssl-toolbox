import { opensslCnf } from '../state.js';
import { getVaultItemById } from '../vault.js';

function resolveConverterFactory(explicitFactory) {
    if (explicitFactory) return explicitFactory;
    if (typeof window !== 'undefined' && typeof window.createOpenSSL !== 'undefined') {
        return window.createOpenSSL;
    }
    throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
}

export async function runConversion({ certBytes, keyBytes = null, fromType, toType, pfxPass = '', keyPass = '' }, explicitFactory = null) {
    if (fromType === toType) {
        throw new Error('The current format and target format are the same.');
    }
    const factory = resolveConverterFactory(explicitFactory);
    const module = await factory();

    const certData = typeof certBytes === 'string' ? certBytes : new Uint8Array(certBytes);
    module.FS.writeFile('/input.cert', certData);

    const outFilename = `converted_cert.${toType}`;

    // P7B containers may be PEM- or DER-encoded — try PEM first, fall back to DER.
    // Each attempt gets a fresh WASM instance: a failed callMain can leave the
    // module's OpenSSL state poisoned for subsequent invocations.
    if (fromType === 'p7b' && toType === 'pem') {
        const informs = ['pem', 'der'];
        for (const inform of informs) {
            const attempt = await factory();
            attempt.FS.writeFile('/input.cert', certData);
            try {
                attempt.callMain(['pkcs7', '-inform', inform, '-in', '/input.cert', '-print_certs', '-out', `/${outFilename}`]);
                const outData = attempt.FS.readFile(`/${outFilename}`);
                if (typeof process !== 'undefined' && process) process.exitCode = 0;
                return { outData, outFilename };
            } catch (err) {
                if (typeof process !== 'undefined' && process) process.exitCode = 0;
            }
        }
        // callMain does not always throw on OpenSSL failure (EXIT_RUNTIME=0),
        // so also cover the case where neither attempt produced output.
        throw new Error('Could not unpack P7B: input is neither PEM- nor DER-encoded PKCS#7.');
    }
    if (fromType === 'p7b') {
        throw new Error(`Unsupported conversion: ${fromType} -> ${toType}. P7B containers can only be unpacked to PEM.`);
    }

    let args = [];

    if (fromType === 'pem' && toType === 'der') {
        args = ['x509', '-outform', 'der', '-in', '/input.cert', '-out', `/${outFilename}`];
    } else if (fromType === 'der' && toType === 'pem') {
        args = ['x509', '-inform', 'der', '-in', '/input.cert', '-out', `/${outFilename}`];
    } else if (fromType === 'pem' && toType === 'p7b') {
        args = ['crl2pkcs7', '-nocrl', '-certfile', '/input.cert', '-out', `/${outFilename}`];
    } else if (fromType === 'der' && toType === 'p7b') {
        module.callMain(['x509', '-inform', 'der', '-in', '/input.cert', '-out', '/temp.pem']);
        args = ['crl2pkcs7', '-nocrl', '-certfile', '/temp.pem', '-out', `/${outFilename}`];
    } else if (toType === 'pfx') {
        if (!keyBytes) throw new Error('A private key is required to create a PFX/PKCS#12 file.');
        const keyData = typeof keyBytes === 'string' ? keyBytes : new Uint8Array(keyBytes);
        module.FS.writeFile('/input.key', keyData);
        module.FS.writeFile('/openssl.cnf', opensslCnf);
        module.ENV.OPENSSL_CONF = '/openssl.cnf';
        let passoutArgs;
        if (pfxPass && pfxPass !== '') {
            module.FS.writeFile('/passout.txt', pfxPass);
            passoutArgs = ['-passout', 'file:/passout.txt'];
        } else {
            passoutArgs = ['-passout', 'pass:'];
        }
        let passinArgs = [];
        if (keyPass && keyPass !== '') {
            module.FS.writeFile('/keypass.txt', keyPass);
            passinArgs = ['-passin', 'file:/keypass.txt'];
        }
        const informArg = fromType === 'der' ? ['-inform', 'der'] : [];
        args = ['pkcs12', '-export', '-legacy', '-out', `/${outFilename}`, '-inkey', '/input.key', '-in', '/input.cert', ...passoutArgs, ...passinArgs].concat(informArg);
    } else {
        throw new Error(`Unsupported conversion: ${fromType} -> ${toType}`);
    }

    try {
        module.callMain(args);
        const out = { outData: module.FS.readFile(`/${outFilename}`), outFilename };
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        return out;
    } catch (err) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw err;
    }
}

export function initConverterTool() {
    document.getElementById('convToType').addEventListener('change', (e) => {
        const keyGroup = document.getElementById('convKeyGroup');
        if (e.target.value === 'pfx') {
            keyGroup.classList.remove('hidden');
        } else {
            keyGroup.classList.add('hidden');
        }
    });

    document.getElementById('convFile').addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;

        const ext = file.name.split('.').pop().toLowerCase();
        const fromSelect = document.getElementById('convFromType');

        if (['der', 'cer', 'crt', 'p7b', 'p7c'].includes(ext)) {
            const reader = new FileReader();
            reader.onload = (evt) => {
                const text = evt.target.result;
                if (text.includes('-----BEGIN PKCS7-----')) {
                    fromSelect.value = 'p7b';
                } else if (text.includes('-----BEGIN CERTIFICATE-----')) {
                    fromSelect.value = 'pem';
                } else {
                    fromSelect.value = 'der';
                }
            };
            reader.readAsText(file.slice(0, 100));
        } else if (ext === 'pem') {
            fromSelect.value = 'pem';
        }
    });

    document.getElementById('convertBtn').addEventListener('click', async () => {
        const fileInput = document.getElementById('convFile');
        const keyInput = document.getElementById('convKeyFile');
        const vaultCertId = document.getElementById('convCertVaultSelect').value;
        const vaultKeyId = document.getElementById('convKeyVaultSelect').value;

        const fromType = document.getElementById('convFromType').value;
        const toType = document.getElementById('convToType').value;
        const pfxPass = document.getElementById('convPass').value;
        const keyPassEl = document.getElementById('convKeyPass');
        const keyPass = keyPassEl ? keyPassEl.value : '';
        const btn = document.getElementById('convertBtn');
        const statusDiv = document.getElementById('convStatus');

        const hasCert = fileInput.files.length > 0 || vaultCertId;
        if (!hasCert) {
            alert('Please select a certificate source (Vault or File).');
            return;
        }

        if (toType === 'pfx' && keyInput.files.length === 0 && !vaultKeyId) {
            alert('A private key is required to create a PFX/PKCS#12 file.');
            return;
        }

        if (fromType === toType) {
            alert('The current format and target format are the same.');
            return;
        }

        try {
            btn.disabled = true;
            statusDiv.className = 'status-busy';
            statusDiv.innerText = 'Converting file…';
            statusDiv.classList.remove('hidden');

            let certBytes;
            if (vaultCertId) {
                const storeItem = getVaultItemById(vaultCertId);
                if (!storeItem) throw new Error('Selected vault certificate was not found.');
                certBytes = storeItem.data;
            } else {
                certBytes = new Uint8Array(await fileInput.files[0].arrayBuffer());
            }

            let keyBytes = null;
            if (toType === 'pfx') {
                if (vaultKeyId) {
                    const storeItem = getVaultItemById(vaultKeyId);
                    if (!storeItem) throw new Error('Selected vault private key was not found.');
                    keyBytes = storeItem.data;
                } else {
                    keyBytes = new Uint8Array(await keyInput.files[0].arrayBuffer());
                }
            }

            const { outData, outFilename } = await runConversion({ certBytes, keyBytes, fromType, toType, pfxPass, keyPass });
            const blob = new Blob([outData], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = outFilename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            statusDiv.className = 'status-ok';
            statusDiv.innerText = 'File converted and downloaded successfully.';
        } catch (err) {
            console.error(err);
            statusDiv.className = 'status-error';
            statusDiv.innerText = toType === 'pfx'
                ? 'Error: conversion failed. Ensure input files match the selected format — if the private key is encrypted, enter its password above.'
                : 'Error: conversion failed. Ensure input files match the selected format.';
        } finally {
            btn.disabled = false;
        }
    });
}
