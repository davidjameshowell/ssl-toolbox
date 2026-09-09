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

const FORMAT_LABELS = { pem: 'PEM', der: 'DER', p7b: 'P7B' };

export function detectSourceFormat(sample) {
    const text = String(sample || '');
    if (text.includes('-----BEGIN PKCS7-----')) return 'p7b';
    if (text.includes('-----BEGIN CERTIFICATE-----')) return 'pem';
    return 'der';
}

/**
 * Pure validation for the converter form. Returns {ok, hint}; hint is the
 * human-readable reason the Convert button is disabled ('' when ready).
 */
export function validateConversionState({ hasCert, hasKey, fromType, toType }) {
    if (!hasCert) return { ok: false, hint: 'Select a certificate above to continue.' };
    if (fromType === toType) return { ok: false, hint: 'Pick two different formats to convert between.' };
    if (fromType === 'p7b' && toType !== 'pem') return { ok: false, hint: 'P7B containers can only be unpacked to PEM.' };
    if (toType === 'pfx' && !hasKey) return { ok: false, hint: 'PFX output needs a private key below.' };
    return { ok: true, hint: '' };
}

export function initConverterTool() {
    const fromSelect = document.getElementById('convFromType');
    const toSelect = document.getElementById('convToType');
    const fileInput = document.getElementById('convFile');
    const keyInput = document.getElementById('convKeyFile');
    const vaultCertSelect = document.getElementById('convCertVaultSelect');
    const vaultKeySelect = document.getElementById('convKeyVaultSelect');
    const formatNote = document.getElementById('convFormatNote');
    const convertBtn = document.getElementById('convertBtn');

    const setFormatNote = (mode, value) => {
        if (!formatNote) return;
        const label = FORMAT_LABELS[value] || value;
        formatNote.textContent = mode === 'detected'
            ? `Source format detected: ${label} — change Current format to override.`
            : `Source format: ${label} (your selection).`;
    };

    const refreshValidation = () => {
        const state = validateConversionState({
            hasCert: (fileInput.files.length > 0) || !!vaultCertSelect.value,
            hasKey: (keyInput.files.length > 0) || !!vaultKeySelect.value,
            fromType: fromSelect.value,
            toType: toSelect.value,
        });
        convertBtn.disabled = !state.ok;
        if (formatNote && !state.ok && (fromSelect.value === toSelect.value || (fromSelect.value === 'p7b' && toSelect.value !== 'pem'))) {
            formatNote.textContent = state.hint;
        }
        return state;
    };

    toSelect.addEventListener('change', (e) => {
        const keyGroup = document.getElementById('convKeyGroup');
        if (e.target.value === 'pfx') {
            keyGroup.classList.remove('hidden');
        } else {
            keyGroup.classList.add('hidden');
        }
        refreshValidation();
    });
    fromSelect.addEventListener('change', () => {
        setFormatNote('manual', fromSelect.value);
        refreshValidation();
    });

    fileInput.addEventListener('change', (e) => {
        const file = e.target.files[0];
        refreshValidation();
        if (!file) return;

        const ext = file.name.split('.').pop().toLowerCase();
        if (['der', 'cer', 'crt', 'p7b', 'p7c'].includes(ext)) {
            const reader = new FileReader();
            reader.onload = (evt) => {
                fromSelect.value = detectSourceFormat(evt.target.result);
                setFormatNote('detected', fromSelect.value);
                refreshValidation();
            };
            reader.readAsText(file.slice(0, 100));
        } else if (ext === 'pem') {
            fromSelect.value = 'pem';
            setFormatNote('detected', 'pem');
            refreshValidation();
        }
    });
    keyInput.addEventListener('change', refreshValidation);

    vaultCertSelect.addEventListener('change', () => {
        if (!vaultCertSelect.value) {
            refreshValidation();
            return;
        }
        const item = getVaultItemById(vaultCertSelect.value);
        if (item && typeof item.data === 'string') {
            fromSelect.value = detectSourceFormat(item.data);
            setFormatNote('detected', fromSelect.value);
        }
        refreshValidation();
    });
    vaultKeySelect.addEventListener('change', refreshValidation);

    document.getElementById('convertBtn').addEventListener('click', async () => {
        const vaultCertId = vaultCertSelect.value;
        const vaultKeyId = vaultKeySelect.value;

        const fromType = fromSelect.value;
        const toType = toSelect.value;
        const pfxPass = document.getElementById('convPass').value;
        const keyPassEl = document.getElementById('convKeyPass');
        const keyPass = keyPassEl ? keyPassEl.value : '';
        const btn = document.getElementById('convertBtn');
        const statusDiv = document.getElementById('convStatus');

        const state = validateConversionState({
            hasCert: fileInput.files.length > 0 || !!vaultCertId,
            hasKey: keyInput.files.length > 0 || !!vaultKeyId,
            fromType,
            toType,
        });
        if (!state.ok) {
            statusDiv.className = 'status-warn';
            statusDiv.innerText = state.hint;
            statusDiv.classList.remove('hidden');
            refreshValidation();
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
            refreshValidation();
        }
    });

    setFormatNote('manual', fromSelect.value);
    refreshValidation();
}
