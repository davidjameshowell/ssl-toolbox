import { opensslCnf } from '../state.js';
import { getVaultItemById } from '../vault.js';

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

        if (['der', 'cer', 'crt'].includes(ext)) {
            const reader = new FileReader();
            reader.onload = (evt) => {
                const text = evt.target.result;
                if (text.includes('-----BEGIN CERTIFICATE-----')) {
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
            statusDiv.className = 'text-center font-medium mt-4 text-sm text-slate-500 animate-pulse';
            statusDiv.innerText = 'Converting file...';
            statusDiv.classList.remove('hidden');

            const module = await window.createOpenSSL();

            if (vaultCertId) {
                const storeItem = getVaultItemById(vaultCertId);
                if (!storeItem) throw new Error('Selected vault certificate was not found.');
                module.FS.writeFile('/input.cert', storeItem.data);
            } else {
                const certBuffer = await fileInput.files[0].arrayBuffer();
                module.FS.writeFile('/input.cert', new Uint8Array(certBuffer));
            }

            const outFilename = `converted_cert.${toType}`;
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
                if (vaultKeyId) {
                    const storeItem = getVaultItemById(vaultKeyId);
                    if (!storeItem) throw new Error('Selected vault private key was not found.');
                    module.FS.writeFile('/input.key', storeItem.data);
                } else {
                    const keyBuffer = await keyInput.files[0].arrayBuffer();
                    module.FS.writeFile('/input.key', new Uint8Array(keyBuffer));
                }

                module.FS.writeFile('/openssl.cnf', opensslCnf);
                module.ENV.OPENSSL_CONF = '/openssl.cnf';

                const informArg = fromType === 'der' ? ['-inform', 'der'] : [];
                args = ['pkcs12', '-export', '-legacy', '-out', `/${outFilename}`, '-inkey', '/input.key', '-in', '/input.cert', '-passout', `pass:${pfxPass}`].concat(informArg);
            }

            module.callMain(args);
            const outData = module.FS.readFile(`/${outFilename}`);
            const blob = new Blob([outData], { type: 'application/octet-stream' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = outFilename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);

            statusDiv.className = 'text-center font-medium mt-4 text-sm text-emerald-600';
            statusDiv.innerText = '✓ File converted and downloaded successfully.';
        } catch (err) {
            console.error(err);
            statusDiv.className = 'text-center font-medium mt-4 text-sm text-red-600';
            statusDiv.innerText = '❌ Error: Conversion failed. Ensure input files match the selected format.';
        } finally {
            btn.disabled = false;
        }
    });
}
