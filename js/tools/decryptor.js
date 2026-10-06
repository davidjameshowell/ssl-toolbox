import { decryptPrivateKey, inspectKeyInfo, isEncryptedKey, summarizeKeyInfo } from '../utils/decrypt.js';
import { downloadFile } from '../utils/download.js';
import { saveToVault } from '../vault.js';

export function initDecryptorTool() {
    const inputArea = document.getElementById('decryptorInput');
    const passInput = document.getElementById('decryptorPass');
    const fileInput = document.getElementById('decryptFile');
    const formatSelect = document.getElementById('decryptFormat');
    const decryptBtn = document.getElementById('decryptBtn');
    const outputArea = document.getElementById('decryptOutput');
    const statusDiv = document.getElementById('decryptStatus');
    const infoDiv = document.getElementById('decryptInfo');
    const copyBtn = document.getElementById('decryptCopy');
    const downloadBtn = document.getElementById('decryptDownload');
    const saveBtn = document.getElementById('decryptSaveVault');
    if (!inputArea || !decryptBtn || !outputArea) return;

    const setStatus = (kind, msg) => {
        if (!statusDiv) return;
        statusDiv.classList.remove('hidden');
        if (kind === 'ok') statusDiv.className = 'status-ok';
        else if (kind === 'warn') statusDiv.className = 'status-warn';
        else if (kind === 'error') statusDiv.className = 'status-error';
        else statusDiv.className = 'status-busy';
        statusDiv.innerText = msg;
    };

    const setSaveState = (state) => {
        if (!saveBtn) return;
        if (state === 'saved') {
            saveBtn.disabled = true;
            saveBtn.dataset.origLabel = saveBtn.dataset.origLabel || saveBtn.textContent;
            saveBtn.textContent = 'Saved to Vault';
        } else {
            saveBtn.disabled = false;
            if (saveBtn.dataset.origLabel) saveBtn.textContent = saveBtn.dataset.origLabel;
        }
    };

    if (fileInput) {
        fileInput.addEventListener('change', () => {
            const file = fileInput.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (evt) => {
                inputArea.value = String(evt.target.result || '');
                document.getElementById('decryptorVaultSelect').value = '';
                setSaveState('idle');
            };
            reader.readAsText(file);
        });
    }
    inputArea.addEventListener('input', () => setSaveState('idle'));

    decryptBtn.addEventListener('click', async () => {
        const pemText = (inputArea.value || '').trim();
        const password = passInput ? passInput.value : '';
        const format = formatSelect ? formatSelect.value : 'auto';

        if (!pemText) {
            setStatus('warn', 'Paste an encrypted key, load one from the Vault, or upload a file first.');
            return;
        }

        decryptBtn.disabled = true;
        const originalLabel = decryptBtn.innerHTML;
        decryptBtn.innerHTML = 'Unlocking…';
        outputArea.value = '';
        if (infoDiv) infoDiv.classList.add('hidden');
        setSaveState('idle');
        setStatus('busy', 'Unlocking key…');

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
            if (isEncryptedKey(pemText)) {
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
                setStatus('ok', 'Copied to clipboard.');
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
            setSaveState('saved');
        });
    }
}
