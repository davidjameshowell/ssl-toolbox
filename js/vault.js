import { vaultStore } from './state.js';
import { downloadFile } from './utils/download.js';
import { switchTab } from './navigation.js';

/** Classify uploaded/pasted PEM content for vault storage. */
export function detectVaultType(content) {
    if (!content || typeof content !== 'string') return 'cert';
    if (content.includes('PRIVATE KEY')) return 'key';
    if (content.includes('CERTIFICATE REQUEST')) return 'csr';
    return 'cert';
}

/** Where a vault item opens: certs/CSRs decode, keys go to the matcher. */
export function vaultItemTarget(type) {
    if (type === 'key') return { tab: 'matcherTab', textareaId: 'matchInput1' };
    return { tab: 'decoderTab', textareaId: 'pemInput' };
}

export function saveToVault(label, type, data) {
    if (!data) return false;
    if (vaultStore.some((item) => item.data === data)) return false;

    const id = `vitem_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    vaultStore.push({ id, label, type, data });
    updateVaultUI();
    return true;
}

export function getVaultItemById(id) {
    return vaultStore.find((item) => item.id === id) || null;
}

export function removeFromVault(id) {
    const idx = vaultStore.findIndex((item) => item.id === id);
    if (idx === -1) return false;
    vaultStore.splice(idx, 1);
    updateVaultUI();
    return true;
}

export function clearVault() {
    vaultStore.length = 0;
    updateVaultUI();
}

export function openVaultItem(id) {
    const item = getVaultItemById(id);
    if (!item || typeof document === 'undefined') return false;
    const { tab, textareaId } = vaultItemTarget(item.type);
    const textarea = document.getElementById(textareaId);
    if (!textarea) return false;
    textarea.value = item.data;
    textarea.dispatchEvent(new Event('input'));
    switchTab(tab);
    return true;
}

export function updateVaultUI() {
    if (typeof document === 'undefined') return;
    const sidebar = document.getElementById('sidebarStoreList');
    if (!sidebar) return;

    if (vaultStore.length === 0) {
        sidebar.innerHTML = '<li class="vault-empty">Vault is empty</li>';
    } else {
        sidebar.innerHTML = vaultStore.map((item) => {
            const badge = item.type === 'key' ? 'badge-key' : item.type === 'csr' ? 'badge-csr' : 'badge-cert';
            return `
                <li class="vault-row" data-vault-id="${item.id}">
                    <div class="flex items-center justify-between gap-2">
                        <button data-action="open" title="Open in tool" class="vault-label">${item.label}</button>
                        <span class="${badge} shrink-0">${item.type}</span>
                    </div>
                    <div class="flex items-center gap-1.5 mt-1.5">
                        <button data-action="download" title="Download .pem" class="vault-dl">Download</button>
                        <button data-action="delete" title="Remove from vault" class="vault-rm">Remove</button>
                    </div>
                </li>`;
        }).join('');
    }

    const dropdowns = ['decoderVaultSelect', 'match1VaultSelect', 'match2VaultSelect', 'decryptorVaultSelect', 'convCertVaultSelect', 'convKeyVaultSelect'];
    dropdowns.forEach((id) => {
        const select = document.getElementById(id);
        if (!select) return;

        const currentVal = select.value;
        const defaultText = select.options[0].text;
        select.innerHTML = `<option value="">${defaultText}</option>`
            + vaultStore.map((item) => `<option value="${item.id}">${item.label} (${item.type.toUpperCase()})</option>`).join('');

        if (vaultStore.some((item) => item.id === currentVal)) {
            select.value = currentVal;
        }
    });
}

function vaultNote(msg) {
    if (typeof document === 'undefined') return;
    const note = document.getElementById('vaultNote');
    if (!note) return;
    note.textContent = msg;
    note.classList.remove('hidden');
    clearTimeout(vaultNote._t);
    vaultNote._t = setTimeout(() => note.classList.add('hidden'), 4000);
}

export function initVaultBindings() {
    const clearBtn = document.getElementById('vaultClearBtn');
    let clearArmed = false;
    let clearTimer = null;
    const disarmClear = () => {
        clearArmed = false;
        clearBtn.textContent = 'Clear';
        clearTimeout(clearTimer);
    };
    clearBtn.addEventListener('click', () => {
        if (vaultStore.length === 0) return;
        if (!clearArmed) {
            clearArmed = true;
            clearBtn.textContent = 'Sure?';
            clearTimer = setTimeout(disarmClear, 3000);
            return;
        }
        disarmClear();
        clearVault();
    });

    // Sidebar rows re-render on every vault change — delegate from the list.
    document.getElementById('sidebarStoreList').addEventListener('click', (e) => {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        const row = e.target.closest('[data-vault-id]');
        if (!row) return;
        const id = row.getAttribute('data-vault-id');
        const action = btn.getAttribute('data-action');
        if (action === 'open') {
            openVaultItem(id);
        } else if (action === 'download') {
            const item = getVaultItemById(id);
            if (item) downloadFile(item.data, `${item.label}.pem`);
        } else if (action === 'delete') {
            removeFromVault(id);
        }
    });

    const vaultUploadBtn = document.getElementById('vaultUploadBtn');
    const vaultUploadInput = document.getElementById('vaultUploadInput');
    vaultUploadBtn.addEventListener('click', () => {
        vaultUploadInput.click();
    });
    vaultUploadInput.addEventListener('change', (e) => {
        const files = Array.from(e.target.files || []);
        files.forEach((file) => {
            const reader = new FileReader();
            reader.onload = (evt) => {
                const content = String(evt.target.result || '');
                if (!content.includes('BEGIN ')) {
                    vaultNote(`Skipped ${file.name}: not a PEM file.`);
                    return;
                }
                const label = file.name.replace(/\.[^.]+$/, '');
                saveToVault(label, detectVaultType(content), content);
            };
            reader.readAsText(file);
        });
        e.target.value = '';
    });

    const decoderVaultSelect = document.getElementById('decoderVaultSelect');
    decoderVaultSelect.addEventListener('change', (e) => {
        if (!e.target.value) return;
        const item = getVaultItemById(e.target.value);
        if (!item) return;

        const textarea = document.getElementById('pemInput');
        textarea.value = item.data;
        textarea.dispatchEvent(new Event('input'));
        e.target.value = '';
    });

    ['match1VaultSelect', 'match2VaultSelect'].forEach((id, index) => {
        const select = document.getElementById(id);
        select.addEventListener('change', (e) => {
            if (!e.target.value) return;
            const item = getVaultItemById(e.target.value);
            if (!item) return;

            document.getElementById(`matchInput${index + 1}`).value = item.data;
            e.target.value = '';
        });
    });

    const decryptorVaultSelect = document.getElementById('decryptorVaultSelect');
    const decryptFile = document.getElementById('decryptFile');
    if (decryptorVaultSelect) {
        decryptorVaultSelect.addEventListener('change', (e) => {
            if (!e.target.value) return;
            const item = getVaultItemById(e.target.value);
            if (!item) return;

            document.getElementById('decryptorInput').value = item.data;
            if (decryptFile) decryptFile.value = '';
            e.target.value = '';
        });
    }

    document.getElementById('convCertVaultSelect').addEventListener('change', (e) => {
        if (e.target.value) {
            document.getElementById('convFile').value = '';
        }
    });

    document.getElementById('convKeyVaultSelect').addEventListener('change', (e) => {
        if (e.target.value) {
            document.getElementById('convKeyFile').value = '';
        }
    });

    document.getElementById('convFile').addEventListener('change', () => {
        document.getElementById('convCertVaultSelect').value = '';
    });

    document.getElementById('convKeyFile').addEventListener('change', () => {
        document.getElementById('convKeyVaultSelect').value = '';
    });
}
