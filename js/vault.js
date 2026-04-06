import { vaultStore } from './state.js';

export function saveToVault(label, type, data) {
    if (!data) return;
    if (vaultStore.some((item) => item.data === data)) return;

    const id = `vitem_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    vaultStore.push({ id, label, type, data });
    updateVaultUI();
}

export function getVaultItemById(id) {
    return vaultStore.find((item) => item.id === id) || null;
}

export function clearVault() {
    vaultStore.length = 0;
    updateVaultUI();
}

export function updateVaultUI() {
    const sidebar = document.getElementById('sidebarStoreList');
    if (!sidebar) return;

    if (vaultStore.length === 0) {
        sidebar.innerHTML = '<li class="text-slate-500 italic text-xs px-2">Vault is empty</li>';
    } else {
        sidebar.innerHTML = vaultStore.map((item) => {
            const color = item.type === 'key'
                ? 'bg-amber-900/50 text-amber-400 border-amber-800'
                : 'bg-blue-900/50 text-blue-400 border-blue-800';
            return `
                <li class="flex items-center justify-between text-slate-300 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-xs shadow-sm">
                    <span class="truncate pr-2 font-medium" title="${item.label}">${item.label}</span>
                    <span class="text-[10px] px-1.5 py-0.5 rounded border uppercase tracking-wider font-bold ${color}">${item.type}</span>
                </li>`;
        }).join('');
    }

    const dropdowns = ['decoderVaultSelect', 'match1VaultSelect', 'match2VaultSelect', 'convCertVaultSelect', 'convKeyVaultSelect'];
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

export function initVaultBindings() {
    document.getElementById('vaultClearBtn').addEventListener('click', () => {
        clearVault();
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
                const content = evt.target.result;
                const type = content.includes('PRIVATE KEY') ? 'key' : 'cert';
                const label = file.name.replace(/\.[^.]+$/, '');
                saveToVault(label, type, content);
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
