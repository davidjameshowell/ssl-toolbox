export const opensslCnf = `
openssl_conf = openssl_init
[openssl_init]
providers = provider_sect
[provider_sect]
default = default_sect
legacy = legacy_sect
[default_sect]
activate = 1
[legacy_sect]
activate = 1
`;

// Vault: hydrate from sessionStorage so items survive page navigation.
function _loadVault() {
    try {
        const raw = sessionStorage.getItem('__vault');
        return raw ? JSON.parse(raw) : [];
    } catch { return []; }
}
export const vaultStore = _loadVault();

export function persistVault() {
    try { sessionStorage.setItem('__vault', JSON.stringify(vaultStore)); } catch {}
}

export const appState = {
    extractedCertPem: null,
    extractedKeyPem: null,
};
