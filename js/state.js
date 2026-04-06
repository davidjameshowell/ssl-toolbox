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

export const vaultStore = [];

export const appState = {
    extractedCertPem: null,
    extractedKeyPem: null,
};
