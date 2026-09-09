import { opensslCnf } from '../state.js';

/**
 * Classify a PEM private key block.
 * @returns {'pkcs8-encrypted'|'pkcs8'|'traditional-rsa-encrypted'|'traditional-rsa'|'traditional-ec-encrypted'|'traditional-ec'|'openssh'|'traditional-encrypted'|null}
 */
export function detectKeyType(pem) {
    if (!pem || typeof pem !== 'string') return null;
    if (pem.includes('BEGIN OPENSSH PRIVATE KEY')) return 'openssh';
    if (pem.includes('BEGIN ENCRYPTED PRIVATE KEY')) return 'pkcs8-encrypted';
    if (pem.includes('BEGIN RSA PRIVATE KEY')) {
        if (pem.includes('Proc-Type: 4,ENCRYPTED') || pem.includes('DEK-Info:')) {
            return 'traditional-rsa-encrypted';
        }
        return 'traditional-rsa';
    }
    if (pem.includes('BEGIN EC PRIVATE KEY')) {
        if (pem.includes('Proc-Type: 4,ENCRYPTED') || pem.includes('DEK-Info:')) {
            return 'traditional-ec-encrypted';
        }
        return 'traditional-ec';
    }
    if (pem.includes('BEGIN PRIVATE KEY')) return 'pkcs8';
    if (pem.includes('PRIVATE KEY')) {
        if (pem.includes('Proc-Type: 4,ENCRYPTED') || pem.includes('DEK-Info:')) {
            return 'traditional-encrypted';
        }
        return null;
    }
    return null;
}

export function isEncryptedKey(pem) {
    const t = detectKeyType(pem);
    return t === 'pkcs8-encrypted' || t === 'traditional-rsa-encrypted' || t === 'traditional-ec-encrypted' || t === 'traditional-encrypted';
}

function resolveFactory(explicitFactory) {
    if (explicitFactory) return explicitFactory;
    if (typeof window !== 'undefined' && typeof window.createOpenSSL !== 'undefined') {
        return window.createOpenSSL;
    }
    throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
}

function familyHintFromHeaders(pem) {
    if (pem.includes('RSA PRIVATE KEY')) return 'RSA';
    if (pem.includes('EC PRIVATE KEY')) return 'EC';
    if (pem.includes('OPENSSH PRIVATE KEY')) return 'OpenSSH';
    if (pem.includes('DSA PRIVATE KEY')) return 'DSA';
    return 'Unknown';
}

/**
 * Inspect a PEM private key: family, size, curve, encryption state.
 * Encrypted keys can be identified without a password (headers only);
 * pass a password to also read size/curve from the decrypted material.
 * @returns {Promise<{family:string, bits:string|null, curve:string|null, encrypted:boolean, dekCipher:string|null}>}
 */
export async function inspectKeyInfo(pemText, options = {}) {
    const { password = '', createOpenSSL: explicitFactory = null } = options;
    if (!pemText || !pemText.includes('PRIVATE KEY')) {
        throw new Error('Not a private key. Expected a PEM block containing "PRIVATE KEY".');
    }
    const encrypted = isEncryptedKey(pemText);
    const dekMatch = pemText.match(/DEK-Info:\s*([^,\s]+)/);
    const dekCipher = dekMatch ? dekMatch[1].trim() : null;

    if (encrypted && !password) {
        return { family: familyHintFromHeaders(pemText), bits: null, curve: null, encrypted, dekCipher };
    }

    const factory = resolveFactory(explicitFactory);
    const module = await factory();
    module.FS.writeFile('/in.pem', pemText);
    module.FS.writeFile('/openssl.cnf', opensslCnf);
    module.ENV.OPENSSL_CONF = '/openssl.cnf';
    const args = ['pkey', '-in', '/in.pem', '-noout', '-text', '-out', '/keytext.txt'];
    if (password) {
        module.FS.writeFile('/pass.txt', password);
        args.push('-passin', 'file:/pass.txt');
    }
    try {
        module.callMain(args);
    } catch (err) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('Could not inspect key — wrong password or corrupted PEM.');
    }
    if (typeof process !== 'undefined' && process && process.exitCode === 1) {
        process.exitCode = 0;
        throw new Error('Could not inspect key — wrong password or corrupted PEM.');
    }
    let text = '';
    try {
        text = module.FS.readFile('/keytext.txt', { encoding: 'utf8' });
    } catch (err) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('Could not inspect key — OpenSSL produced no output.');
    }
    if (typeof process !== 'undefined' && process) process.exitCode = 0;

    let family = 'Unknown';
    if (/ED25519/i.test(text)) family = 'Ed25519';
    else if (/ED448/i.test(text)) family = 'Ed448';
    else if (/X25519/i.test(text)) family = 'X25519';
    else if (/X448/i.test(text)) family = 'X448';
    else if (/ASN1 OID:/.test(text)) family = 'EC';
    else if (/modulus:/.test(text)) family = 'RSA';
    else if (/\nP:\n|\nQ:\n/.test(text)) family = 'DSA';
    if (family === 'Unknown') family = familyHintFromHeaders(pemText);

    const bitsMatch = text.match(/Private-Key:\s*\((\d+)\s*bit/);
    const curveMatch = text.match(/ASN1 OID:\s*(\S+)/);
    return {
        family,
        bits: bitsMatch ? bitsMatch[1] : null,
        curve: curveMatch ? curveMatch[1].trim() : null,
        encrypted,
        dekCipher,
    };
}

/** One-line human summary, e.g. "RSA · 2048-bit · AES-256-CBC encrypted → PKCS#8". */
export function summarizeKeyInfo(info, outputFormat = 'auto') {
    const parts = [];
    let head = info.family || 'Unknown key';
    if (info.bits) head += ` · ${info.bits}-bit`;
    if (info.curve) head += ` (${info.curve})`;
    parts.push(head);
    if (info.encrypted) {
        parts.push(info.dekCipher ? `${info.dekCipher} encrypted` : 'encrypted');
    } else {
        parts.push('unencrypted');
    }
    if (outputFormat && outputFormat !== 'auto') {
        parts.push(`→ ${outputFormat === 'pkcs8' ? 'PKCS#8' : 'Traditional'}`);
    }
    return parts.join(' · ');
}

/**
 * Decrypt an encrypted PEM private key via WASM OpenSSL `pkey`.
 * @param {string} pemText - encrypted (or unencrypted) PEM text
 * @param {string} password - decryption password (may be empty for unencrypted keys)
 * @param {{format?: 'auto'|'pkcs8'|'traditional', createOpenSSL?: Function}} options
 * @returns {Promise<string>} decrypted PEM text
 */
export async function decryptPrivateKey(pemText, password, options = {}) {
    const { format = 'auto', createOpenSSL: explicitFactory = null } = options;

    if (!pemText || pemText.trim() === '') {
        throw new Error('No private key provided. Paste or upload an encrypted PEM key first.');
    }
    if (!pemText.includes('PRIVATE KEY')) {
        throw new Error('Not a private key. Expected a PEM block containing "PRIVATE KEY".');
    }

    const keyType = detectKeyType(pemText);
    if (keyType === 'openssh') {
        throw new Error('OpenSSH key format is not supported. Convert with `ssh-keygen -p -m PEM -f <key>` first.');
    }
    if (keyType === null) {
        throw new Error('Could not detect private key type. Ensure it is PKCS#8 or traditional RSA/EC PEM.');
    }

    let useTraditional;
    if (format === 'traditional') {
        useTraditional = true;
    } else if (format === 'pkcs8') {
        useTraditional = false;
    } else {
        // auto: preserve family — traditional stays traditional, PKCS#8 stays PKCS#8
        useTraditional = keyType.startsWith('traditional-');
    }

    const factory = resolveFactory(explicitFactory);
    const module = await factory();
    module.FS.writeFile('/in.pem', pemText);
    module.FS.writeFile('/openssl.cnf', opensslCnf);
    module.ENV.OPENSSL_CONF = '/openssl.cnf';

    const args = ['pkey', '-in', '/in.pem', '-out', '/out.pem'];
    if (password && password !== '') {
        module.FS.writeFile('/pass.txt', password);
        args.push('-passin', 'file:/pass.txt');
    }
    if (useTraditional) args.push('-traditional');

    try {
        module.callMain(args);
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
    } catch (err) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('Decryption failed — wrong password or corrupted PEM key.');
    }

    let out;
    try {
        out = module.FS.readFile('/out.pem', { encoding: 'utf8' }).trim();
    } catch (err) {
        throw new Error('Decryption failed — OpenSSL produced no output. Check the password.');
    }
    if (!out || !out.includes('PRIVATE KEY')) {
        throw new Error('Decryption failed — OpenSSL produced no output. Check the password.');
    }
    return out;
}
