import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectKeyType, isEncryptedKey, decryptPrivateKey, inspectKeyInfo, summarizeKeyInfo } from '../js/utils/decrypt.js';
import { extractPublicKey } from '../js/tools/matcher.js';
import { genEncryptedKeys, run as runOpenssl } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

describe('key unlocker (decryptPrivateKey)', () => {
    it('classifies PKCS#8, traditional and OpenSSH headers', () => {
        const { rsaEncPem, ecEncPem, rsaTradEncPem, rsaPlainPem } = genEncryptedKeys();
        assert.equal(detectKeyType(rsaEncPem), 'pkcs8-encrypted');
        assert.equal(detectKeyType(ecEncPem), 'pkcs8-encrypted');
        assert.equal(detectKeyType(rsaTradEncPem), 'traditional-rsa-encrypted');
        assert.equal(detectKeyType(rsaPlainPem), 'pkcs8');
        assert.equal(detectKeyType('-----BEGIN OPENSSH PRIVATE KEY-----\nxyz'), 'openssh');
        assert.equal(detectKeyType('garbage'), null);
        assert.equal(isEncryptedKey(rsaEncPem), true);
        assert.equal(isEncryptedKey(rsaPlainPem), false);
    });

    it('creates an encrypted RSA key with password and decrypts it (PKCS#8 auto)', async () => {
        const { rsaEncPem, password } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        const clear = await decryptPrivateKey(rsaEncPem, password, { format: 'auto', createOpenSSL: factory });
        assert.match(clear, /-----BEGIN PRIVATE KEY-----/);
        assert.doesNotMatch(clear, /ENCRYPTED/);
        // same key: pubkey before (via password) equals pubkey after (no password)
        const before = await extractPublicKey(rsaEncPem, password, 'enc', factory);
        const after = await extractPublicKey(clear, '', 'dec', factory);
        assert.equal(before, after);
    });

    it('decrypts EC keys and preserves key material', async () => {
        const { ecEncPem, password } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        const clear = await decryptPrivateKey(ecEncPem, password, { format: 'pkcs8', createOpenSSL: factory });
        assert.match(clear, /-----BEGIN PRIVATE KEY-----/);
        const before = await extractPublicKey(ecEncPem, password, 'enc', factory);
        const after = await extractPublicKey(clear, '', 'dec', factory);
        assert.equal(before, after);
    });

    it('auto preserves traditional RSA type; explicit pkcs8 converts', async () => {
        const { rsaTradEncPem, password } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        const auto = await decryptPrivateKey(rsaTradEncPem, password, { format: 'auto', createOpenSSL: factory });
        assert.match(auto, /-----BEGIN RSA PRIVATE KEY-----/);
        const converted = await decryptPrivateKey(rsaTradEncPem, password, { format: 'pkcs8', createOpenSSL: factory });
        assert.match(converted, /-----BEGIN PRIVATE KEY-----/);
        assert.doesNotMatch(converted, /BEGIN RSA PRIVATE KEY/);
    });

    it('supports passwords with colons/special chars via file-based passin', async () => {
        const special = 'p@ss:w/ith:colons$!%';
        const { rsaEncPem } = genEncryptedKeys({ password: special });
        const clear = await decryptPrivateKey(rsaEncPem, special, { createOpenSSL: getOpenSSLFactory() });
        assert.match(clear, /BEGIN (RSA )?PRIVATE KEY/);
    });

    it('rejects wrong password, empty input, non-keys and OpenSSH', async () => {
        const { rsaEncPem } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        await assert.rejects(() => decryptPrivateKey(rsaEncPem, 'wrong-password', { createOpenSSL: factory }), /wrong password|Decryption failed/);
        await assert.rejects(() => decryptPrivateKey('', 'x', { createOpenSSL: factory }), /No private key/);
        await assert.rejects(() => decryptPrivateKey('-----BEGIN CERTIFICATE-----\nabc', 'x', { createOpenSSL: factory }), /Not a private key/);
        await assert.rejects(
            () => decryptPrivateKey('-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=', 'x', { createOpenSSL: factory }),
            /OpenSSH/
        );
    });
});

describe('key inspector (inspectKeyInfo)', () => {
    it('reads family and size from unencrypted RSA and EC keys', async () => {
        const { rsaPlainPem, ecEncPem, password } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        const rsa = await inspectKeyInfo(rsaPlainPem, { createOpenSSL: factory });
        assert.equal(rsa.family, 'RSA');
        assert.equal(rsa.bits, '2048');
        assert.equal(rsa.encrypted, false);

        const ecDecrypted = await decryptPrivateKey(ecEncPem, password, { createOpenSSL: factory });
        const ec = await inspectKeyInfo(ecDecrypted, { createOpenSSL: factory });
        assert.equal(ec.family, 'EC');
        assert.equal(ec.bits, '256');
        assert.equal(ec.curve, 'prime256v1');
    });

    it('identifies encrypted keys from headers without a password', async () => {
        const { rsaEncPem, rsaTradEncPem } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        const pkcs8 = await inspectKeyInfo(rsaEncPem, { createOpenSSL: factory });
        assert.equal(pkcs8.encrypted, true);
        assert.equal(pkcs8.bits, null);

        const trad = await inspectKeyInfo(rsaTradEncPem, { createOpenSSL: factory });
        assert.equal(trad.encrypted, true);
        assert.equal(trad.family, 'RSA');
        assert.match(trad.dekCipher || '', /AES|DES/);
    });

    it('reads size through the password for encrypted keys', async () => {
        const { rsaEncPem, password } = genEncryptedKeys();
        const info = await inspectKeyInfo(rsaEncPem, { password, createOpenSSL: getOpenSSLFactory() });
        assert.equal(info.family, 'RSA');
        assert.equal(info.bits, '2048');
        assert.equal(info.encrypted, true);
    });

    it('recognizes Ed25519 keys', async () => {
        const edPem = runOpenssl(['genpkey', '-algorithm', 'ed25519']);
        const info = await inspectKeyInfo(edPem, { createOpenSSL: getOpenSSLFactory() });
        assert.equal(info.family, 'Ed25519');
        assert.equal(info.encrypted, false);
    });

    it('rejects non-keys and wrong passwords', async () => {
        const { rsaEncPem } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        await assert.rejects(() => inspectKeyInfo('not a key', { createOpenSSL: factory }), /Not a private key/);
        await assert.rejects(() => inspectKeyInfo(rsaEncPem, { password: 'wrong', createOpenSSL: factory }), /wrong password/);
    });

    it('summarizes key info in one line', () => {
        assert.equal(
            summarizeKeyInfo({ family: 'RSA', bits: '2048', curve: null, encrypted: true, dekCipher: 'AES-256-CBC' }, 'pkcs8'),
            'RSA · 2048-bit · AES-256-CBC encrypted · → PKCS#8'
        );
        assert.equal(
            summarizeKeyInfo({ family: 'EC', bits: '256', curve: 'prime256v1', encrypted: false, dekCipher: null }, 'auto'),
            'EC · 256-bit (prime256v1) · unencrypted'
        );
    });
});
