import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectPemType, extractPublicKey } from '../js/tools/matcher.js';
import { genSelfSignedCert, genCsr, genEncryptedKeys } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

describe('matcher', () => {
    it('detects PEM types', () => {
        assert.equal(detectPemType('-----BEGIN CERTIFICATE-----'), 'x509');
        assert.equal(detectPemType('-----BEGIN CERTIFICATE REQUEST-----'), 'req');
        assert.equal(detectPemType('-----BEGIN PRIVATE KEY-----'), 'pkey');
        assert.equal(detectPemType('-----BEGIN ENCRYPTED PRIVATE KEY-----'), 'pkey');
        assert.equal(detectPemType('garbage'), null);
    });

    it('matches key to its own cert, rejects unrelated cert', async () => {
        const a = genSelfSignedCert({ cn: 'match-a.example' });
        const b = genSelfSignedCert({ cn: 'match-b.example' });
        const factory = getOpenSSLFactory();
        const pubKey = await extractPublicKey(a.keyPem, '', 'key', factory);
        const pubCertA = await extractPublicKey(a.certPem, '', 'cert', factory);
        const pubCertB = await extractPublicKey(b.certPem, '', 'cert', factory);
        assert.equal(pubKey, pubCertA);
        assert.notEqual(pubKey, pubCertB);
    });

    it('reads encrypted keys with password, fails without/wrong', async () => {
        const { rsaEncPem, password } = genEncryptedKeys();
        const factory = getOpenSSLFactory();
        const pub = await extractPublicKey(rsaEncPem, password, 'Input 1', factory);
        assert.match(pub, /BEGIN PUBLIC KEY/);
        await assert.rejects(() => extractPublicKey(rsaEncPem, '', 'Input 1', factory));
        await assert.rejects(() => extractPublicKey(rsaEncPem, 'wrong', 'Input 1', factory));
    });

    it('reads CSR public keys', async () => {
        const { csrPem, keyPem } = genCsr();
        const factory = getOpenSSLFactory();
        const fromCsr = await extractPublicKey(csrPem, '', 'csr', factory);
        const fromKey = await extractPublicKey(keyPem, '', 'key', factory);
        assert.equal(fromCsr, fromKey);
    });
});
