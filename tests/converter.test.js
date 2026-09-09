import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { runConversion } from '../js/tools/converter.js';
import { extractPfxData } from '../js/tools/pfx.js';
import { extractPublicKey } from '../js/tools/matcher.js';
import { genSelfSignedCert, genEncryptedKeys, certForKey, makeP7b } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

const textOf = (u8) => Buffer.from(u8).toString('utf8');

describe('converter', () => {
    it('round-trips PEM -> DER -> PEM', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'conv.example' });
        const factory = getOpenSSLFactory();
        const { outData: der } = await runConversion({ certBytes: certPem, fromType: 'pem', toType: 'der' }, factory);
        assert.ok(der.length > 100);
        assert.doesNotMatch(textOf(der.slice(0, 30)), /BEGIN CERTIFICATE/);
        const { outData: back } = await runConversion({ certBytes: der, fromType: 'der', toType: 'pem' }, factory);
        assert.match(textOf(back), /BEGIN CERTIFICATE/);
    });

    it('converts PEM -> P7B', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'p7b.example' });
        const { outData } = await runConversion({ certBytes: certPem, fromType: 'pem', toType: 'p7b' }, getOpenSSLFactory());
        assert.match(textOf(outData), /BEGIN PKCS7/);
    });

    it('bundles PEM + key -> PFX with password, then re-extracts', async () => {
        const { certPem, keyPem } = genSelfSignedCert({ cn: 'bundle.example' });
        const factory = getOpenSSLFactory();
        const { outData: pfx } = await runConversion(
            { certBytes: certPem, keyBytes: keyPem, fromType: 'pem', toType: 'pfx', pfxPass: 'bundle-pass' },
            factory
        );
        assert.ok(pfx.length > 500);
        const { certPem: back } = await extractPfxData(pfx, 'bundle-pass', factory);
        assert.match(back, /BEGIN CERTIFICATE/);
    });

    it('rejects same-format and keyless PFX requests', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'err.example' });
        const factory = getOpenSSLFactory();
        await assert.rejects(() => runConversion({ certBytes: certPem, fromType: 'pem', toType: 'pem' }, factory));
        await assert.rejects(() => runConversion({ certBytes: certPem, fromType: 'pem', toType: 'pfx' }, factory));
    });

    it('unpacks PEM-encoded P7B -> PEM with matching certificate', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'unpack.example' });
        const factory = getOpenSSLFactory();
        const { outData: p7b } = await runConversion({ certBytes: certPem, fromType: 'pem', toType: 'p7b' }, factory);
        const { outData: back } = await runConversion({ certBytes: textOf(p7b), fromType: 'p7b', toType: 'pem' }, factory);
        assert.match(textOf(back), /BEGIN CERTIFICATE/);
        const before = await extractPublicKey(certPem, '', 'orig', factory);
        const after = await extractPublicKey(textOf(back), '', 'unpacked', factory);
        assert.equal(before, after);
    });

    it('unpacks DER-encoded P7B -> PEM via informat fallback', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'unpack-der.example' });
        const { p7bBytes } = makeP7b(certPem, { der: true });
        const factory = getOpenSSLFactory();
        const { outData: back } = await runConversion({ certBytes: p7bBytes, fromType: 'p7b', toType: 'pem' }, factory);
        assert.match(textOf(back), /BEGIN CERTIFICATE/);
        const before = await extractPublicKey(certPem, '', 'orig', factory);
        const after = await extractPublicKey(textOf(back), '', 'unpacked', factory);
        assert.equal(before, after);
    });

    it('rejects P7B -> non-PEM targets with a clear error', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'p7b-err.example' });
        const factory = getOpenSSLFactory();
        const { outData: p7b } = await runConversion({ certBytes: certPem, fromType: 'pem', toType: 'p7b' }, factory);
        await assert.rejects(
            () => runConversion({ certBytes: textOf(p7b), fromType: 'p7b', toType: 'der' }, factory),
            /only be unpacked to PEM/
        );
        await assert.rejects(() => runConversion({ certBytes: 'garbage', fromType: 'p7b', toType: 'pem' }, factory), /neither PEM- nor DER/);
    });

    it('bundles encrypted key -> PFX with key password, then re-extracts', async () => {
        const { rsaEncPem, password: keyPass } = genEncryptedKeys();
        const { certPem } = certForKey({ keyPem: rsaEncPem, password: keyPass, cn: 'enc-bundle.example' });
        const factory = getOpenSSLFactory();
        const { outData: pfx } = await runConversion(
            { certBytes: certPem, keyBytes: rsaEncPem, fromType: 'pem', toType: 'pfx', pfxPass: 'bundle-pass', keyPass },
            factory
        );
        assert.ok(pfx.length > 500);
        const { certPem: backCert, keyPem: backKey } = await extractPfxData(pfx, 'bundle-pass', factory);
        assert.match(backCert, /BEGIN CERTIFICATE/);
        assert.match(backKey, /BEGIN PRIVATE KEY/);
        const before = await extractPublicKey(rsaEncPem, keyPass, 'enc', factory);
        const after = await extractPublicKey(backKey, '', 'dec', factory);
        assert.equal(before, after);
    });

    it('fails PFX build for encrypted key without key password', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'enckey-err.example' });
        const { rsaEncPem } = genEncryptedKeys();
        await assert.rejects(
            () => runConversion({ certBytes: certPem, keyBytes: rsaEncPem, fromType: 'pem', toType: 'pfx', pfxPass: 'x' }, getOpenSSLFactory())
        );
    });
});
