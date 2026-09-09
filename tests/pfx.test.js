import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractPfxData } from '../js/tools/pfx.js';
import { extractPublicKey } from '../js/tools/matcher.js';
import { genSelfSignedCert, makePfx, makeCertsOnlyPfx } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

describe('pfx extractor', () => {
    it('extracts cert + key from password-protected PFX and they match', async () => {
        const { certPem, keyPem } = genSelfSignedCert({ cn: 'pfx.example' });
        const { pfxBytes, password } = makePfx({ certPem, keyPem });
        const factory = getOpenSSLFactory();
        const { certPem: outCert, keyPem: outKey, details } = await extractPfxData(pfxBytes, password, factory);
        assert.match(outCert, /BEGIN CERTIFICATE/);
        assert.match(outKey, /BEGIN PRIVATE KEY/);
        assert.match(details, /subject=/);
        const pubCert = await extractPublicKey(outCert, '', 'cert', factory);
        const pubKey = await extractPublicKey(outKey, '', 'key', factory);
        assert.equal(pubCert, pubKey);
    });

    it('supports empty-password PFX archives', async () => {
        const { certPem, keyPem } = genSelfSignedCert({ cn: 'nopass.example' });
        const { pfxBytes } = makePfx({ certPem, keyPem, password: '' });
        const { certPem: outCert } = await extractPfxData(pfxBytes, '', getOpenSSLFactory());
        assert.match(outCert, /BEGIN CERTIFICATE/);
    });

    it('fails on wrong password', async () => {
        const { certPem, keyPem } = genSelfSignedCert({ cn: 'wrongpass.example' });
        const { pfxBytes } = makePfx({ certPem, keyPem, password: 'correct' });
        await assert.rejects(() => extractPfxData(pfxBytes, 'incorrect', getOpenSSLFactory()));
    });

    it('returns every certificate in a multi-cert PFX with per-cert details', async () => {
        const leaf = genSelfSignedCert({ cn: 'leaf.example' });
        const ca = genSelfSignedCert({ cn: 'ca.example' });
        const { pfxBytes, password } = makePfx({ certPem: leaf.certPem, keyPem: leaf.keyPem, extraCerts: [ca.certPem] });
        const { certs, chain, keyPem } = await extractPfxData(pfxBytes, password, getOpenSSLFactory());
        assert.equal(certs.length, 2);
        assert.equal(chain.length, 2);
        assert.match(chain[0].details, /leaf\.example/);
        assert.match(chain[1].details, /ca\.example/);
        assert.match(keyPem, /PRIVATE KEY/);
    });

    it('tolerates certs-only archives with an empty key', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'certsonly.example' });
        const { pfxBytes, password } = makeCertsOnlyPfx({ certPem });
        const { certs, chain, keyPem, details } = await extractPfxData(pfxBytes, password, getOpenSSLFactory());
        assert.equal(certs.length, 1);
        assert.equal(chain.length, 1);
        assert.match(details, /certsonly\.example/);
        assert.equal(keyPem, '');
    });
});
