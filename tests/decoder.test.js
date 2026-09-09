import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildLogicalChain, decodeCertBlock, decodeCsrBlock, decodeEmptyNote } from '../js/tools/decoder.js';
import { parseCertMetadata, parseCsrMetadata } from '../js/utils/cert.js';
import { genSelfSignedCert, genCsr } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

describe('decoder', () => {
    it('decodes a single PEM cert via WASM', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'decode.example' });
        const { stdOut } = await decodeCertBlock(certPem, getOpenSSLFactory());
        const meta = parseCertMetadata(stdOut, '');
        assert.match(meta.subject, /decode\.example/);
        assert.ok(meta.serial.length > 0);
    });

    it('sorts leaf -> intermediate -> root regardless of input order', () => {
        const leaf = { subject: 'CN=leaf', issuer: 'CN=inter', cn: 'leaf' };
        const inter = { subject: 'CN=inter', issuer: 'CN=root', cn: 'inter' };
        const root = { subject: 'CN=root', issuer: 'CN=root', cn: 'root' };
        for (const input of [
            [leaf, root, inter],
            [root, leaf, inter],
            [root, inter, leaf],
            [inter, root, leaf],
        ]) {
            const sorted = buildLogicalChain(input);
            assert.deepEqual(sorted.map((c) => c.cn), ['leaf', 'inter', 'root']);
        }
    });

    it('returns input unchanged for single-element chains', () => {
        const one = [{ subject: 'a', issuer: 'b' }];
        assert.equal(buildLogicalChain(one), one);
    });

    it('rejects garbage PEM', async () => {
        await assert.rejects(() => decodeCertBlock('not a cert', getOpenSSLFactory()));
    });

    it('decodes a CSR block with subject, key and signature details', async () => {
        const { csrPem } = genCsr({ cn: 'inspect.example' });
        const { subjectOut, textOut } = await decodeCsrBlock(csrPem, getOpenSSLFactory());
        assert.match(subjectOut, /inspect\.example/);
        const meta = parseCsrMetadata(textOut);
        assert.equal(meta.cn, 'inspect.example');
        assert.equal(meta.pubkeyAlg, 'RSA');
        assert.equal(meta.pubkeyBits, '2048');
        assert.match(meta.sigAlg, /WithRSAEncryption/i);
    });

    it('rejects garbage as CSR', async () => {
        await assert.rejects(() => decodeCsrBlock('-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----', getOpenSSLFactory()));
    });

    it('explains empty input instead of rendering nothing', () => {
        assert.equal(decodeEmptyNote(false), '');
        const note = decodeEmptyNote(true);
        assert.match(note, /No certificates or CSRs detected/);
        assert.match(note, /BEGIN CERTIFICATE/);
    });
});
