import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { OpenSSLError, runOpenSSL } from '../js/openssl/engine.js';
import { certDecodeJob, runJobLocal } from '../js/openssl/jobs.js';
import { runJobs } from '../js/openssl/pool.js';
import { decodeCertBlock, decodeCsrBlock, pemCertificateToDer, sha256FingerprintLine } from '../js/tools/decoder.js';
import { genSelfSignedCert, genCsr } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

describe('openssl engine layer', () => {
    it('returns exit code 0 for a successful invocation', async () => {
        const module = await getOpenSSLFactory()();
        assert.equal(runOpenSSL(module, ['version']), 0);
    });

    it('throws OpenSSLError and keeps process.exitCode clean on failure', async () => {
        const module = await getOpenSSLFactory()();
        assert.throws(
            () => runOpenSSL(module, ['x509', '-in', '/does-not-exist.pem', '-noout']),
            (err) => err instanceof OpenSSLError && err.name === 'OpenSSLError' && err.args[0] === 'x509',
        );
        // Emscripten sets process.exitCode on OpenSSL failure; runOpenSSL must reset it.
        assert.equal(process.exitCode || 0, 0);
    });

    it('decodes a certificate with exactly one engine instantiation', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'engine.example' });
        const inner = getOpenSSLFactory();
        let instantiations = 0;
        const countingFactory = () => {
            instantiations += 1;
            return inner();
        };

        const res = await decodeCertBlock(certPem, countingFactory);
        assert.equal(instantiations, 1, 'one cert should need one fresh WASM instance');
        assert.match(res.stdOut, /^subject=/m);
        assert.match(res.textOut, /Signature Algorithm/);
        assert.equal(res.sanOut, '');
        assert.match(res.fpOut, /^SHA256 Fingerprint=([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    });

    it('decodes a CSR with exactly one engine instantiation', async () => {
        const { csrPem } = genCsr({ cn: 'engine.csr.example' });
        const inner = getOpenSSLFactory();
        let instantiations = 0;
        const countingFactory = () => {
            instantiations += 1;
            return inner();
        };

        const res = await decodeCsrBlock(csrPem, countingFactory);
        assert.equal(instantiations, 1);
        assert.match(res.subjectOut, /engine\.csr\.example/);
        assert.match(res.textOut, /Subject Public Key Info/);
    });

    it('computes the SHA-256 fingerprint via WebCrypto, matching Node crypto', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'fp.example' });
        const der = pemCertificateToDer(certPem);
        assert.ok(der && der.length > 0);
        assert.equal(der[0], 0x30, 'DER certificate should start with a SEQUENCE tag');

        const expectedHex = createHash('sha256').update(der).digest('hex').toUpperCase();
        const expectedColon = expectedHex.match(/../g).join(':');
        assert.equal(await sha256FingerprintLine(certPem), `SHA256 Fingerprint=${expectedColon}`);
    });

    it('returns an empty fingerprint for a non-certificate PEM', async () => {
        assert.equal(await sha256FingerprintLine('garbage'), '');
    });

    it('runs a batch of jobs through the local executor with aligned results', async () => {
        const a = genSelfSignedCert({ cn: 'batch-a.example' });
        const b = genSelfSignedCert({ cn: 'batch-b.example' });
        const factory = getOpenSSLFactory();

        // runJobLocal executes a single serialisable job.
        const one = await runJobLocal(certDecodeJob(a.certPem, 'one'), factory);
        assert.match(one['/cert.txt'], /batch-a\.example/);

        // runJobs runs a batch and preserves index alignment (worker path is
        // unavailable under Node, so this exercises the local fallback).
        const results = await runJobs([certDecodeJob(a.certPem, 'a'), certDecodeJob(b.certPem, 'b')], factory);
        assert.equal(results.length, 2);
        assert.match(results[0]['/cert.txt'], /batch-a\.example/);
        assert.match(results[1]['/cert.txt'], /batch-b\.example/);
    });
});
