import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
    parseCertMetadata, formatFriendlyDate, parseCertTextDetails, parseCsrMetadata,
    parseSanEntries, parseFingerprint, getExpiryStatus,
} from '../js/utils/cert.js';
import { genSelfSignedCert } from './helpers/openssl.js';
import { getOpenSSLFactory } from './helpers/wasm.js';

describe('cert utils', () => {
    it('parses subject, issuer, dates, serial and SAN from WASM output', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'unit.example' });
        const factory = getOpenSSLFactory();
        const mod = await factory();
        mod.FS.writeFile('/input.pem', certPem);
        mod.callMain(['x509', '-in', '/input.pem', '-noout', '-subject', '-issuer', '-dates', '-serial', '-out', '/std.txt']);
        const stdOut = mod.FS.readFile('/std.txt', { encoding: 'utf8' });

        const mod2 = await factory();
        mod2.FS.writeFile('/input.pem', certPem);
        mod2.callMain(['x509', '-in', '/input.pem', '-noout', '-ext', 'subjectAltName', '-out', '/san.txt']);
        const sanOut = mod2.FS.readFile('/san.txt', { encoding: 'utf8' });

        const meta = parseCertMetadata(stdOut, sanOut);
        assert.match(meta.subject, /CN\s*=\s*unit\.example/);
        assert.equal(meta.cn, 'unit.example');
        assert.equal(meta.org, 'Test Org');
        assert.ok(meta.validFromRaw.length > 0);
        assert.ok(meta.validToRaw.length > 0);
        assert.notEqual(meta.validFrom, meta.validFromRaw); // friendly formatting applied
        assert.match(meta.serial, /^[0-9A-F]+$/i);
        assert.match(meta.san, /test\.example/);
    });

    it('handles certs without SAN gracefully', () => {
        const stdOut = 'subject=CN = plain.example, O = Acme\nissuer=CN = plain.example, O = Acme\nnotBefore=Jan  1 00:00:00 2024 GMT\nnotAfter=Jan  1 00:00:00 2025 GMT\nserial=1234ABCD\n';
        const meta = parseCertMetadata(stdOut, '');
        assert.equal(meta.cn, 'plain.example');
        assert.equal(meta.san, '');
        assert.equal(meta.serial, '1234ABCD');
    });

    it('formatFriendlyDate passes through garbage', () => {
        assert.equal(formatFriendlyDate('not-a-date'), 'not-a-date');
        const friendly = formatFriendlyDate('Jan  1 00:00:00 2025 GMT');
        assert.notEqual(friendly, 'Jan  1 00:00:00 2025 GMT');
        assert.match(friendly, /2024|2025/); // timezone-dependent year boundary
    });

    it('parses signature alg, pubkey, usages and curve from -text output', () => {
        const textOut = [
            'Certificate:',
            '    Data:',
            '        Signature Algorithm: sha256WithRSAEncryption',
            '        Subject Public Key Info:',
            '            Public Key Algorithm: rsaEncryption',
            '                Public-Key: (2048 bit)',
            '        X509v3 extensions:',
            '            X509v3 Key Usage: critical',
            '                Digital Signature, Key Encipherment',
            '            X509v3 Extended Key Usage:',
            '                TLS Web Server Authentication, TLS Web Client Authentication',
            '    Signature Algorithm: sha256WithRSAEncryption',
            '',
        ].join('\n');
        const d = parseCertTextDetails(textOut);
        assert.equal(d.sigAlg, 'sha256WithRSAEncryption');
        assert.equal(d.pubkeyAlg, 'RSA');
        assert.equal(d.pubkeyBits, '2048');
        assert.equal(d.keyUsage, 'Digital Signature, Key Encipherment');
        assert.equal(d.extKeyUsage, 'TLS Web Server Authentication, TLS Web Client Authentication');
    });

    it('maps EC algorithms and captures curve', () => {
        const textOut = 'Public Key Algorithm: id-ecPublicKey\n    Public-Key: (256 bit)\n    ASN1 OID: prime256v1\n';
        const d = parseCertTextDetails(textOut);
        assert.equal(d.pubkeyAlg, 'EC');
        assert.equal(d.pubkeyBits, '256');
        assert.equal(d.curve, 'prime256v1');
    });

    it('collects all SAN entries across continuation lines', () => {
        const sanOut = 'X509v3 Subject Alternative Name: \n    DNS:example.com, DNS:www.example.com,\n    IP Address:10.0.0.1, email:admin@example.com\nX509v3 Basic Constraints: critical\n';
        assert.equal(
            parseSanEntries(sanOut),
            'DNS:example.com, DNS:www.example.com, IP Address:10.0.0.1, email:admin@example.com'
        );
        assert.equal(parseSanEntries(''), '');
        assert.equal(parseSanEntries('no extensions here'), '');
    });

    it('classifies expiry status against a fixed clock', () => {
        const now = new Date('2026-09-09T00:00:00Z');
        assert.equal(getExpiryStatus('Jan  1 00:00:00 2024 GMT', now), 'expired');
        assert.equal(getExpiryStatus('Sep 20 00:00:00 2026 GMT', now), 'expiring');
        assert.equal(getExpiryStatus('Oct  9 16:43:04 2026 GMT', now), 'valid');
        assert.equal(getExpiryStatus('garbage', now), '');
    });

    it('parses fingerprints', () => {
        assert.equal(parseFingerprint('sha256 Fingerprint=ab:cd:01\n'), 'AB:CD:01');
        assert.equal(parseFingerprint(''), '');
    });

    it('parses CSR metadata from req -text output', () => {
        const textOut = [
            'Certificate Request:',
            '    Data:',
            '        Subject: CN = csr.example, O = CSR Co',
            '        Subject Public Key Info:',
            '            Public Key Algorithm: rsaEncryption',
            '                Public-Key: (2048 bit)',
            '        Attributes:',
            '            Requested Extensions:',
            '                X509v3 Subject Alternative Name:',
            '                    DNS:csr.example, DNS:www.csr.example',
            '    Signature Algorithm: sha256WithRSAEncryption',
            '',
        ].join('\n');
        const csr = parseCsrMetadata(textOut);
        assert.equal(csr.cn, 'csr.example');
        assert.equal(csr.org, 'CSR Co');
        assert.equal(csr.sigAlg, 'sha256WithRSAEncryption');
        assert.equal(csr.pubkeyAlg, 'RSA');
        assert.equal(csr.pubkeyBits, '2048');
        assert.equal(csr.san, 'DNS:csr.example, DNS:www.csr.example');
    });

    it('fills extended fields via 4-arg parseCertMetadata', async () => {
        const { certPem } = genSelfSignedCert({ cn: 'extended.example', days: 90 });
        const { decodeCertBlock } = await import('../js/tools/decoder.js');
        const { stdOut, sanOut, textOut, fpOut } = await decodeCertBlock(certPem, getOpenSSLFactory());
        const meta = parseCertMetadata(stdOut, sanOut, textOut, fpOut);
        assert.match(meta.sigAlg, /WithRSAEncryption|ECDSA|Ed25519/i);
        assert.equal(meta.pubkeyAlg, 'RSA');
        assert.equal(meta.pubkeyBits, '2048');
        assert.match(meta.fingerprintSha256, /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
        assert.equal(meta.expiryStatus, 'valid');
        assert.match(meta.san, /DNS:/);
    });
});
