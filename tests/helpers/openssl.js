import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// Test-only passphrases are generated per run rather than committed as literals
// (a hardcoded `password = "..."` trips generic-password secret scanners).
export const TEST_PASSWORD = `test-${crypto.randomBytes(12).toString('hex')}`;

function run(args, input = null) {
    return execFileSync('openssl', args, { input, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] });
}

function runBytes(args, input = null) {
    return execFileSync('openssl', args, { input, stdio: ['pipe', 'pipe', 'pipe'] });
}

export function mkTempDir(prefix = 'ssl-toolbox-') {
    return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

export function genSelfSignedCert({ cn = 'test.example', days = 30 } = {}) {
    const dir = mkTempDir();
    const key = path.join(dir, 'key.pem');
    const cert = path.join(dir, 'cert.pem');
    execFileSync('openssl', [
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', key, '-out', cert,
        '-days', String(days), '-subj', `/CN=${cn}/O=Test Org`,
        '-addext', 'subjectAltName=DNS:test.example,DNS:www.test.example',
    ]);
    return {
        dir,
        keyPem: fs.readFileSync(key, 'utf8'),
        certPem: fs.readFileSync(cert, 'utf8'),
        keyPath: key,
        certPath: cert,
    };
}

export function genEncryptedKeys({ password = TEST_PASSWORD } = {}) {
    const dir = mkTempDir();
    const rsaEnc = path.join(dir, 'rsa-enc.pem');
    const ecEnc = path.join(dir, 'ec-enc.pem');
    const rsaTradEnc = path.join(dir, 'rsa-trad-enc.pem');
    const rsaPlain = path.join(dir, 'rsa-plain.pem');

    execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-aes256', '-pass', `pass:${password}`, '-out', rsaEnc]);
    execFileSync('openssl', ['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-aes256', '-pass', `pass:${password}`, '-out', ecEnc]);
    execFileSync('openssl', ['genrsa', '-traditional', '-aes256', '-passout', `pass:${password}`, '-out', rsaTradEnc, '2048']);
    execFileSync('openssl', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', rsaPlain]);

    return {
        dir,
        password,
        rsaEncPem: fs.readFileSync(rsaEnc, 'utf8'),
        ecEncPem: fs.readFileSync(ecEnc, 'utf8'),
        rsaTradEncPem: fs.readFileSync(rsaTradEnc, 'utf8'),
        rsaPlainPem: fs.readFileSync(rsaPlain, 'utf8'),
    };
}

export function genCsr({ cn = 'csr.example' } = {}) {
    const dir = mkTempDir();
    const key = path.join(dir, 'key.pem');
    const csr = path.join(dir, 'req.csr');
    execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', `/CN=${cn}`]);
    return { dir, keyPem: fs.readFileSync(key, 'utf8'), csrPem: fs.readFileSync(csr, 'utf8') };
}

export function makePfx({ certPem, keyPem, password = TEST_PASSWORD, extraCerts = [] }) {
    const dir = mkTempDir();
    const cert = path.join(dir, 'cert.pem');
    const key = path.join(dir, 'key.pem');
    const out = path.join(dir, 'bundle.pfx');
    fs.writeFileSync(cert, certPem);
    fs.writeFileSync(key, keyPem);
    const args = ['pkcs12', '-export', '-legacy', '-out', out, '-inkey', key, '-in', cert, '-passout', `pass:${password}`];
    extraCerts.forEach((extra, i) => {
        const extraPath = path.join(dir, `chain${i}.pem`);
        fs.writeFileSync(extraPath, extra);
        args.push('-certfile', extraPath);
    });
    execFileSync('openssl', args);
    return { dir, pfxBytes: new Uint8Array(fs.readFileSync(out)), password };
}

export function makeCertsOnlyPfx({ certPem, password = TEST_PASSWORD }) {
    const dir = mkTempDir();
    const cert = path.join(dir, 'cert.pem');
    const out = path.join(dir, 'bundle.pfx');
    fs.writeFileSync(cert, certPem);
    execFileSync('openssl', ['pkcs12', '-export', '-legacy', '-nokeys', '-out', out, '-in', cert, '-passout', `pass:${password}`]);
    return { dir, pfxBytes: new Uint8Array(fs.readFileSync(out)), password };
}

export function certForKey({ keyPem, password = null, cn = 'match.example', days = 30 }) {
    const dir = mkTempDir();
    const key = path.join(dir, 'key.pem');
    const cert = path.join(dir, 'cert.pem');
    fs.writeFileSync(key, keyPem);
    const args = ['req', '-new', '-x509', '-key', key, '-out', cert, '-days', String(days), '-subj', `/CN=${cn}`];
    if (password) args.push('-passin', `pass:${password}`);
    execFileSync('openssl', args);
    return { dir, certPem: fs.readFileSync(cert, 'utf8') };
}

export function makeP7b(certPem, { der = false } = {}) {
    const dir = mkTempDir();
    const cert = path.join(dir, 'cert.pem');
    const out = path.join(dir, der ? 'bundle.p7b' : 'bundle.p7b');
    fs.writeFileSync(cert, certPem);
    const args = ['crl2pkcs7', '-nocrl', '-certfile', cert, '-out', out];
    if (der) args.push('-outform', 'der');
    execFileSync('openssl', args);
    const raw = fs.readFileSync(out, der ? null : 'utf8');
    return { dir, p7bBytes: der ? new Uint8Array(raw) : raw };
}

export { run, runBytes };
