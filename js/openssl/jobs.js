/**
 * OpenSSL "jobs" — a serialisable description of one engine invocation.
 *
 * A job is: files to write, CLI args to run, and output files to read back.
 * The same job shape is executed either on the main thread (Local, used by the
 * Node tests and as a fallback) or inside a Web Worker (see pool.js), so the
 * decode logic exists in exactly one place.
 */
import { opensslCnf } from '../state.js';
import { runOpenSSL } from './engine.js';

/** Parse a certificate: summary lines + full text in one combined invocation. */
export function certDecodeJob(certPem, id) {
    return {
        id,
        writes: { '/input.pem': certPem },
        args: ['x509', '-in', '/input.pem', '-noout', '-subject', '-issuer', '-dates', '-serial', '-text', '-out', '/cert.txt'],
        outputs: ['/cert.txt'],
    };
}

/** Parse a CSR: subject + full text in one combined invocation. */
export function csrDecodeJob(csrPem, id) {
    return {
        id,
        writes: { '/input.pem': csrPem, '/openssl.cnf': opensslCnf },
        env: { OPENSSL_CONF: '/openssl.cnf' },
        args: ['req', '-in', '/input.pem', '-noout', '-subject', '-text', '-out', '/csr.txt', '-config', '/openssl.cnf'],
        outputs: ['/csr.txt'],
    };
}

/**
 * Execute one job against a freshly created engine instance.
 * OpenSSL instances are single-use, so callers get a factory and this creates
 * a new module for the job.
 */
export async function runJobLocal(job, factory) {
    const module = await factory();
    for (const [path, content] of Object.entries(job.writes || {})) {
        module.FS.writeFile(path, content);
    }
    if (job.env) Object.assign(module.ENV, job.env);
    runOpenSSL(module, job.args);
    const files = {};
    for (const path of job.outputs || []) {
        try {
            files[path] = module.FS.readFile(path, { encoding: 'utf8' });
        } catch (e) {
            // Missing output is reported by the interpreter as a parse failure.
        }
    }
    return files;
}
