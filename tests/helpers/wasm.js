import fs from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const here = path.dirname(fileURLToPath(import.meta.url));
const vendorDir = path.join(here, '../../vendor/openssl');
const vendorFile = path.join(vendorDir, 'openssl.js');

// vendor/openssl.js is a UMD bundle with `module.exports = createOpenSSL`.
// Root package.json is type:module, so plain require() would load it as ESM
// (exports undefined → empty namespace). Execute it in a CJS-like VM context.
function loadVendorFactory() {
    const code = fs.readFileSync(vendorFile, 'utf8');
    const module = { exports: {} };
    const sandbox = {
        module,
        exports: module.exports,
        require: createRequire(vendorFile),
        __dirname: vendorDir,
        __filename: vendorFile,
        process,
        console,
        Buffer,
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        URL,
        Blob,
        globalThis,
    };
    sandbox.self = sandbox;
    sandbox.globalThis = sandbox;
    vm.createContext(sandbox);
    vm.runInContext(code, sandbox, { filename: vendorFile });
    return sandbox.module.exports.default || sandbox.module.exports;
}

const createOpenSSL = loadVendorFactory();

export function getOpenSSLFactory() {
    return (opts = {}) =>
        createOpenSSL({
            locateFile: (p) => path.join(vendorDir, p),
            ...opts,
        });
}

export { createOpenSSL };
