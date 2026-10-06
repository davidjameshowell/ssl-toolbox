/**
 * Classic Web Worker that executes one OpenSSL job at a time off the main
 * thread. Loaded via `new Worker(new URL('./openssl-worker.js', import.meta.url))`.
 *
 * The WASM modules are single-use (one OpenSSL command per instance), so each
 * job gets a fresh instance created from a module compiled once per worker.
 */
/* eslint-disable no-restricted-globals */
importScripts('../../vendor/openssl/openssl.js');

const WASM_URL = '../../vendor/openssl/openssl.wasm';

let compiledPromise = null;

function getCompiledModule() {
    if (!compiledPromise) {
        compiledPromise = (async () => {
            try {
                if (typeof WebAssembly.compileStreaming === 'function') {
                    return await WebAssembly.compileStreaming(fetch(WASM_URL));
                }
                const buffer = await (await fetch(WASM_URL)).arrayBuffer();
                return await WebAssembly.compile(buffer);
            } catch (e) {
                return null;
            }
        })();
    }
    return compiledPromise;
}

async function createModule() {
    const compiled = await getCompiledModule();
    const opts = compiled
        ? {
            instantiateWasm(imports, success) {
                const instance = new WebAssembly.Instance(compiled, imports);
                success(instance, compiled);
                return instance.exports;
            },
        }
        : {};
    return self.createOpenSSL(opts);
}

self.onmessage = async (event) => {
    const { id, args, writes = {}, env = {}, outputs = [] } = event.data || {};
    try {
        const module = await createModule();
        for (const [path, content] of Object.entries(writes)) {
            module.FS.writeFile(path, content);
        }
        Object.assign(module.ENV, env);

        let code = 0;
        try {
            const ret = module.callMain(args);
            code = typeof ret === 'number' ? ret : 0;
        } catch (err) {
            code = 1;
        }

        const files = {};
        for (const path of outputs) {
            try {
                files[path] = module.FS.readFile(path, { encoding: 'utf8' });
            } catch (e) {
                // Leave missing; the caller reports a parse failure.
            }
        }
        self.postMessage({ id, ok: true, files, code });
    } catch (err) {
        self.postMessage({ id, ok: false, error: String((err && err.message) || err), files: {} });
    }
};

// Announce readiness so the pool never posts a job into a worker that failed
// to load its engine glue.
self.postMessage({ type: 'ready', hasFactory: typeof self.createOpenSSL === 'function' });
