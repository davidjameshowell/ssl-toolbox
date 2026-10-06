/**
 * OpenSSL engine layer.
 *
 * Responsibilities:
 *  - P0: run OpenSSL CLI invocations and surface *real* failures. The wasm is
 *        built with EXIT_RUNTIME=0 (noExitRuntime=true), so callMain returns the
 *        process exit status instead of throwing, and a hard abort raises a
 *        RuntimeError that poisons the instance. Both are normalised here into
 *        an OpenSSLError so callers can map them to user-facing messages.
 *  - P1: compile the wasm module once per page and hand every createOpenSSL()
 *        call a ready-made WebAssembly.Module via `instantiateWasm`, so repeat
 *        operations skip the 3 MB fetch + compile.
 *
 * Nothing here touches `document`/`window` at import time, so the Node test
 * suite can import tools that depend on it.
 */

const WASM_PATH = 'vendor/openssl/openssl.wasm';

/** Error thrown for any OpenSSL execution failure (non-zero exit or abort). */
export class OpenSSLError extends Error {
    constructor(message, { args = [], cause = null } = {}) {
        super(message);
        this.name = 'OpenSSLError';
        this.args = args;
        this.cause = cause;
    }
}

/**
 * Emscripten's Node runtime sets `process.exitCode` from `_proc_exit` on every
 * OpenSSL invocation — including intentionally-failed ones (wrong password,
 * negative parse attempts). Left alone it fails the whole `node:test` process,
 * so successful *and* failed calls are normalised back to 0 here.
 */
function resetNodeExitCode() {
    if (typeof process !== 'undefined' && process && process.exitCode) {
        process.exitCode = 0;
    }
}

/**
 * Execute an OpenSSL CLI invocation against an initialised module.
 *
 * Returns the process exit code (0 on success). Throws OpenSSLError when the
 * command exits non-zero or the instance aborts. A thrown instance must be
 * discarded — create a fresh one.
 */
export function runOpenSSL(module, args) {
    let code;
    try {
        // callMain prepends the program name and mutates the array; pass a copy
        // so callers' argument lists (and any error metadata) stay intact.
        code = module.callMain([...args]);
    } catch (cause) {
        throw new OpenSSLError('OpenSSL execution aborted', { args, cause });
    } finally {
        resetNodeExitCode();
    }
    if (typeof code === 'number' && code !== 0) {
        throw new OpenSSLError(`OpenSSL exited with status ${code}`, { args });
    }
    return typeof code === 'number' ? code : 0;
}

/** Read a file produced by OpenSSL inside the module FS. */
export function readOutput(module, path, encoding = 'utf8') {
    try {
        return module.FS.readFile(path, { encoding });
    } catch (cause) {
        throw new OpenSSLError(`OpenSSL produced no output at ${path}`, { cause });
    }
}

/* -------------------------------------------------------------------------- */
/* Browser engine: compile once, instantiate cheaply                          */
/* -------------------------------------------------------------------------- */

let compiledModule = null;
let compilePromise = null;

function wasmUrl() {
    try {
        return new URL(WASM_PATH, document.baseURI).href;
    } catch (e) {
        return WASM_PATH;
    }
}

/** True once the wasm binary has been fetched and compiled. */
export function isEngineCompiled() {
    return compiledModule !== null;
}

/**
 * Fetch + compile the wasm binary exactly once. Safe to call repeatedly and
 * safe to call before the first tool use (warm-up). Resolves to null when the
 * environment cannot pre-compile (then the glue falls back to its own loader).
 */
export function preloadEngine() {
    if (compilePromise) return compilePromise;
    if (typeof WebAssembly === 'undefined' || typeof fetch === 'undefined') {
        return Promise.resolve(null);
    }
    const url = wasmUrl();
    const fetchBytes = () => fetch(url, { credentials: 'same-origin' }).then((r) => r.arrayBuffer());
    const compile = typeof WebAssembly.compileStreaming === 'function'
        ? WebAssembly.compileStreaming(fetch(url, { credentials: 'same-origin' })).catch(() => fetchBytes().then((b) => WebAssembly.compile(b)))
        : fetchBytes().then((b) => WebAssembly.compile(b));

    compilePromise = compile
        .then((mod) => {
            compiledModule = mod;
            return mod;
        })
        .catch(() => {
            // Leave the glue to fetch/compile on demand; allow a retry later.
            compilePromise = null;
            return null;
        });
    return compilePromise;
}

function hasBrowserFactory() {
    return typeof window !== 'undefined' && typeof window.createOpenSSL !== 'undefined';
}

/** True when the OpenSSL factory script has loaded. */
export function isEngineAvailable() {
    return hasBrowserFactory();
}

/** Instantiate a browser module, reusing the pre-compiled WebAssembly.Module. */
export async function createBrowserModule(opts = {}) {
    if (!hasBrowserFactory()) {
        throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
    }
    if (!compiledModule) {
        await preloadEngine();
    }
    const moduleOpts = { ...opts };
    if (compiledModule) {
        moduleOpts.instantiateWasm = (imports, success) => {
            const instance = new WebAssembly.Instance(compiledModule, imports);
            success(instance, compiledModule);
            return instance.exports;
        };
    }
    return window.createOpenSSL(moduleOpts);
}

/**
 * Resolve the OpenSSL module factory.
 *  - In the browser: returns a factory that reuses the pre-compiled wasm.
 *  - In tests: the caller supplies an explicit factory.
 */
export function resolveFactory(explicitFactory) {
    if (explicitFactory) return explicitFactory;
    if (hasBrowserFactory()) {
        return (opts = {}) => createBrowserModule(opts);
    }
    throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
}
