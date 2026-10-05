/**
 * Browser worker pool for OpenSSL jobs (P2, off-main-thread).
 *
 * A small fixed pool of classic workers each loads the WASM engine once and
 * executes serialised jobs. The pool is created lazily and only for batches
 * large enough to amortise worker + wasm bootstrap. It is deliberately
 * fail-safe: workers announce readiness before any job is sent, every job has
 * a timeout, and any failure falls back to identical main-thread execution.
 */
import { resolveFactory } from './engine.js';
import { runJobLocal } from './jobs.js';

// Below this batch size, main-thread execution is faster than worker bootstrap.
const WORKER_THRESHOLD = 4;
const MAX_WORKERS = 4;
const READY_TIMEOUT_MS = 4000;
const JOB_TIMEOUT_MS = 20000;

let poolPromise = null;

function workersAvailable() {
    return typeof Worker !== 'undefined' && typeof navigator !== 'undefined';
}

class WorkerHandle {
    constructor() {
        this.failed = false;
        this.pending = new Map();
        this.ready = new Promise((resolve) => {
            this.resolveReady = resolve;
        });

        try {
            this.worker = new Worker(new URL('./openssl-worker.js', import.meta.url));
        } catch (err) {
            this.failed = true;
            this.resolveReady(false);
            return;
        }

        this.worker.onmessage = (event) => this.onMessage(event.data || {});
        this.worker.onerror = () => this.fail();
        this.worker.onmessageerror = () => this.fail();

        setTimeout(() => {
            if (!this.failed) {
                // Never became ready in time — stop using it.
                this.resolveReady(false);
            }
        }, READY_TIMEOUT_MS);
    }

    onMessage(reply) {
        if (reply.type === 'ready') {
            this.resolveReady(reply.hasFactory !== false);
            return;
        }
        const finish = this.pending.get(reply.id);
        if (finish) finish(reply);
    }

    fail() {
        this.failed = true;
        this.resolveReady(false);
        for (const finish of this.pending.values()) finish({ ok: false, files: {} });
        this.pending.clear();
    }

    run(job) {
        if (this.failed) return Promise.resolve({ ok: false, files: {} });
        return new Promise((resolve) => {
            let settled = false;
            const finish = (reply) => {
                if (settled) return;
                settled = true;
                this.pending.delete(job.id);
                resolve(reply);
            };
            this.pending.set(job.id, finish);
            try {
                this.worker.postMessage(job);
            } catch (err) {
                finish({ ok: false, files: {} });
                return;
            }
            setTimeout(() => {
                if (!settled) {
                    this.failed = true;
                    finish({ ok: false, files: {} });
                }
            }, JOB_TIMEOUT_MS);
        });
    }

    terminate() {
        try {
            if (this.worker) this.worker.terminate();
        } catch (e) {
            // ignore
        }
    }
}

function createPool() {
    const cpus = (typeof navigator !== 'undefined' && navigator.hardwareConcurrency) || MAX_WORKERS;
    const count = Math.min(MAX_WORKERS, Math.max(2, cpus - 1));
    const handles = Array.from({ length: count }, () => new WorkerHandle());
    return Promise.all(handles.map((handle) => handle.ready)).then((readies) => {
        if (!readies.every(Boolean)) {
            handles.forEach((handle) => handle.terminate());
            return null;
        }
        return handles;
    });
}

function getPool() {
    if (!poolPromise) poolPromise = createPool();
    return poolPromise;
}

/**
 * Run a batch of jobs. Returns an array of output-file maps aligned with jobs.
 * Uses workers when available and the batch is large; otherwise — and on any
 * worker failure — runs locally with identical results.
 * `explicitFactory` is used by the local path (tests / Node).
 */
export async function runJobs(jobs, explicitFactory = null) {
    if (!jobs || jobs.length === 0) return [];

    if (jobs.length >= WORKER_THRESHOLD && workersAvailable()) {
        try {
            const handles = await getPool();
            if (handles) {
                const results = new Array(jobs.length);
                let cursor = 0;
                await Promise.all(handles.map(async (handle) => {
                    while (cursor < jobs.length) {
                        const index = cursor;
                        cursor += 1;
                        const reply = await handle.run(jobs[index]);
                        if (!reply || reply.ok !== true || !reply.files) {
                            throw new Error('OpenSSL worker job failed');
                        }
                        results[index] = reply.files;
                    }
                }));
                return results;
            }
        } catch (err) {
            // Worker path failed — fall back to the main thread.
        }
    }

    const factory = resolveFactory(explicitFactory);
    const results = [];
    for (const job of jobs) {
        results.push(await runJobLocal(job, factory));
    }
    return results;
}
