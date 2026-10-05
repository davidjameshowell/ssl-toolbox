import { parseCertMetadata, parseCsrMetadata } from '../utils/cert.js';
import { saveToVault } from '../vault.js';
import { resolveFactory } from '../openssl/engine.js';
import { certDecodeJob, csrDecodeJob, runJobLocal } from '../openssl/jobs.js';
import { runJobs } from '../openssl/pool.js';

let decodeDebounceTimer;

export function buildLogicalChain(certs) {
    if (certs.length <= 1) return certs;

    let sorted = [];
    let remaining = [...certs];

    // Leaf = non-self-signed cert whose subject is nobody's issuer.
    // Self-signed roots must never qualify, regardless of input order.
    const leafIndex = remaining.findIndex(
        (c1) => c1.subject !== c1.issuer && !remaining.some((c2) => c2 !== c1 && c2.issuer === c1.subject)
    );
    if (leafIndex === -1) return remaining;

    let current = remaining.splice(leafIndex, 1)[0];
    sorted.push(current);

    while (remaining.length > 0) {
        const parentIndex = remaining.findIndex((cert) => cert.subject === current.issuer);
        if (parentIndex !== -1) {
            current = remaining.splice(parentIndex, 1)[0];
            sorted.push(current);
        } else {
            sorted = sorted.concat(remaining);
            break;
        }
    }

    return sorted;
}

function pubkeyLabel(meta) {
    if (!meta.pubkeyAlg && !meta.pubkeyBits) return '-';
    let label = meta.pubkeyAlg || 'Unknown';
    if (meta.pubkeyBits) label += ` · ${meta.pubkeyBits}-bit`;
    if (meta.curve) label += ` (${meta.curve})`;
    return label;
}

function expiryBadge(cert) {
    if (cert.expiryStatus === 'expired') {
        return ' <span class="ml-2 badge-expired">Expired</span>';
    }
    if (cert.expiryStatus === 'expiring') {
        return ' <span class="ml-2 badge-expiring">Expires soon</span>';
    }
    return '';
}

function renderCsrNode(csr, saveIndex) {
    const safeName = csr.cn || csr.org || 'Unknown CSR';

    return `
        <div class="relative z-10 flex">
            <div class="mt-5 w-16 shrink-0 flex justify-center z-10 relative">
                <div class="w-4 h-4 rounded-full bg-white dark:bg-slate-900 border-[3px] border-slate-300 dark:border-slate-600 ring-4 ring-slate-100 dark:ring-white/5"></div>
            </div>

            <details class="group bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 rounded-lg shadow-card overflow-hidden flex-1 z-10" open>
                <summary class="px-5 py-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-white/5 flex items-center justify-between transition-colors list-none">
                    <div class="flex items-center gap-4">
                        <svg class="w-8 h-8 text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-white/5 p-1.5 rounded-md border border-slate-200 dark:border-white/10" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <div class="flex flex-col">
                            <div class="flex items-center gap-3 mb-0.5">
                                <span class="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400">Certificate Signing Request</span>
                                <button type="button" data-action="save" data-save-index="${saveIndex}" class="btn-mini">Save to Vault</button>
                            </div>
                            <span class="font-semibold tracking-tight text-slate-900 dark:text-white text-lg">${safeName}</span>
                            <span class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">${csr.pubkeyAlg ? `${pubkeyLabel(csr)} public key` : 'Public key details unavailable'}</span>
                        </div>
                    </div>
                    <svg class="w-5 h-5 text-slate-400 dark:text-slate-500 transition-transform group-open:rotate-180" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </summary>

                <div class="px-5 py-4 border-t border-slate-200/70 dark:border-white/10 bg-slate-50/70 dark:bg-black/20">
                    <div class="kv">
                        <dl class="divide-y divide-slate-200 dark:divide-white/10">
                            <div class="kv-row"><dt class="kv-dt">Common Name</dt><dd class="kv-dd font-semibold">${csr.cn || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">SANs</dt><dd class="kv-dd">${csr.san || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Organization</dt><dd class="kv-dd">${csr.org || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Public Key</dt><dd class="kv-dd">${pubkeyLabel(csr)}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Signature Algorithm</dt><dd class="kv-dd font-mono tnum text-xs">${csr.sigAlg || '-'}</dd></div>
                        </dl>
                    </div>
                    <details class="group mt-2">
                        <summary class="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 select-none w-max">
                            <svg class="w-3 h-3 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
                            Raw OpenSSL Output
                        </summary>
                        <div class="mt-2"><pre class="raw-pre">${csr.rawDetails}</pre></div>
                    </details>
                </div>
            </details>
        </div>
    `;
}

function renderChainNode(cert, index, saveIndex) {
    const isLeaf = index === 0;
    const isRoot = cert.subject === cert.issuer;

    const label = isLeaf ? 'Leaf Certificate' : (isRoot ? 'Root CA' : 'Intermediate CA');
    const iconChip = 'bg-slate-100 dark:bg-white/5 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-white/10';
    const safeName = cert.cn || cert.org || 'Unknown Cert';

    return `
        <div class="relative z-10 flex">
            ${index > 0 ? '<div class="absolute -top-6 left-8 w-0.5 h-10 bg-slate-300 dark:bg-white/10 z-0"></div>' : ''}

            <div class="mt-5 w-16 shrink-0 flex justify-center z-10 relative">
                <div class="w-4 h-4 rounded-full bg-white dark:bg-slate-900 border-[3px] border-slate-300 dark:border-slate-600 ring-4 ring-slate-100 dark:ring-white/5"></div>
            </div>

            <details class="group bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 rounded-lg shadow-card overflow-hidden flex-1 z-10" ${isLeaf ? 'open' : ''}>
                <summary class="px-5 py-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-white/5 flex items-center justify-between transition-colors list-none">
                    <div class="flex items-center gap-4">
                        <svg class="w-8 h-8 ${iconChip} p-1.5 rounded-md border" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <div class="flex flex-col">
                            <div class="flex items-center gap-3 mb-0.5">
                                <span class="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500 dark:text-slate-400">${label}</span>
                                <button type="button" data-action="save" data-save-index="${saveIndex}" class="btn-mini">Save to Vault</button>
                            </div>
                            <span class="font-semibold tracking-tight text-slate-900 dark:text-white text-lg">${safeName}</span>
                            <span class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Issuer: ${cert.issuerCN || cert.issuer}</span>
                        </div>
                    </div>
                    <svg class="w-5 h-5 text-slate-400 dark:text-slate-500 transition-transform group-open:rotate-180" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </summary>

                <div class="px-5 py-4 border-t border-slate-200/70 dark:border-white/10 bg-slate-50/70 dark:bg-black/20">
                    <div class="kv">
                        <dl class="divide-y divide-slate-200 dark:divide-white/10">
                            <div class="kv-row"><dt class="kv-dt">Common Name</dt><dd class="kv-dd font-semibold">${cert.cn || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">SANs</dt><dd class="kv-dd">${cert.san || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Organization</dt><dd class="kv-dd">${cert.org || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Location</dt><dd class="kv-dd">${[cert.loc, cert.st, cert.c].filter(Boolean).join(', ') || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Valid From</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2"><span title="Raw GMT: ${cert.validFromRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${cert.validFrom || '-'}</span></dd></div>
                            <div class="kv-row"><dt class="kv-dt">Valid To</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2"><span title="Raw GMT: ${cert.validToRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${cert.validTo || '-'}</span>${expiryBadge(cert)}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Serial</dt><dd class="kv-dd font-mono tnum text-xs">${cert.serial || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Public Key</dt><dd class="kv-dd">${pubkeyLabel(cert)}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Signature Algorithm</dt><dd class="kv-dd font-mono tnum text-xs">${cert.sigAlg || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Key Usage</dt><dd class="kv-dd">${cert.keyUsage || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">Extended Key Usage</dt><dd class="kv-dd">${cert.extKeyUsage || '-'}</dd></div>
                            <div class="kv-row"><dt class="kv-dt">SHA-256 Fingerprint</dt><dd class="kv-dd font-mono tnum text-xs">${cert.fingerprintSha256 || '-'}</dd></div>
                        </dl>
                    </div>
                    <details class="group mt-2">
                        <summary class="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 select-none w-max">
                            <svg class="w-3 h-3 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
                            Raw OpenSSL Output
                        </summary>
                        <div class="mt-2"><pre class="raw-pre">${cert.rawDetails}</pre></div>
                    </details>
                </div>
            </details>
        </div>
    `;
}

/**
 * Decode base64 PEM certificate body to DER bytes (cross browser/Node).
 * Used for the WebCrypto SHA-256 fingerprint below.
 */
export function pemCertificateToDer(certPem) {
    const match = String(certPem || '').match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
    if (!match) return null;
    const b64 = match[1].replace(/\s+/g, '');
    if (!b64) return null;
    if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
    if (typeof atob === 'function') {
        const bin = atob(b64);
        const out = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
        return out;
    }
    return null;
}

/** SHA-256 fingerprint as an OpenSSL-shaped line, computed natively via WebCrypto. */
export async function sha256FingerprintLine(certPem) {
    const der = pemCertificateToDer(certPem);
    const subtle = globalThis.crypto && globalThis.crypto.subtle;
    if (!der || !subtle) return '';
    const digest = await subtle.digest('SHA-256', der);
    const hex = Array.from(new Uint8Array(digest))
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join(':');
    return `SHA256 Fingerprint=${hex}`;
}

export async function decodeCertBlock(certPem, explicitFactory = null) {
    const factory = resolveFactory(explicitFactory);
    let files;
    try {
        files = await runJobLocal(certDecodeJob(certPem, 'cert'), factory);
    } catch (err) {
        throw new Error('OpenSSL failed to parse the certificate.');
    }
    const textOut = files['/cert.txt'] || '';
    if (!textOut) {
        throw new Error('OpenSSL failed to parse the certificate.');
    }

    // Fingerprint via WebCrypto instead of a dedicated OpenSSL pass.
    let fpOut = '';
    try {
        fpOut = await sha256FingerprintLine(certPem);
    } catch (err) {
        // best-effort
    }

    // The combined dump doubles as the summary source and the extended text;
    // SAN is read from `textOut` since no separate `-ext` call is made.
    return { stdOut: textOut, sanOut: '', textOut, fpOut };
}

export async function decodeCsrBlock(csrPem, explicitFactory = null) {
    const factory = resolveFactory(explicitFactory);
    let files;
    try {
        files = await runJobLocal(csrDecodeJob(csrPem, 'csr'), factory);
    } catch (err) {
        throw new Error('OpenSSL failed to parse the certificate request.');
    }
    const textOut = files['/csr.txt'] || '';
    if (!textOut) {
        throw new Error('OpenSSL failed to parse the certificate request.');
    }
    const subjectLine = (textOut.match(/^subject=.*$/m) || [''])[0];
    return { subjectOut: subjectLine || textOut, textOut };
}

let decodeGeneration = 0;
const vaultSaveRegistry = [];

async function executePemChainDecode(blocks, generation) {
    const resultsContainer = document.getElementById('decodeResults');
    const loader = document.getElementById('decodeLoader');
    const parsedCerts = [];
    const parsedCsrs = [];

    try {
        // Build one serialisable job per PEM block and run them as a batch:
        // a worker pool handles large bundles off the main thread while small
        // bundles (and any worker failure) run locally — identical results.
        const jobs = blocks.map((block, index) => (
            block.includes('CERTIFICATE REQUEST')
                ? csrDecodeJob(block, `decode-${index}`)
                : certDecodeJob(block, `decode-${index}`)
        ));
        const results = await runJobs(jobs);
        if (generation !== decodeGeneration) return;

        for (let i = 0; i < blocks.length; i += 1) {
            const files = results[i] || {};
            if (blocks[i].includes('CERTIFICATE REQUEST')) {
                const textOut = files['/csr.txt'] || '';
                if (!textOut) throw new Error('OpenSSL failed to parse the certificate request.');
                const subjectLine = (textOut.match(/^subject=.*$/m) || [''])[0];
                const meta = parseCsrMetadata(textOut);
                meta.raw = blocks[i];
                meta.rawDetails = (subjectLine || textOut).trim();
                parsedCsrs.push(meta);
            } else {
                const textOut = files['/cert.txt'] || '';
                if (!textOut) throw new Error('OpenSSL failed to parse the certificate.');
                const fpOut = await sha256FingerprintLine(blocks[i]).catch(() => '');
                const meta = parseCertMetadata(textOut, '', textOut, fpOut);
                meta.raw = blocks[i];
                meta.rawDetails = textOut.trim();
                parsedCerts.push(meta);
            }
        }
        if (generation !== decodeGeneration) return;

        vaultSaveRegistry.length = 0;
        const sortedCerts = buildLogicalChain(parsedCerts);
        let html = '';
        sortedCerts.forEach((cert, index) => {
            const saveIndex = vaultSaveRegistry.push({ label: cert.cn || cert.org || 'Unknown Cert', type: 'cert', pem: cert.raw }) - 1;
            html += renderChainNode(cert, index, saveIndex);
        });
        parsedCsrs.forEach((csr) => {
            const saveIndex = vaultSaveRegistry.push({ label: csr.cn || csr.org || 'Unknown CSR', type: 'csr', pem: csr.raw }) - 1;
            html += renderCsrNode(csr, saveIndex);
        });
        resultsContainer.innerHTML = html;
    } catch (err) {
        console.error(err);
    } finally {
        if (generation === decodeGeneration) loader.classList.add('hidden');
    }
}

export function decodeEmptyNote(hasText) {
    if (!hasText) return '';
    return `<div class="rounded-2xl border border-dashed border-slate-300 dark:border-white/15 px-5 py-6 text-center">`
        + `<p class="text-sm font-semibold text-slate-700 dark:text-slate-300">No certificates or CSRs detected</p>`
        + `<p class="text-xs text-slate-500 dark:text-slate-400 mt-1">Paste a PEM block starting with <span class="font-mono">-----BEGIN CERTIFICATE-----</span> or pick one from the Vault.</p>`
        + `</div>`;
}

export function initDecoderTool() {
    const resultsContainer = document.getElementById('decodeResults');
    const loader = document.getElementById('decodeLoader');

    // Delegated vault-save handler: buttons carry a registry index instead of a
    // base64 PEM body embedded in the DOM.
    resultsContainer.addEventListener('click', (e) => {
        const btn = e.target.closest('[data-save-index]');
        if (!btn) return;
        e.preventDefault();
        const entry = vaultSaveRegistry[Number(btn.getAttribute('data-save-index'))];
        if (!entry) return;
        const added = saveToVault(entry.label, entry.type, entry.pem);
        const orig = btn.textContent;
        btn.textContent = added ? 'Saved' : 'Already in Vault';
        btn.disabled = true;
        setTimeout(() => {
            btn.textContent = orig;
            btn.disabled = false;
        }, 2000);
    });

    document.getElementById('pemInput').addEventListener('input', (e) => {
        const pemText = e.target.value;
        clearTimeout(decodeDebounceTimer);

        // Bump the generation so any in-flight decode is discarded.
        const generation = ++decodeGeneration;

        const blocks = pemText.match(/-----BEGIN (?:CERTIFICATE|CERTIFICATE REQUEST)-----[\s\S]*?-----END (?:CERTIFICATE|CERTIFICATE REQUEST)-----/g);
        if (!blocks || blocks.length === 0) {
            resultsContainer.innerHTML = decodeEmptyNote(pemText.trim() !== '');
            loader.classList.add('hidden');
            return;
        }

        loader.classList.remove('hidden');
        decodeDebounceTimer = setTimeout(() => {
            executePemChainDecode(blocks, generation);
        }, 500);
    });
}
