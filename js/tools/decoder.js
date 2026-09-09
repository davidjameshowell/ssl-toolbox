import { opensslCnf } from '../state.js';
import { parseCertMetadata, parseCsrMetadata } from '../utils/cert.js';
import { saveToVault } from '../vault.js';

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

function renderCsrNode(csr) {
    const safeName = csr.cn || csr.org || 'Unknown CSR';
    const b64Pem = window.btoa(unescape(encodeURIComponent(csr.raw)));

    return `
        <div class="relative z-10 flex">
            <div class="mt-5 w-16 shrink-0 flex justify-center z-10 relative">
                <div class="w-4 h-4 rounded-full bg-white dark:bg-slate-900 border-[3px] border-slate-300 dark:border-slate-600 ring-4 ring-slate-100 dark:ring-white/5"></div>
            </div>

            <details class="group bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 rounded-2xl shadow-card overflow-hidden flex-1 z-10" open>
                <summary class="px-5 py-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-white/5 flex items-center justify-between transition-colors list-none">
                    <div class="flex items-center gap-4">
                        <svg class="w-8 h-8 text-teal-500 dark:text-teal-400 bg-teal-50 dark:bg-teal-500/10 p-1.5 rounded-xl border border-teal-100 dark:border-teal-500/20" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        <div class="flex flex-col">
                            <div class="flex items-center gap-3 mb-0.5">
                                <span class="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400 dark:text-slate-500">Certificate Signing Request</span>
                                <button onclick="event.preventDefault(); saveToVaultFromUI('${safeName}', 'csr', '${b64Pem}', this)" class="btn-mini">Save to Vault</button>
                            </div>
                            <span class="font-bold tracking-tight text-slate-900 dark:text-white text-lg">${safeName}</span>
                            <span class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">${csr.pubkeyAlg ? `${pubkeyLabel(csr)} public key` : 'Public key details unavailable'}</span>
                        </div>
                    </div>
                    <svg class="w-5 h-5 text-slate-400 dark:text-slate-500 transition-transform group-open:rotate-180" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </summary>

                <div class="px-5 py-4 border-t border-slate-200/70 dark:border-white/10 bg-slate-50/70 dark:bg-black/20">
                    <div class="kv">
                        <dl class="divide-y divide-slate-100 dark:divide-white/5">
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

function renderChainNode(cert, index) {
    const isLeaf = index === 0;
    const isRoot = cert.subject === cert.issuer;

    const label = isLeaf ? 'Leaf Certificate' : (isRoot ? 'Root CA' : 'Intermediate CA');
    const iconColor = isLeaf ? 'text-sky-500 dark:text-sky-400' : (isRoot ? 'text-amber-500 dark:text-amber-400' : 'text-violet-500 dark:text-violet-400');
    const iconChip = isLeaf ? 'bg-sky-50 dark:bg-sky-500/10 border-sky-100 dark:border-sky-500/20' : (isRoot ? 'bg-amber-50 dark:bg-amber-500/10 border-amber-100 dark:border-amber-500/20' : 'bg-violet-50 dark:bg-violet-500/10 border-violet-100 dark:border-violet-500/20');
    const safeName = cert.cn || cert.org || 'Unknown Cert';
    const b64Pem = window.btoa(unescape(encodeURIComponent(cert.raw)));

    return `
        <div class="relative z-10 flex">
            ${index > 0 ? '<div class="absolute -top-6 left-8 w-0.5 h-10 bg-slate-300 dark:bg-white/10 z-0"></div>' : ''}

            <div class="mt-5 w-16 shrink-0 flex justify-center z-10 relative">
                <div class="w-4 h-4 rounded-full bg-white dark:bg-slate-900 border-[3px] border-slate-300 dark:border-slate-600 ring-4 ring-slate-100 dark:ring-white/5"></div>
            </div>

            <details class="group bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 rounded-2xl shadow-card overflow-hidden flex-1 z-10" ${isLeaf ? 'open' : ''}>
                <summary class="px-5 py-4 cursor-pointer hover:bg-slate-50 dark:hover:bg-white/5 flex items-center justify-between transition-colors list-none">
                    <div class="flex items-center gap-4">
                        <svg class="w-8 h-8 ${iconColor} ${iconChip} p-1.5 rounded-xl border" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <div class="flex flex-col">
                            <div class="flex items-center gap-3 mb-0.5">
                                <span class="text-[11px] font-bold uppercase tracking-[0.14em] text-slate-400 dark:text-slate-500">${label}</span>
                                <button onclick="event.preventDefault(); saveToVaultFromUI('${safeName}', 'cert', '${b64Pem}', this)" class="btn-mini">Save to Vault</button>
                            </div>
                            <span class="font-bold tracking-tight text-slate-900 dark:text-white text-lg">${safeName}</span>
                            <span class="text-xs text-slate-500 dark:text-slate-400 mt-0.5">Issuer: ${cert.issuerCN || cert.issuer}</span>
                        </div>
                    </div>
                    <svg class="w-5 h-5 text-slate-400 dark:text-slate-500 transition-transform group-open:rotate-180" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </summary>

                <div class="px-5 py-4 border-t border-slate-200/70 dark:border-white/10 bg-slate-50/70 dark:bg-black/20">
                    <div class="kv">
                        <dl class="divide-y divide-slate-100 dark:divide-white/5">
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

function resolveDecoderFactory(explicitFactory) {
    if (explicitFactory) return explicitFactory;
    if (typeof window !== 'undefined' && typeof window.createOpenSSL !== 'undefined') {
        return window.createOpenSSL;
    }
    throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
}

export async function decodeCertBlock(certPem, explicitFactory = null) {
    const factory = resolveDecoderFactory(explicitFactory);
    const moduleDec = await factory();
    moduleDec.FS.writeFile('/input.pem', certPem);
    try {
        moduleDec.callMain(['x509', '-in', '/input.pem', '-noout', '-subject', '-issuer', '-dates', '-serial', '-out', '/std.txt']);
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('OpenSSL failed to parse the certificate.');
    }
    if (typeof process !== 'undefined' && process && process.exitCode === 1) {
        process.exitCode = 0;
        throw new Error('OpenSSL failed to parse the certificate.');
    }
    let stdOut;
    try {
        stdOut = moduleDec.FS.readFile('/std.txt', { encoding: 'utf8' });
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('OpenSSL failed to parse the certificate.');
    }

    let sanOut = '';
    try {
        const moduleSan = await factory();
        moduleSan.FS.writeFile('/input.pem', certPem);
        moduleSan.callMain(['x509', '-in', '/input.pem', '-noout', '-ext', 'subjectAltName', '-out', '/san.txt']);
        sanOut = moduleSan.FS.readFile('/san.txt', { encoding: 'utf8' });
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        // certs without SAN throw — not fatal
    }

    // Extended details are best-effort: a valid cert always yields stdOut,
    // but text/fingerprint extras must never break the decode flow.
    let textOut = '';
    try {
        const moduleText = await factory();
        moduleText.FS.writeFile('/input.pem', certPem);
        moduleText.callMain(['x509', '-in', '/input.pem', '-noout', '-text', '-out', '/text.txt']);
        textOut = moduleText.FS.readFile('/text.txt', { encoding: 'utf8' });
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
    }

    let fpOut = '';
    try {
        const moduleFp = await factory();
        moduleFp.FS.writeFile('/input.pem', certPem);
        moduleFp.callMain(['x509', '-in', '/input.pem', '-noout', '-fingerprint', '-sha256', '-out', '/fp.txt']);
        fpOut = moduleFp.FS.readFile('/fp.txt', { encoding: 'utf8' });
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
    }

    if (typeof process !== 'undefined' && process) process.exitCode = 0;
    return { stdOut, sanOut, textOut, fpOut };
}

export async function decodeCsrBlock(csrPem, explicitFactory = null) {
    const factory = resolveDecoderFactory(explicitFactory);
    const moduleSubj = await factory();
    moduleSubj.FS.writeFile('/input.csr', csrPem);
    moduleSubj.FS.writeFile('/openssl.cnf', opensslCnf);
    moduleSubj.ENV.OPENSSL_CONF = '/openssl.cnf';
    try {
        moduleSubj.callMain(['req', '-in', '/input.csr', '-noout', '-subject', '-out', '/subj.txt', '-config', '/openssl.cnf']);
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('OpenSSL failed to parse the certificate request.');
    }
    let subjectOut = '';
    try {
        subjectOut = moduleSubj.FS.readFile('/subj.txt', { encoding: 'utf8' });
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        throw new Error('OpenSSL failed to parse the certificate request.');
    }

    let textOut = '';
    try {
        const moduleText = await factory();
        moduleText.FS.writeFile('/input.csr', csrPem);
        moduleText.FS.writeFile('/openssl.cnf', opensslCnf);
        moduleText.ENV.OPENSSL_CONF = '/openssl.cnf';
        moduleText.callMain(['req', '-in', '/input.csr', '-noout', '-text', '-out', '/csrtext.txt', '-config', '/openssl.cnf']);
        textOut = moduleText.FS.readFile('/csrtext.txt', { encoding: 'utf8' });
    } catch (e) {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
        // subject parsed fine; extended text is best-effort
    }
    if (typeof process !== 'undefined' && process) process.exitCode = 0;
    return { subjectOut, textOut };
}

async function executePemChainDecode(blocks) {
    const resultsContainer = document.getElementById('decodeResults');
    const loader = document.getElementById('decodeLoader');
    const parsedCerts = [];
    const parsedCsrs = [];

    try {
        for (let i = 0; i < blocks.length; i += 1) {
            if (blocks[i].includes('CERTIFICATE REQUEST')) {
                const { subjectOut, textOut } = await decodeCsrBlock(blocks[i]);
                const meta = parseCsrMetadata(textOut);
                meta.raw = blocks[i];
                meta.rawDetails = (subjectOut || '').trim();
                parsedCsrs.push(meta);
            } else {
                const { stdOut, sanOut, textOut, fpOut } = await decodeCertBlock(blocks[i]);
                const meta = parseCertMetadata(stdOut, sanOut, textOut, fpOut);
                meta.raw = blocks[i];
                meta.rawDetails = stdOut.trim();
                parsedCerts.push(meta);
            }
        }

        const sortedCerts = buildLogicalChain(parsedCerts);
        resultsContainer.innerHTML = '';
        sortedCerts.forEach((cert, index) => {
            resultsContainer.innerHTML += renderChainNode(cert, index);
        });
        parsedCsrs.forEach((csr) => {
            resultsContainer.innerHTML += renderCsrNode(csr);
        });
    } catch (err) {
        console.error(err);
    } finally {
        loader.classList.add('hidden');
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
    window.saveToVaultFromUI = (label, type, rawPem, btn) => {
        const pem = decodeURIComponent(escape(window.atob(rawPem)));
        const added = saveToVault(label, type, pem);
        if (btn) {
            const orig = btn.textContent;
            btn.textContent = added ? 'Saved' : 'Already in Vault';
            btn.disabled = true;
            setTimeout(() => {
                btn.textContent = orig;
                btn.disabled = false;
            }, 2000);
        }
    };

    document.getElementById('pemInput').addEventListener('input', (e) => {
        const pemText = e.target.value;
        const resultsContainer = document.getElementById('decodeResults');
        const loader = document.getElementById('decodeLoader');

        clearTimeout(decodeDebounceTimer);

        const blocks = pemText.match(/-----BEGIN (?:CERTIFICATE|CERTIFICATE REQUEST)-----[\s\S]*?-----END (?:CERTIFICATE|CERTIFICATE REQUEST)-----/g);
        if (!blocks || blocks.length === 0) {
            resultsContainer.innerHTML = decodeEmptyNote(pemText.trim() !== '');
            loader.classList.add('hidden');
            return;
        }

        loader.classList.remove('hidden');
        decodeDebounceTimer = setTimeout(() => {
            executePemChainDecode(blocks);
        }, 500);
    });
}
