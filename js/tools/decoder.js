import { parseCertMetadata } from '../utils/cert.js';
import { saveToVault } from '../vault.js';

let decodeDebounceTimer;

function buildLogicalChain(certs) {
    if (certs.length <= 1) return certs;

    let sorted = [];
    let remaining = [...certs];

    const leafIndex = remaining.findIndex((c1) => !remaining.some((c2) => c2.issuer === c1.subject && c1.subject !== c1.issuer));
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

function renderChainNode(cert, index) {
    const isLeaf = index === 0;
    const isRoot = cert.subject === cert.issuer;

    const label = isLeaf ? 'Leaf Certificate' : (isRoot ? 'Root CA' : 'Intermediate CA');
    const iconColor = isLeaf ? 'text-blue-500' : (isRoot ? 'text-amber-500' : 'text-purple-500');
    const safeName = cert.cn || cert.org || 'Unknown Cert';
    const b64Pem = window.btoa(unescape(encodeURIComponent(cert.raw)));

    return `
        <div class="relative z-10 flex">
            ${index > 0 ? '<div class="absolute -top-6 left-8 w-0.5 h-10 bg-slate-300 z-0"></div>' : ''}

            <div class="mt-5 w-16 shrink-0 flex justify-center z-10 relative">
                <div class="w-4 h-4 rounded-full bg-white border-[3px] border-slate-300 ring-4 ring-slate-50"></div>
            </div>

            <details class="group bg-white border border-slate-200 rounded-xl shadow-sm overflow-hidden flex-1 z-10" ${isLeaf ? 'open' : ''}>
                <summary class="px-5 py-4 cursor-pointer hover:bg-slate-50 flex items-center justify-between transition-colors list-none">
                    <div class="flex items-center gap-4">
                        <svg class="w-8 h-8 ${iconColor} bg-slate-50 p-1.5 rounded-lg border border-slate-100" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                        <div class="flex flex-col">
                            <div class="flex items-center gap-3 mb-0.5">
                                <span class="text-[10px] font-bold uppercase tracking-wider text-slate-400">${label}</span>
                                <button onclick="event.preventDefault(); saveToVaultFromUI('${safeName}', 'cert', '${b64Pem}')" class="text-[10px] bg-blue-50 text-blue-600 border border-blue-200 px-2 py-0.5 rounded hover:bg-blue-100 transition-colors shadow-sm">Save to Vault</button>
                            </div>
                            <span class="font-bold text-slate-800 text-lg">${safeName}</span>
                            <span class="text-xs text-slate-500 mt-0.5">Issuer: ${cert.issuerCN || cert.issuer}</span>
                        </div>
                    </div>
                    <svg class="w-5 h-5 text-slate-400 transition-transform group-open:rotate-180" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                    </svg>
                </summary>

                <div class="px-5 py-4 border-t border-slate-100 bg-slate-50/50">
                    <div class="bg-white border border-slate-200 rounded-lg overflow-hidden mb-4 shadow-sm text-sm">
                        <dl class="divide-y divide-slate-100">
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">Common Name</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-semibold break-all">${cert.cn || '-'}</dd></div>
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">SANs</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 break-all">${cert.san || '-'}</dd></div>
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">Organization</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 break-all">${cert.org || '-'}</dd></div>
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">Location</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 break-all">${[cert.loc, cert.st, cert.c].filter(Boolean).join(', ') || '-'}</dd></div>
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">Valid From</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2"><span title="Raw GMT: ${cert.validFromRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${cert.validFrom || '-'}</span></dd></div>
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">Valid To</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2"><span title="Raw GMT: ${cert.validToRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${cert.validTo || '-'}</span></dd></div>
                            <div class="px-4 py-2 sm:grid sm:grid-cols-3 sm:gap-4 sm:px-5 hover:bg-slate-50"><dt class="font-medium text-slate-500">Serial</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${cert.serial || '-'}</dd></div>
                        </dl>
                    </div>
                    <details class="group mt-2">
                        <summary class="flex items-center gap-2 cursor-pointer text-xs font-medium text-slate-500 hover:text-slate-800 select-none w-max">
                            <svg class="w-3 h-3 transition-transform group-open:rotate-90" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" /></svg>
                            Raw OpenSSL Output
                        </summary>
                        <div class="mt-2"><pre class="bg-slate-800 text-emerald-400 rounded-lg p-3 text-[11px] font-mono overflow-x-auto whitespace-pre-wrap break-words">${cert.rawDetails}</pre></div>
                    </details>
                </div>
            </details>
        </div>
    `;
}

async function executePemChainDecode(certBlocks) {
    const resultsContainer = document.getElementById('decodeResults');
    const loader = document.getElementById('decodeLoader');
    const parsedCerts = [];

    try {
        for (let i = 0; i < certBlocks.length; i += 1) {
            const moduleDec = await window.createOpenSSL();
            moduleDec.FS.writeFile('/input.pem', certBlocks[i]);
            moduleDec.callMain(['x509', '-in', '/input.pem', '-noout', '-subject', '-issuer', '-dates', '-serial', '-out', '/std.txt']);
            const stdOut = moduleDec.FS.readFile('/std.txt', { encoding: 'utf8' });

            let sanOut = '';
            try {
                const moduleSan = await window.createOpenSSL();
                moduleSan.FS.writeFile('/input.pem', certBlocks[i]);
                moduleSan.callMain(['x509', '-in', '/input.pem', '-noout', '-ext', 'subjectAltName', '-out', '/san.txt']);
                sanOut = moduleSan.FS.readFile('/san.txt', { encoding: 'utf8' });
            } catch (e) {
                // noop
            }

            const meta = parseCertMetadata(stdOut, sanOut);
            meta.raw = certBlocks[i];
            meta.rawDetails = stdOut.trim();
            parsedCerts.push(meta);
        }

        const sortedCerts = buildLogicalChain(parsedCerts);
        resultsContainer.innerHTML = '';
        sortedCerts.forEach((cert, index) => {
            resultsContainer.innerHTML += renderChainNode(cert, index);
        });
    } catch (err) {
        console.error(err);
    } finally {
        loader.classList.add('hidden');
    }
}

export function initDecoderTool() {
    window.saveToVaultFromUI = (label, type, rawPem) => {
        const pem = decodeURIComponent(escape(window.atob(rawPem)));
        saveToVault(label, type, pem);
        alert(`Saved "${label}" to Memory Vault!`);
    };

    document.getElementById('pemInput').addEventListener('input', (e) => {
        const pemText = e.target.value;
        const resultsContainer = document.getElementById('decodeResults');
        const loader = document.getElementById('decodeLoader');

        clearTimeout(decodeDebounceTimer);

        const certBlocks = pemText.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
        if (!certBlocks || certBlocks.length === 0) {
            resultsContainer.innerHTML = '';
            loader.classList.add('hidden');
            return;
        }

        loader.classList.remove('hidden');
        decodeDebounceTimer = setTimeout(() => {
            executePemChainDecode(certBlocks);
        }, 500);
    });
}
