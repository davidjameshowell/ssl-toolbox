import { appState, opensslCnf } from '../state.js';
import { parseCertMetadata } from '../utils/cert.js';
import { downloadFile } from '../utils/download.js';
import { saveToVault } from '../vault.js';

function resolvePfxFactory(explicitFactory) {
    if (explicitFactory) return explicitFactory;
    if (typeof window !== 'undefined' && typeof window.createOpenSSL !== 'undefined') {
        return window.createOpenSSL;
    }
    throw new Error('OpenSSL factory unavailable. Pass createOpenSSL explicitly in Node/tests.');
}

export async function extractPfxData(pfxBytes, password, explicitFactory = null) {
    const factory = resolvePfxFactory(explicitFactory);
    const pfxData = pfxBytes instanceof Uint8Array ? pfxBytes : new Uint8Array(pfxBytes);
    const hasPassword = password && password !== '';
    const passArgs = (mod) => {
        if (hasPassword) {
            mod.FS.writeFile('/passin.txt', password);
            return ['-passin', 'file:/passin.txt'];
        }
        return ['-passin', 'pass:'];
    };

    const resetExit = () => {
        if (typeof process !== 'undefined' && process) process.exitCode = 0;
    };

    try {
        const moduleCert = await factory();
        moduleCert.FS.writeFile('/mycert.pfx', pfxData);
        moduleCert.FS.writeFile('/openssl.cnf', opensslCnf);
        moduleCert.ENV.OPENSSL_CONF = '/openssl.cnf';
        moduleCert.callMain(['pkcs12', '-legacy', '-in', '/mycert.pfx', '-nokeys', '-out', '/cert.pem', ...passArgs(moduleCert)]);
        const certPem = moduleCert.FS.readFile('/cert.pem', { encoding: 'utf8' });

        // A PFX can bundle a full chain — split every certificate block so the
        // UI can display each one instead of silently showing only the first.
        const certs = certPem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [certPem];

        const readDetails = async (pem) => {
            const moduleView = await factory();
            moduleView.FS.writeFile('/cert.pem', pem);
            moduleView.callMain(['x509', '-in', '/cert.pem', '-noout', '-subject', '-issuer', '-dates', '-out', '/details.txt']);
            return moduleView.FS.readFile('/details.txt', { encoding: 'utf8' });
        };
        const details = await readDetails(certs[0]);
        const chain = [{ pem: certs[0], details }];
        for (let i = 1; i < certs.length; i += 1) {
            chain.push({ pem: certs[i], details: await readDetails(certs[i]) });
        }

        // Certs-only archives (no private key) are valid — don't fail the
        // whole extraction when the key bag is absent.
        let keyPem = '';
        try {
            const moduleKey = await factory();
            moduleKey.FS.writeFile('/mycert.pfx', pfxData);
            moduleKey.FS.writeFile('/openssl.cnf', opensslCnf);
            moduleKey.ENV.OPENSSL_CONF = '/openssl.cnf';
            moduleKey.callMain(['pkcs12', '-legacy', '-in', '/mycert.pfx', '-nocerts', '-nodes', '-out', '/key.pem', ...passArgs(moduleKey)]);
            keyPem = moduleKey.FS.readFile('/key.pem', { encoding: 'utf8' });
            if (!keyPem.includes('PRIVATE KEY')) keyPem = '';
        } catch (keyErr) {
            keyPem = '';
        }

        resetExit();
        return { certPem, certs, keyPem, details, chain };
    } catch (err) {
        resetExit();
        throw err;
    }
}

async function processVault(file, password) {
    const statusDiv = document.getElementById('status');
    const certViewer = document.getElementById('certViewer');
    const unlockBtn = document.getElementById('unlockBtn');

    try {
        statusDiv.className = 'status-busy';
        statusDiv.innerText = 'Extracting archive contents…';
        unlockBtn.disabled = true;

        const buffer = await file.arrayBuffer();
        const pfxData = new Uint8Array(buffer);

        const { certPem, certs, keyPem, details: parsedDetails, chain } = await extractPfxData(pfxData, password);
        appState.extractedCertPem = certPem;
        appState.extractedKeyPem = keyPem;

        document.getElementById('pfxDetailsText').innerText = parsedDetails.trim();
        const meta = parseCertMetadata(parsedDetails, '');

        document.getElementById('pfxCN').innerText = meta.cn;
        document.getElementById('pfxOrg').innerText = meta.org;
        document.getElementById('pfxIssuer').innerText = meta.issuer;

        document.getElementById('pfxValidFrom').innerHTML = `<span title="Raw GMT: ${meta.validFromRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${meta.validFrom}</span>`;
        document.getElementById('pfxValidTo').innerHTML = `<span title="Raw GMT: ${meta.validToRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${meta.validTo}</span>`;

        const chainBox = document.getElementById('pfxChain');
        if (chainBox) {
            if (chain.length > 1) {
                chainBox.classList.remove('hidden');
                chainBox.innerHTML = `<h4 class="text-sm font-semibold text-slate-700 dark:text-slate-300 mb-2">Certificate chain (${chain.length})</h4>` + chain.map((entry, i) => {
                    const m = parseCertMetadata(entry.details, '');
                    const badge = i === 0
                        ? '<span class="ml-2 badge-leaf">Leaf</span>'
                        : '<span class="ml-2 badge-chain">Chain</span>';
                    return `<div class="mini-card">`
                        + `<span class="font-semibold text-slate-900 dark:text-slate-100 break-all">${m.cn || m.org || `Certificate ${i + 1}`}</span>${badge}`
                        + `<div class="text-xs text-slate-500 dark:text-slate-400 mt-0.5 break-all">Issuer: ${m.issuerCN || m.issuer || '-'}</div>`
                        + `</div>`;
                }).join('');
            } else {
                chainBox.classList.add('hidden');
                chainBox.innerHTML = '';
            }
        }

        certViewer.classList.remove('hidden');
        statusDiv.className = 'status-ok';
        const hasKey = appState.extractedKeyPem && appState.extractedKeyPem.length > 0;
        statusDiv.innerText = hasKey
            ? `Vault unlocked successfully. ${certs.length} certificate${certs.length === 1 ? '' : 's'} + private key found.`
            : `Vault unlocked successfully. ${certs.length} certificate${certs.length === 1 ? '' : 's'} found (no private key in archive).`;
        document.getElementById('passwordGroup').classList.add('hidden');
        unlockBtn.style.display = 'none';

        const safeName = meta.cn || file.name;
        saveToVault(`${safeName}`, 'cert', appState.extractedCertPem);
        if (hasKey) {
            saveToVault(`${safeName} (key)`, 'key', appState.extractedKeyPem);
        }
        document.getElementById('pfxPass').value = '';
    } catch (err) {
        statusDiv.className = 'status-error';
        statusDiv.innerText = 'Error: invalid password or corrupted file.';
    } finally {
        unlockBtn.disabled = false;
    }
}

export function initPfxTool() {
    document.getElementById('pfxFile').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        const statusDiv = document.getElementById('status');
        const pwdGroup = document.getElementById('passwordGroup');
        const unlockBtn = document.getElementById('unlockBtn');

        document.getElementById('certViewer').classList.add('hidden');
        pwdGroup.classList.add('hidden');
        pwdGroup.classList.remove('opacity-100');
        unlockBtn.classList.add('hidden');
        unlockBtn.style.display = 'none';
        document.getElementById('pfxPass').value = '';

        if (!file) return;

        statusDiv.classList.remove('hidden');
        if (typeof window.createOpenSSL === 'undefined') {
            statusDiv.className = 'status-warn';
            statusDiv.innerText = 'OpenSSL is still loading — pick the file again in a moment.';
            return;
        }

        statusDiv.className = 'status-busy';
        statusDiv.innerText = 'Checking encryption status…';

        const buffer = await file.arrayBuffer();
        const pfxData = new Uint8Array(buffer);

        const testModule = await window.createOpenSSL();
        testModule.FS.writeFile('/test.pfx', pfxData);
        testModule.FS.writeFile('/openssl.cnf', opensslCnf);
        testModule.ENV.OPENSSL_CONF = '/openssl.cnf';

        let isEncrypted = true;
        try {
            testModule.callMain(['pkcs12', '-legacy', '-in', '/test.pfx', '-nokeys', '-out', '/test_cert.pem', '-passin', 'pass:']);
            const stat = testModule.FS.stat('/test_cert.pem');
            if (stat && stat.size > 0) isEncrypted = false;
        } catch (err) {
            // noop
        }

        if (isEncrypted) {
            statusDiv.className = 'status-warn';
            statusDiv.innerText = 'File is password protected.';
            pwdGroup.classList.remove('hidden');
            setTimeout(() => pwdGroup.classList.add('opacity-100'), 10);
            unlockBtn.classList.remove('hidden');
            unlockBtn.style.display = 'flex';
        } else {
            statusDiv.className = 'status-busy';
            statusDiv.innerText = 'No password required. Processing…';
            await processVault(file, '');
        }
    });

    document.getElementById('unlockBtn').addEventListener('click', async () => {
        const file = document.getElementById('pfxFile').files[0];
        const password = document.getElementById('pfxPass').value;
        await processVault(file, password);
    });

    document.getElementById('downloadBtn').addEventListener('click', () => {
        if (!appState.extractedCertPem) return;
        downloadFile(appState.extractedCertPem, 'cert.pem');
        if (appState.extractedKeyPem) {
            downloadFile(appState.extractedKeyPem, 'key.pem');
        }
    });
}
