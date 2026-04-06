import { appState, opensslCnf } from '../state.js';
import { parseCertMetadata } from '../utils/cert.js';
import { downloadFile } from '../utils/download.js';
import { saveToVault } from '../vault.js';

async function processVault(file, password) {
    const statusDiv = document.getElementById('status');
    const certViewer = document.getElementById('certViewer');
    const unlockBtn = document.getElementById('unlockBtn');

    try {
        statusDiv.className = 'text-center font-medium mt-4 text-sm text-slate-500 animate-pulse';
        statusDiv.innerText = 'Extracting vault contents...';
        unlockBtn.disabled = true;

        const buffer = await file.arrayBuffer();
        const pfxData = new Uint8Array(buffer);

        const moduleCert = await window.createOpenSSL();
        moduleCert.FS.writeFile('/mycert.pfx', pfxData);
        moduleCert.FS.writeFile('/openssl.cnf', opensslCnf);
        moduleCert.ENV.OPENSSL_CONF = '/openssl.cnf';
        moduleCert.callMain(['pkcs12', '-legacy', '-in', '/mycert.pfx', '-nokeys', '-out', '/cert.pem', '-passin', `pass:${password}`]);
        appState.extractedCertPem = moduleCert.FS.readFile('/cert.pem', { encoding: 'utf8' });

        const moduleView = await window.createOpenSSL();
        moduleView.FS.writeFile('/cert.pem', appState.extractedCertPem);
        moduleView.callMain(['x509', '-in', '/cert.pem', '-noout', '-subject', '-issuer', '-dates', '-out', '/details.txt']);
        const parsedDetails = moduleView.FS.readFile('/details.txt', { encoding: 'utf8' });

        const moduleKey = await window.createOpenSSL();
        moduleKey.FS.writeFile('/mycert.pfx', pfxData);
        moduleKey.FS.writeFile('/openssl.cnf', opensslCnf);
        moduleKey.ENV.OPENSSL_CONF = '/openssl.cnf';
        moduleKey.callMain(['pkcs12', '-legacy', '-in', '/mycert.pfx', '-nocerts', '-nodes', '-out', '/key.pem', '-passin', `pass:${password}`]);
        appState.extractedKeyPem = moduleKey.FS.readFile('/key.pem', { encoding: 'utf8' });

        document.getElementById('pfxDetailsText').innerText = parsedDetails.trim();
        const meta = parseCertMetadata(parsedDetails, '');

        document.getElementById('pfxCN').innerText = meta.cn;
        document.getElementById('pfxOrg').innerText = meta.org;
        document.getElementById('pfxIssuer').innerText = meta.issuer;

        document.getElementById('pfxValidFrom').innerHTML = `<span title="Raw GMT: ${meta.validFromRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${meta.validFrom}</span>`;
        document.getElementById('pfxValidTo').innerHTML = `<span title="Raw GMT: ${meta.validToRaw}" class="cursor-help border-b border-dotted border-slate-400 hover:border-slate-600 pb-0.5 transition-colors">${meta.validTo}</span>`;

        certViewer.classList.remove('hidden');
        statusDiv.className = 'text-center font-medium mt-4 text-sm text-emerald-600';
        statusDiv.innerText = '✓ Vault unlocked successfully.';
        document.getElementById('passwordGroup').classList.add('hidden');
        unlockBtn.style.display = 'none';

        const safeName = meta.cn || file.name;
        saveToVault(`${safeName}`, 'cert', appState.extractedCertPem);
        if (appState.extractedKeyPem && appState.extractedKeyPem.length > 0) {
            saveToVault(`${safeName}`, 'key', appState.extractedKeyPem);
        }
    } catch (err) {
        statusDiv.className = 'text-center font-medium mt-4 text-sm text-red-600';
        statusDiv.innerText = '❌ Error: Invalid password or corrupted file.';
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

        if (typeof window.createOpenSSL === 'undefined') {
            alert('OpenSSL WebAssembly is loading. Try again in a moment.');
            return;
        }

        statusDiv.className = 'text-center font-medium mt-4 text-sm text-slate-500 animate-pulse';
        statusDiv.innerText = 'Checking encryption status...';
        statusDiv.classList.remove('hidden');

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
            statusDiv.innerText = 'File is password protected.';
            statusDiv.classList.remove('animate-pulse');
            pwdGroup.classList.remove('hidden');
            setTimeout(() => pwdGroup.classList.add('opacity-100'), 10);
            unlockBtn.classList.remove('hidden');
            unlockBtn.style.display = 'flex';
        } else {
            statusDiv.innerText = 'No password required. Processing...';
            await processVault(file, '');
        }
    });

    document.getElementById('unlockBtn').addEventListener('click', async () => {
        const file = document.getElementById('pfxFile').files[0];
        const password = document.getElementById('pfxPass').value;
        await processVault(file, password);
    });

    document.getElementById('downloadBtn').addEventListener('click', () => {
        if (appState.extractedCertPem && appState.extractedKeyPem) {
            downloadFile(appState.extractedCertPem, 'cert.pem');
            downloadFile(appState.extractedKeyPem, 'key.pem');
        }
    });
}
