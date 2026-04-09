/* global openpgp */

async function generatePGPKey() {
    const status = document.getElementById('pgpStatus');
    const resultsDiv = document.getElementById('pgpResults');
    const btn = document.getElementById('pgpGenerateBtn');

    const name = document.getElementById('pgpName').value.trim();
    const email = document.getElementById('pgpEmail').value.trim();
    const keyType = document.getElementById('pgpKeyType').value;
    const passphrase = document.getElementById('pgpPassphrase').value;

    if (!name || !email) {
        status.textContent = '❌ Name and email are required.';
        status.className = 'text-center font-medium mt-4 text-sm text-red-600';
        status.classList.remove('hidden');
        return;
    }

    btn.disabled = true;
    status.textContent = 'Generating PGP key pair...';
    status.className = 'text-center font-medium mt-4 text-sm text-slate-500 animate-pulse';
    status.classList.remove('hidden');
    resultsDiv.classList.add('hidden');

    try {
        if (typeof openpgp === 'undefined') throw new Error('OpenPGP.js library not loaded.');

        const options = {
            userIDs: [{ name, email }],
            passphrase: passphrase || undefined,
        };

        if (keyType === 'rsa2048') { options.type = 'rsa'; options.rsaBits = 2048; }
        else if (keyType === 'rsa4096') { options.type = 'rsa'; options.rsaBits = 4096; }
        else if (keyType === 'ecc') { options.type = 'ecc'; options.curve = 'curve25519'; }

        const { privateKey, publicKey } = await openpgp.generateKey(options);

        document.getElementById('pgpOutputPublic').textContent = publicKey;
        document.getElementById('pgpOutputPrivate').textContent = privateKey;
        resultsDiv.classList.remove('hidden');

        const parsed = await openpgp.readKey({ armoredKey: publicKey });
        const fp = parsed.getFingerprint().toUpperCase().match(/.{4}/g).join(' ');
        const created = parsed.getCreationTime().toLocaleString();
        const algo = parsed.getAlgorithmInfo();

        document.getElementById('pgpFingerprint').textContent = fp;
        document.getElementById('pgpCreated').textContent = created;
        document.getElementById('pgpAlgorithm').textContent = `${algo.algorithm.toUpperCase()} ${algo.bits || algo.curve || ''}`;

        status.textContent = '✓ PGP key pair generated successfully.';
        status.className = 'text-center font-medium mt-4 text-sm text-emerald-600';
    } catch (err) {
        status.textContent = `❌ Error: ${err.message || 'Key generation failed.'}`;
        status.className = 'text-center font-medium mt-4 text-sm text-red-600';
    } finally {
        btn.disabled = false;
    }
}

async function inspectPGPKey() {
    const input = document.getElementById('pgpInspectInput').value.trim();
    const resultsDiv = document.getElementById('pgpInspectResults');
    if (!input) return;

    try {
        if (typeof openpgp === 'undefined') throw new Error('OpenPGP.js library not loaded.');

        const key = await openpgp.readKey({ armoredKey: input });
        const fp = key.getFingerprint().toUpperCase().match(/.{4}/g).join(' ');
        const created = key.getCreationTime().toLocaleString();
        const algo = key.getAlgorithmInfo();
        const users = key.getUserIDs();

        resultsDiv.innerHTML = `
            <div class="bg-white border border-slate-200 rounded-lg overflow-hidden text-sm">
                <dl class="divide-y divide-slate-100">
                    <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">User IDs</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2">${users.map(u => u.replace(/</g, '&lt;')).join('<br>')}</dd></div>
                    <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-slate-50"><dt class="font-medium text-slate-500">Fingerprint</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs">${fp}</dd></div>
                    <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">Algorithm</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2">${algo.algorithm.toUpperCase()} ${algo.bits || algo.curve || ''}</dd></div>
                    <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-slate-50"><dt class="font-medium text-slate-500">Created</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2">${created}</dd></div>
                </dl>
            </div>`;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ ${err.message}</p>`;
    }
}

export function initPgpTool() {
    document.getElementById('pgpGenerateBtn').addEventListener('click', generatePGPKey);
    document.getElementById('pgpInspectBtn').addEventListener('click', inspectPGPKey);

    document.getElementById('pgpDownloadPublic').addEventListener('click', () => {
        const key = document.getElementById('pgpOutputPublic').textContent;
        if (key) {
            const blob = new Blob([key], { type: 'application/pgp-keys' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'public.asc';
            document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
        }
    });
    document.getElementById('pgpDownloadPrivate').addEventListener('click', () => {
        const key = document.getElementById('pgpOutputPrivate').textContent;
        if (key) {
            const blob = new Blob([key], { type: 'application/pgp-keys' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a'); a.href = url; a.download = 'private.asc';
            document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
        }
    });
}
