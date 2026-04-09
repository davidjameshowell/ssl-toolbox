import { opensslCnf } from '../state.js';
import { downloadFile } from '../utils/download.js';
import { saveToVault } from '../vault.js';

function pemToSshRsa(pubPem) {
    const b64 = pubPem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
    const der = atob(b64);
    const bytes = new Uint8Array(der.length);
    for (let i = 0; i < der.length; i++) bytes[i] = der.charCodeAt(i);

    function readASN1(buf, offset) {
        const tag = buf[offset++];
        let len = buf[offset++];
        if (len & 0x80) {
            const numBytes = len & 0x7f;
            len = 0;
            for (let i = 0; i < numBytes; i++) len = (len << 8) | buf[offset++];
        }
        return { tag, data: buf.slice(offset, offset + len), next: offset + len };
    }

    try {
        const seq = readASN1(bytes, 0);
        const algSeq = readASN1(seq.data, 0);
        const bitStr = readASN1(seq.data, algSeq.next);

        let keyData = bitStr.data;
        if (keyData[0] === 0) keyData = keyData.slice(1);

        const rsaSeq = readASN1(keyData, 0);
        const modInt = readASN1(rsaSeq.data, 0);
        const expInt = readASN1(rsaSeq.data, modInt.next);

        let modulus = modInt.data;
        let exponent = expInt.data;

        function encodeSshBuffer(data) {
            const len = new Uint8Array(4);
            new DataView(len.buffer).setUint32(0, data.length);
            const result = new Uint8Array(len.length + data.length);
            result.set(len);
            result.set(data, 4);
            return result;
        }

        const typeStr = new TextEncoder().encode('ssh-rsa');
        const parts = [encodeSshBuffer(typeStr), encodeSshBuffer(exponent), encodeSshBuffer(modulus)];
        const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
        const sshKey = new Uint8Array(totalLen);
        let offset = 0;
        for (const p of parts) { sshKey.set(p, offset); offset += p.length; }

        let b64Out = '';
        for (let i = 0; i < sshKey.length; i += 3) {
            const chunk = sshKey.slice(i, i + 3);
            let binary = '';
            for (const b of chunk) binary += String.fromCharCode(b);
            b64Out += btoa(binary);
        }

        return `ssh-rsa ${btoa(String.fromCharCode(...sshKey))}`;
    } catch {
        return null;
    }
}

async function generateSSHKey() {
    const status = document.getElementById('sshStatus');
    const resultsDiv = document.getElementById('sshResults');
    const btn = document.getElementById('sshGenerateBtn');
    const keyType = document.getElementById('sshKeyType').value;
    const comment = document.getElementById('sshComment').value.trim() || 'user@local';

    btn.disabled = true;
    status.textContent = 'Generating SSH key pair...';
    status.className = 'text-center font-medium mt-4 text-sm text-slate-500 animate-pulse';
    status.classList.remove('hidden');
    resultsDiv.classList.add('hidden');

    try {
        const module = await window.createOpenSSL();
        module.FS.writeFile('/openssl.cnf', opensslCnf);
        module.ENV.OPENSSL_CONF = '/openssl.cnf';

        if (keyType.startsWith('rsa')) {
            const bits = keyType.replace('rsa', '');
            module.callMain(['genpkey', '-algorithm', 'RSA', '-pkeyopt', `rsa_keygen_bits:${bits}`, '-out', '/key.pem']);
        } else if (keyType === 'ecdsa256') {
            module.callMain(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-256', '-out', '/key.pem']);
        } else if (keyType === 'ecdsa384') {
            module.callMain(['genpkey', '-algorithm', 'EC', '-pkeyopt', 'ec_paramgen_curve:P-384', '-out', '/key.pem']);
        }

        const keyPem = module.FS.readFile('/key.pem', { encoding: 'utf8' });

        const module2 = await window.createOpenSSL();
        module2.FS.writeFile('/key.pem', keyPem);
        module2.callMain(['pkey', '-in', '/key.pem', '-pubout', '-out', '/pub.pem']);
        const pubPem = module2.FS.readFile('/pub.pem', { encoding: 'utf8' });

        let sshPub = '';
        if (keyType.startsWith('rsa')) {
            sshPub = pemToSshRsa(pubPem);
            if (sshPub) sshPub += ` ${comment}`;
            else sshPub = '(Could not convert to SSH format — use the PEM public key below)';
        } else {
            sshPub = '(ECDSA SSH format conversion requires additional encoding — PEM public key shown below)';
        }

        document.getElementById('sshOutputPrivate').textContent = keyPem.trim();
        document.getElementById('sshOutputPublic').textContent = pubPem.trim();
        document.getElementById('sshOutputSSH').textContent = sshPub;
        resultsDiv.classList.remove('hidden');

        status.textContent = '✓ SSH key pair generated successfully.';
        status.className = 'text-center font-medium mt-4 text-sm text-emerald-600';

        saveToVault(`SSH Key (${keyType})`, 'key', keyPem);
    } catch (err) {
        status.textContent = `❌ Error: ${err.message || 'Key generation failed.'}`;
        status.className = 'text-center font-medium mt-4 text-sm text-red-600';
    } finally {
        btn.disabled = false;
    }
}

export function initSshTool() {
    document.getElementById('sshGenerateBtn').addEventListener('click', generateSSHKey);

    document.getElementById('sshDownloadPrivate').addEventListener('click', () => {
        const key = document.getElementById('sshOutputPrivate').textContent;
        if (key) downloadFile(key, 'id_rsa');
    });
    document.getElementById('sshDownloadPublic').addEventListener('click', () => {
        const pub = document.getElementById('sshOutputSSH').textContent;
        if (pub && !pub.startsWith('(')) downloadFile(pub, 'id_rsa.pub');
        else {
            const pem = document.getElementById('sshOutputPublic').textContent;
            if (pem) downloadFile(pem, 'public.pem');
        }
    });
}
