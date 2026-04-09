function base64UrlDecode(str) {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';
    return atob(base64);
}

function base64UrlEncode(str) {
    return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decodeJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT format — expected 3 dot-separated parts.');
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const payload = JSON.parse(base64UrlDecode(parts[1]));
    return { header, payload, signature: parts[2], raw: parts };
}

function jsonHighlight(obj) {
    const json = JSON.stringify(obj, null, 2);
    return json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
        .replace(/"(\\u[a-fA-F0-9]{4}|\\[^u]|[^\\"])*"/g, (match) => {
            if (/:$/.test(match.replace(/\s+$/, ''))) return `<span class="text-blue-400">${match}</span>`;
            return `<span class="text-amber-400">${match}</span>`;
        })
        .replace(/\b(true|false)\b/g, '<span class="text-emerald-400">$1</span>')
        .replace(/\b(null)\b/g, '<span class="text-rose-400">$1</span>')
        .replace(/\b(-?\d+(\.\d+)?([eE][+-]?\d+)?)\b/g, '<span class="text-purple-400">$1</span>');
}

function checkExpiry(payload) {
    if (!payload.exp) return { text: 'No expiry claim', cls: 'text-slate-400' };
    const exp = new Date(payload.exp * 1000);
    const now = new Date();
    if (exp < now) return { text: `Expired ${exp.toLocaleString()}`, cls: 'text-red-500 font-semibold' };
    return { text: `Expires ${exp.toLocaleString()}`, cls: 'text-emerald-600' };
}

async function importKey(alg, keyText) {
    const pemHeader = /-----BEGIN [A-Z ]+-----/;
    const pemFooter = /-----END [A-Z ]+-----/;
    const pem = keyText.trim();

    if (alg === 'HS256' || alg === 'HS384' || alg === 'HS512') {
        const enc = new TextEncoder();
        const keyData = enc.encode(pem);
        const hashMap = { HS256: 'SHA-256', HS384: 'SHA-384', HS512: 'SHA-512' };
        return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: hashMap[alg] }, false, ['verify']);
    }

    const b64 = pem.replace(pemHeader, '').replace(pemFooter, '').replace(/\s/g, '');
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);

    if (alg === 'RS256' || alg === 'RS384' || alg === 'RS512') {
        const hashMap = { RS256: 'SHA-256', RS384: 'SHA-384', RS512: 'SHA-512' };
        return crypto.subtle.importKey('spki', bytes.buffer, { name: 'RSASSA-PKCS1-v1_5', hash: hashMap[alg] }, false, ['verify']);
    }
    if (alg === 'ES256' || alg === 'ES384' || alg === 'ES512') {
        const curveMap = { ES256: 'P-256', ES384: 'P-384', ES512: 'P-521' };
        return crypto.subtle.importKey('spki', bytes.buffer, { name: 'ECDSA', namedCurve: curveMap[alg] }, false, ['verify']);
    }

    throw new Error(`Unsupported algorithm: ${alg}`);
}

async function verifySignature(token, keyText) {
    const parts = token.split('.');
    const header = JSON.parse(base64UrlDecode(parts[0]));
    const alg = header.alg;
    if (!alg) throw new Error('No algorithm in JWT header');

    const key = await importKey(alg, keyText);
    const data = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);

    let sigBytes = base64UrlDecode(parts[2]);
    const sig = new Uint8Array(sigBytes.length);
    for (let i = 0; i < sigBytes.length; i++) sig[i] = sigBytes.charCodeAt(i);

    if (alg.startsWith('HS')) {
        return crypto.subtle.verify('HMAC', key, sig.buffer, data);
    }
    if (alg.startsWith('RS')) {
        return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, sig.buffer, data);
    }
    if (alg.startsWith('ES')) {
        const hashMap = { ES256: 'SHA-256', ES384: 'SHA-384', ES512: 'SHA-512' };
        return crypto.subtle.verify({ name: 'ECDSA', hash: hashMap[alg] }, key, sig.buffer, data);
    }

    throw new Error(`Unsupported algorithm: ${alg}`);
}

function renderDecoded(token) {
    const resultsDiv = document.getElementById('jwtResults');
    try {
        const { header, payload, signature } = decodeJWT(token);
        const expiry = checkExpiry(payload);

        resultsDiv.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Header</h4>
                    <pre class="bg-slate-800 text-slate-200 rounded-lg p-4 text-xs font-mono overflow-x-auto">${jsonHighlight(header)}</pre>
                </div>
                <div>
                    <h4 class="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Payload</h4>
                    <pre class="bg-slate-800 text-slate-200 rounded-lg p-4 text-xs font-mono overflow-x-auto">${jsonHighlight(payload)}</pre>
                </div>
            </div>
            <div class="mt-4 flex items-center gap-4">
                <span class="text-xs font-bold text-slate-400 uppercase tracking-wider">Expiry:</span>
                <span class="text-sm ${expiry.cls}">${expiry.text}</span>
            </div>
            <div class="mt-2">
                <span class="text-xs font-bold text-slate-400 uppercase tracking-wider">Signature:</span>
                <code class="text-xs text-slate-500 break-all ml-2">${signature}</code>
            </div>
            <div id="jwtVerifyResult" class="mt-4"></div>`;
    } catch (err) {
        resultsDiv.innerHTML = `<p class="text-red-600 text-sm font-medium">❌ ${err.message}</p>`;
    }
}

async function handleVerify() {
    const token = document.getElementById('jwtInput').value.trim();
    const keyText = document.getElementById('jwtVerifyKey').value.trim();
    const resultDiv = document.getElementById('jwtVerifyResult');
    if (!resultDiv) return;
    if (!token || !keyText) { resultDiv.innerHTML = '<p class="text-amber-600 text-sm">Provide both a JWT and a verification key.</p>'; return; }

    try {
        const valid = await verifySignature(token, keyText);
        if (valid) {
            resultDiv.innerHTML = '<div class="bg-emerald-50 border border-emerald-200 rounded-lg p-3 text-emerald-800 text-sm font-semibold">✓ Signature is valid</div>';
        } else {
            resultDiv.innerHTML = '<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-800 text-sm font-semibold">✗ Signature is invalid</div>';
        }
    } catch (err) {
        resultDiv.innerHTML = `<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-800 text-sm">❌ Verification error: ${err.message}</div>`;
    }
}

export function initJwtTool() {
    let debounce;
    document.getElementById('jwtInput').addEventListener('input', (e) => {
        clearTimeout(debounce);
        debounce = setTimeout(() => {
            const val = e.target.value.trim();
            if (val) renderDecoded(val);
            else document.getElementById('jwtResults').innerHTML = '';
        }, 300);
    });

    document.getElementById('jwtVerifyBtn').addEventListener('click', handleVerify);
}
