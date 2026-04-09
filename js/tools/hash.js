async function computeHashes(data) {
    const algos = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
    const results = {};

    for (const algo of algos) {
        const hash = await crypto.subtle.digest(algo, data);
        const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
        results[algo] = hex;
    }

    return results;
}

async function computeHMAC(data, keyStr, algo) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(keyStr), { name: 'HMAC', hash: algo }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', key, data);
    return Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function computeMD5viaWASM(text) {
    try {
        const module = await window.createOpenSSL();
        module.FS.writeFile('/input.bin', text);

        const lines = [];
        module.print = (t) => lines.push(t);
        module.callMain(['dgst', '-md5', '/input.bin']);
        const output = lines.join('\n');
        const match = output.match(/=\s*([a-f0-9]+)/);
        return match ? match[1] : '(MD5 unavailable)';
    } catch {
        return '(MD5 unavailable)';
    }
}

async function runHash() {
    const textInput = document.getElementById('hashInput').value;
    const fileInput = document.getElementById('hashFile').files[0];
    const hmacKey = document.getElementById('hashHmacKey').value.trim();
    const resultsDiv = document.getElementById('hashResults');

    let data;
    let displaySource;

    if (fileInput) {
        const buffer = await fileInput.arrayBuffer();
        data = new Uint8Array(buffer);
        displaySource = `File: ${fileInput.name} (${fileInput.size.toLocaleString()} bytes)`;
    } else if (textInput) {
        data = new TextEncoder().encode(textInput);
        displaySource = `Text input (${data.length} bytes)`;
    } else {
        resultsDiv.innerHTML = '<p class="text-amber-600 text-sm">Enter text or select a file.</p>';
        return;
    }

    const hashes = await computeHashes(data);
    const md5 = await computeMD5viaWASM(textInput || new TextDecoder().decode(data));

    let hmacHtml = '';
    if (hmacKey) {
        const hmac256 = await computeHMAC(data, hmacKey, 'SHA-256');
        const hmac512 = await computeHMAC(data, hmacKey, 'SHA-512');
        hmacHtml = `
            <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-amber-50"><dt class="font-medium text-amber-700">HMAC-SHA-256</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${hmac256}</dd></div>
            <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-amber-700">HMAC-SHA-512</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${hmac512}</dd></div>`;
    }

    resultsDiv.innerHTML = `
        <p class="text-xs text-slate-500 mb-3">${displaySource}</p>
        <div class="bg-white border border-slate-200 rounded-lg overflow-hidden text-sm">
            <dl class="divide-y divide-slate-100">
                <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">MD5</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${md5}</dd></div>
                <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-slate-50"><dt class="font-medium text-slate-500">SHA-1</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${hashes['SHA-1']}</dd></div>
                <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">SHA-256</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${hashes['SHA-256']}</dd></div>
                <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4 bg-slate-50"><dt class="font-medium text-slate-500">SHA-384</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${hashes['SHA-384']}</dd></div>
                <div class="px-4 py-3 sm:grid sm:grid-cols-3 sm:gap-4"><dt class="font-medium text-slate-500">SHA-512</dt><dd class="mt-1 text-slate-900 sm:mt-0 sm:col-span-2 font-mono text-xs break-all">${hashes['SHA-512']}</dd></div>
                ${hmacHtml}
            </dl>
        </div>`;
}

function compareHashes() {
    const h1 = document.getElementById('hashCompare1').value.trim().toLowerCase();
    const h2 = document.getElementById('hashCompare2').value.trim().toLowerCase();
    const result = document.getElementById('hashCompareResult');
    if (!h1 || !h2) { result.innerHTML = ''; return; }

    if (h1 === h2) {
        result.innerHTML = '<div class="bg-emerald-50 border border-emerald-200 rounded-lg p-3 text-emerald-800 text-sm font-semibold">✓ Hashes match</div>';
    } else {
        result.innerHTML = '<div class="bg-red-50 border border-red-200 rounded-lg p-3 text-red-800 text-sm font-semibold">✗ Hashes do not match</div>';
    }
}

export function initHashTool() {
    document.getElementById('hashBtn').addEventListener('click', runHash);
    document.getElementById('hashCompareBtn').addEventListener('click', compareHashes);
}
