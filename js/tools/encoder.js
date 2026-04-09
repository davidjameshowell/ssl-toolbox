function encode(mode, input) {
    const bytes = new TextEncoder().encode(input);
    switch (mode) {
        case 'base64': return btoa(String.fromCharCode(...bytes));
        case 'base64url': return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
        case 'url': return encodeURIComponent(input);
        case 'html': return input.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
        case 'hex': return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        default: return input;
    }
}

function decode(mode, input) {
    switch (mode) {
        case 'base64': {
            const binary = atob(input);
            return new TextDecoder().decode(Uint8Array.from(binary, c => c.charCodeAt(0)));
        }
        case 'base64url': {
            let b64 = input.replace(/-/g, '+').replace(/_/g, '/');
            while (b64.length % 4) b64 += '=';
            const binary = atob(b64);
            return new TextDecoder().decode(Uint8Array.from(binary, c => c.charCodeAt(0)));
        }
        case 'url': return decodeURIComponent(input);
        case 'html': {
            const doc = new DOMParser().parseFromString(input, 'text/html');
            return doc.documentElement.textContent;
        }
        case 'hex': {
            const hexPairs = input.replace(/\s/g, '').match(/.{1,2}/g) || [];
            return new TextDecoder().decode(Uint8Array.from(hexPairs, h => parseInt(h, 16)));
        }
        default: return input;
    }
}

function updateOutput() {
    const input = document.getElementById('encoderInput').value;
    const mode = document.getElementById('encoderMode').value;
    const direction = document.getElementById('encoderDirection').value;
    const output = document.getElementById('encoderOutput');

    try {
        output.value = direction === 'encode' ? encode(mode, input) : decode(mode, input);
        document.getElementById('encoderStatus').textContent = '';
    } catch (err) {
        output.value = '';
        document.getElementById('encoderStatus').textContent = `Error: ${err.message}`;
    }
}

export function initEncoderTool() {
    document.getElementById('encoderInput').addEventListener('input', updateOutput);
    document.getElementById('encoderMode').addEventListener('change', updateOutput);
    document.getElementById('encoderDirection').addEventListener('change', updateOutput);

    document.getElementById('encoderFile').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        document.getElementById('encoderInput').value = btoa(String.fromCharCode(...bytes));
        document.getElementById('encoderMode').value = 'base64';
        document.getElementById('encoderDirection').value = 'encode';
        document.getElementById('encoderOutput').value = btoa(String.fromCharCode(...bytes));
    });

    document.getElementById('encoderCopy').addEventListener('click', () => {
        const text = document.getElementById('encoderOutput').value;
        if (text) navigator.clipboard.writeText(text);
    });
}
