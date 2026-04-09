function uuidv4() {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uuidv7() {
    const now = Date.now();
    const bytes = crypto.getRandomValues(new Uint8Array(16));

    // Timestamp in first 48 bits
    bytes[0] = (now / 2 ** 40) & 0xff;
    bytes[1] = (now / 2 ** 32) & 0xff;
    bytes[2] = (now / 2 ** 24) & 0xff;
    bytes[3] = (now / 2 ** 16) & 0xff;
    bytes[4] = (now / 2 ** 8) & 0xff;
    bytes[5] = now & 0xff;

    // Version 7
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    // Variant 10
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function randomHex(len) {
    const bytes = crypto.getRandomValues(new Uint8Array(Math.ceil(len / 2)));
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, len);
}

function randomBase64(len) {
    const bytes = crypto.getRandomValues(new Uint8Array(len));
    return btoa(String.fromCharCode(...bytes));
}

function generate() {
    const type = document.getElementById('uuidType').value;
    const count = Math.min(Math.max(parseInt(document.getElementById('uuidCount').value) || 1, 1), 1000);
    const length = Math.min(Math.max(parseInt(document.getElementById('uuidLength').value) || 32, 1), 1024);
    const output = document.getElementById('uuidOutput');

    const results = [];
    for (let i = 0; i < count; i++) {
        switch (type) {
            case 'uuidv4': results.push(uuidv4()); break;
            case 'uuidv7': results.push(uuidv7()); break;
            case 'hex': results.push(randomHex(length)); break;
            case 'base64': results.push(randomBase64(length)); break;
            case 'bytes': {
                const bytes = crypto.getRandomValues(new Uint8Array(length));
                results.push(Array.from(bytes).join(' '));
                break;
            }
        }
    }

    output.value = results.join('\n');
}

export function initUuidTool() {
    document.getElementById('uuidGenerateBtn').addEventListener('click', generate);
    document.getElementById('uuidCopy').addEventListener('click', () => {
        const text = document.getElementById('uuidOutput').value;
        if (text) navigator.clipboard.writeText(text);
    });

    document.getElementById('uuidType').addEventListener('change', () => {
        const type = document.getElementById('uuidType').value;
        const lengthGroup = document.getElementById('uuidLengthGroup');
        if (type === 'hex' || type === 'base64' || type === 'bytes') {
            lengthGroup.classList.remove('hidden');
        } else {
            lengthGroup.classList.add('hidden');
        }
    });
}
