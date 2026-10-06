export function formatFriendlyDate(rawStr) {
    try {
        const d = new Date(rawStr);
        if (isNaN(d)) return rawStr;
        return d.toLocaleString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            timeZoneName: 'short',
        });
    } catch (e) {
        return rawStr;
    }
}

export function getExpiryStatus(validToRaw, now = new Date()) {
    const t = new Date(validToRaw);
    if (isNaN(t.getTime())) return '';
    if (t.getTime() < now.getTime()) return 'expired';
    if (t.getTime() - now.getTime() < 30 * 24 * 3600 * 1000) return 'expiring';
    return 'valid';
}

/**
 * Collect value lines belonging to a header line: only lines indented
 * *deeper* than the header itself. A same-or-lower indent (e.g. the next
 * `Signature Algorithm:` section in `req -text`) ends the section. This
 * matters because -text section headers are themselves indented.
 */
function collectSectionValues(lines, headerIdx) {
    const headerIndent = (lines[headerIdx].match(/^\s*/) || [''])[0].length;
    const values = [];
    for (let i = headerIdx + 1; i < lines.length; i += 1) {
        const line = lines[i];
        if (line.trim() === '') break;
        const indent = (line.match(/^\s*/) || [''])[0].length;
        if (indent <= headerIndent) break;
        values.push(line.trim());
    }
    return values;
}

/** Collect comma-separated entries following a "Subject Alternative Name:" header. */
export function parseSanEntries(sanOut) {
    if (!sanOut || !sanOut.includes('Subject Alternative Name:')) return '';
    const lines = sanOut.split('\n');
    const idx = lines.findIndex((l) => l.includes('Subject Alternative Name:'));
    return collectSectionValues(lines, idx).join(' ').split(/\s*,\s*/).filter(Boolean).join(', ');
}

const PUBKEY_FRIENDLY = {
    rsaEncryption: 'RSA',
    'id-ecPublicKey': 'EC',
    Ed25519: 'Ed25519',
    X25519: 'X25519',
    dsa: 'DSA',
};

/** Parse `openssl x509 -text` output for algorithms, key size, usages. */
export function parseCertTextDetails(textOut = '') {
    const details = {
        sigAlg: '',
        pubkeyAlg: '',
        pubkeyBits: '',
        curve: '',
        keyUsage: '',
        extKeyUsage: '',
    };
    if (!textOut) return details;

    const sigMatch = textOut.match(/^\s*Signature Algorithm:\s*(.+)$/m);
    if (sigMatch) details.sigAlg = sigMatch[1].trim();

    const algMatch = textOut.match(/Public Key Algorithm:\s*(.+)/);
    if (algMatch) {
        const raw = algMatch[1].trim();
        details.pubkeyAlg = PUBKEY_FRIENDLY[raw] || raw;
    }

    const bitsMatch = textOut.match(/Public-Key:\s*\((\d+)\s*bit\)/);
    if (bitsMatch) details.pubkeyBits = bitsMatch[1];

    const curveMatch = textOut.match(/ASN1 OID:\s*(\S+)/);
    if (curveMatch) details.curve = curveMatch[1].trim();

    const collectUsage = (label) => {
        const lines = textOut.split('\n');
        const idx = lines.findIndex((l) => l.includes(label));
        if (idx === -1) return '';
        return collectSectionValues(lines, idx).join(' ').replace(/,\s*/g, ', ');
    };
    details.keyUsage = collectUsage('X509v3 Key Usage:');
    details.extKeyUsage = collectUsage('X509v3 Extended Key Usage:');
    return details;
}

export function parseFingerprint(fpOut = '') {
    const match = String(fpOut || '').match(/Fingerprint=([0-9A-Fa-f:]+)/);
    return match ? match[1].toUpperCase() : '';
}

/** Parse `openssl req -text` output for CSR inspection. */
export function parseCsrMetadata(textOut = '') {
    const data = {
        subject: '',
        cn: '',
        org: '',
        ou: '',
        loc: '',
        st: '',
        c: '',
        san: '',
        sigAlg: '',
        pubkeyAlg: '',
        pubkeyBits: '',
        curve: '',
    };
    if (!textOut) return data;

    const extract = (str, attr) => {
        const match = str.match(new RegExp(`\\b${attr}\\s*=\\s*(.*?)(?:,\\s*[A-Z]+\\s*=|$)`));
        return match ? match[1].trim() : '';
    };

    const subjMatch = textOut.match(/^\s*Subject:\s*(.+)$/m);
    if (subjMatch) {
        data.subject = subjMatch[1].trim();
        data.cn = extract(data.subject, 'CN');
        data.org = extract(data.subject, 'O');
        data.ou = extract(data.subject, 'OU');
        data.loc = extract(data.subject, 'L');
        data.st = extract(data.subject, 'ST');
        data.c = extract(data.subject, 'C');
    }

    const details = parseCertTextDetails(textOut);
    data.sigAlg = details.sigAlg;
    data.pubkeyAlg = details.pubkeyAlg;
    data.pubkeyBits = details.pubkeyBits;
    data.curve = details.curve;
    data.san = parseSanEntries(textOut);
    return data;
}

export function parseCertMetadata(stdOut, sanOut = "", textOut = "", fpOut = "") {
    const data = {
        subject: '',
        issuer: '',
        cn: '',
        issuerCN: '',
        san: '',
        org: '',
        ou: '',
        loc: '',
        st: '',
        c: '',
        validFrom: '',
        validFromRaw: '',
        validTo: '',
        validToRaw: '',
        expiryStatus: '',
        serial: '',
        sigAlg: '',
        pubkeyAlg: '',
        pubkeyBits: '',
        curve: '',
        keyUsage: '',
        extKeyUsage: '',
        fingerprintSha256: '',
    };

    const extract = (str, attr) => {
        const match = str.match(new RegExp(`\\b${attr}\\s*=\\s*(.*?)(?:,\\s*[A-Z]+\\s*=|$)`));
        return match ? match[1].trim() : '';
    };

    stdOut.split('\n').forEach((line) => {
        if (line.startsWith('subject=')) {
            data.subject = line.substring(8).trim();
            data.cn = extract(data.subject, 'CN');
            data.org = extract(data.subject, 'O');
            data.ou = extract(data.subject, 'OU');
            data.loc = extract(data.subject, 'L');
            data.st = extract(data.subject, 'ST');
            data.c = extract(data.subject, 'C');
        } else if (line.startsWith('issuer=')) {
            data.issuer = line.substring(7).trim();
            data.issuerCN = extract(data.issuer, 'CN') || extract(data.issuer, 'O');
        } else if (line.startsWith('notBefore=')) {
            data.validFromRaw = line.substring(10).trim();
            data.validFrom = formatFriendlyDate(data.validFromRaw);
        } else if (line.startsWith('notAfter=')) {
            data.validToRaw = line.substring(9).trim();
            data.validTo = formatFriendlyDate(data.validToRaw);
        } else if (line.startsWith('serial=')) {
            data.serial = line.substring(7).trim();
        }
    });

    data.san = parseSanEntries(sanOut) || parseSanEntries(textOut);

    const textDetails = parseCertTextDetails(textOut);
    data.sigAlg = textDetails.sigAlg;
    data.pubkeyAlg = textDetails.pubkeyAlg;
    data.pubkeyBits = textDetails.pubkeyBits;
    data.curve = textDetails.curve;
    data.keyUsage = textDetails.keyUsage;
    data.extKeyUsage = textDetails.extKeyUsage;
    data.fingerprintSha256 = parseFingerprint(fpOut);
    data.expiryStatus = getExpiryStatus(data.validToRaw);

    return data;
}
