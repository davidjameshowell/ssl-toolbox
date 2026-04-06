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

export function parseCertMetadata(stdOut, sanOut = "") {
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
        serial: '',
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

    if (sanOut && sanOut.includes('Subject Alternative Name:')) {
        const sanLines = sanOut.split('\n');
        for (let i = 0; i < sanLines.length; i += 1) {
            if (sanLines[i].includes('DNS:')) {
                data.san = sanLines[i].trim().replace(/DNS:/g, '').trim();
                break;
            }
        }
    }

    return data;
}
