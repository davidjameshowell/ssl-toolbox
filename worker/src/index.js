// Cloudflare Worker — API proxy for network testing tools
// Endpoints: /api/dns, /api/ssl, /api/headers, /api/ocsp, /api/whois, /api/smtp, /api/portscan

const BLOCKED_IPS = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.|169\.254\.|::1|fc|fd|fe80)/;
const MAX_PORTS = 20;

function corsHeaders(env, request) {
    const origin = request.headers.get('Origin') || '';
    const allowed = env.ALLOWED_ORIGIN || '*';
    const allowOrigin = allowed === '*' || origin === allowed ? origin : '';
    return {
        'Access-Control-Allow-Origin': allowOrigin || allowed,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
    };
}

function json(data, status = 200, env, request) {
    return new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...corsHeaders(env, request) },
    });
}

function isBlockedHost(host) {
    return BLOCKED_IPS.test(host) || host === 'localhost' || host.endsWith('.local') || host.endsWith('.internal');
}

// ─── DNS ─────────────────────────────────────────────────────────
async function handleDNS(url, env, request) {
    const domain = url.searchParams.get('domain');
    const type = url.searchParams.get('type') || 'A';
    if (!domain) return json({ error: 'Missing domain parameter' }, 400, env, request);

    const resp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
        headers: { Accept: 'application/dns-json' },
    });
    const data = await resp.json();
    const answers = (data.Answer || []).map(a => ({
        name: a.name,
        type: a.type,
        TTL: a.TTL,
        data: a.data,
    }));
    return json({ domain, type, answers }, 200, env, request);
}

// ─── SSL ─────────────────────────────────────────────────────────
async function handleSSL(url, env, request) {
    const host = url.searchParams.get('host');
    const port = url.searchParams.get('port') || '443';
    if (!host) return json({ error: 'Missing host parameter' }, 400, env, request);
    if (isBlockedHost(host)) return json({ error: 'Host not allowed' }, 403, env, request);

    try {
        const resp = await fetch(`https://${host}:${port}/`, {
            method: 'HEAD',
            cf: { cacheTtl: 0 },
            signal: AbortSignal.timeout(10000),
        });

        const cf = resp.cf || {};
        return json({
            host,
            port: parseInt(port),
            tlsVersion: cf.tlsVersion || null,
            cipher: cf.tlsCipher || null,
            certificates: [],
        }, 200, env, request);
    } catch (err) {
        return json({ error: `SSL check failed: ${err.message}` }, 502, env, request);
    }
}

// ─── Headers ─────────────────────────────────────────────────────
async function handleHeaders(url, env, request) {
    const targetUrl = url.searchParams.get('url');
    if (!targetUrl) return json({ error: 'Missing url parameter' }, 400, env, request);

    let parsed;
    try { parsed = new URL(targetUrl); } catch { return json({ error: 'Invalid URL' }, 400, env, request); }
    if (isBlockedHost(parsed.hostname)) return json({ error: 'Host not allowed' }, 403, env, request);
    if (!['http:', 'https:'].includes(parsed.protocol)) return json({ error: 'Only HTTP/HTTPS allowed' }, 400, env, request);

    try {
        const resp = await fetch(targetUrl, {
            method: 'HEAD',
            redirect: 'follow',
            signal: AbortSignal.timeout(10000),
        });

        const headers = {};
        for (const [k, v] of resp.headers) {
            headers[k.toLowerCase()] = v;
        }
        return json({ url: targetUrl, status: resp.status, headers }, 200, env, request);
    } catch (err) {
        return json({ error: `Fetch failed: ${err.message}` }, 502, env, request);
    }
}

// ─── OCSP ────────────────────────────────────────────────────────
async function handleOCSP(request, env) {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON body' }, 400, env, request); }

    const { cert } = body;
    if (!cert) return json({ error: 'Missing cert field' }, 400, env, request);

    // Extract OCSP responder URL from AIA extension
    // This is a simplified implementation — full ASN.1 parsing would be needed for production
    const ocspMatch = cert.match(/OCSP\s*-\s*URI:(http[^\s]+)/i);

    return json({
        status: 'unknown',
        note: 'Full OCSP checking requires ASN.1 parsing of the certificate. This endpoint is a placeholder that demonstrates the API contract.',
        responderUrl: ocspMatch ? ocspMatch[1] : null,
    }, 200, env, request);
}

// ─── WHOIS ───────────────────────────────────────────────────────
async function handleWhois(url, env, request) {
    const domain = url.searchParams.get('domain');
    if (!domain) return json({ error: 'Missing domain parameter' }, 400, env, request);

    // Validate domain format
    if (!/^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(domain)) {
        return json({ error: 'Invalid domain format' }, 400, env, request);
    }

    try {
        const socket = connect({ hostname: 'whois.iana.org', port: 43 });
        const writer = socket.writable.getWriter();
        const encoder = new TextEncoder();
        await writer.write(encoder.encode(domain + '\r\n'));
        await writer.close();

        const reader = socket.readable.getReader();
        const decoder = new TextDecoder();
        let raw = '';
        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            raw += decoder.decode(value, { stream: true });
        }

        // Try to find referral whois server
        const referMatch = raw.match(/refer:\s*(\S+)/i);
        if (referMatch) {
            try {
                const refSocket = connect({ hostname: referMatch[1], port: 43 });
                const refWriter = refSocket.writable.getWriter();
                await refWriter.write(encoder.encode(domain + '\r\n'));
                await refWriter.close();

                const refReader = refSocket.readable.getReader();
                let refRaw = '';
                while (true) {
                    const { done, value } = await refReader.read();
                    if (done) break;
                    refRaw += decoder.decode(value, { stream: true });
                }
                if (refRaw.trim()) raw = refRaw;
            } catch {
                // Fall back to IANA response
            }
        }

        // Basic parsing
        const parsed = {};
        const patterns = {
            'Registrar': /registrar:\s*(.+)/i,
            'Created': /creat(?:ion|ed)\s*(?:date)?:\s*(.+)/i,
            'Updated': /updat(?:ed)?\s*(?:date)?:\s*(.+)/i,
            'Expires': /expir(?:y|ation)\s*(?:date)?:\s*(.+)/i,
            'Name Servers': /name\s*server:\s*(.+)/i,
            'Status': /(?:domain\s*)?status:\s*(.+)/i,
        };
        for (const [label, re] of Object.entries(patterns)) {
            const m = raw.match(re);
            if (m) parsed[label] = m[1].trim();
        }

        return json({ domain, raw, parsed }, 200, env, request);
    } catch (err) {
        return json({ error: `WHOIS lookup failed: ${err.message}` }, 502, env, request);
    }
}

// ─── SMTP ────────────────────────────────────────────────────────
async function handleSMTP(url, env, request) {
    const domain = url.searchParams.get('domain');
    if (!domain) return json({ error: 'Missing domain parameter' }, 400, env, request);

    // Get MX records via DoH
    const mxResp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=MX`, {
        headers: { Accept: 'application/dns-json' },
    });
    const mxData = await mxResp.json();
    const mx = (mxData.Answer || [])
        .filter(a => a.type === 15)
        .map(a => {
            const parts = a.data.split(' ');
            return { priority: parseInt(parts[0]) || 0, host: (parts[1] || '').replace(/\.$/, '') };
        })
        .sort((a, b) => a.priority - b.priority);

    // Check SPF
    const spfResp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=TXT`, {
        headers: { Accept: 'application/dns-json' },
    });
    const spfData = await spfResp.json();
    const txtRecords = (spfData.Answer || []).map(a => a.data?.replace(/^"|"$/g, '') || '');
    const spfRecord = txtRecords.find(r => r.startsWith('v=spf1'));

    // Check DMARC
    const dmarcResp = await fetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent('_dmarc.' + domain)}&type=TXT`, {
        headers: { Accept: 'application/dns-json' },
    });
    const dmarcData = await dmarcResp.json();
    const dmarcRecords = (dmarcData.Answer || []).map(a => a.data?.replace(/^"|"$/g, '') || '');
    const dmarcRecord = dmarcRecords.find(r => r.startsWith('v=DMARC1'));

    // Try SMTP connection to primary MX on port 587
    let smtp = null;
    if (mx.length > 0) {
        try {
            const socket = connect({ hostname: mx[0].host, port: 587 });
            const reader = socket.readable.getReader();
            const decoder = new TextDecoder();

            const { value } = await Promise.race([
                reader.read(),
                new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
            ]);
            const banner = value ? decoder.decode(value).trim() : '';

            smtp = { banner, starttls: false, tlsVersion: null };

            // Try STARTTLS
            try {
                const writer = socket.writable.getWriter();
                const encoder = new TextEncoder();
                await writer.write(encoder.encode('EHLO testingservers.com\r\n'));

                const { value: ehloValue } = await Promise.race([
                    reader.read(),
                    new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 5000)),
                ]);
                const ehlo = ehloValue ? decoder.decode(ehloValue) : '';
                if (ehlo.includes('STARTTLS')) {
                    smtp.starttls = true;
                }
                await writer.close();
            } catch {}
        } catch {
            smtp = { banner: '(connection failed)', starttls: false };
        }
    }

    return json({
        domain,
        mx,
        smtp,
        spf: { found: !!spfRecord, record: spfRecord || null },
        dkim: { found: false, note: 'DKIM selector required — check selector1._domainkey or google._domainkey' },
        dmarc: { found: !!dmarcRecord, record: dmarcRecord || null },
    }, 200, env, request);
}

// ─── Port Scanner ────────────────────────────────────────────────
async function handlePortscan(url, env, request) {
    const host = url.searchParams.get('host');
    const portsStr = url.searchParams.get('ports');
    if (!host || !portsStr) return json({ error: 'Missing host or ports parameter' }, 400, env, request);
    if (isBlockedHost(host)) return json({ error: 'Host not allowed' }, 403, env, request);

    const ports = portsStr.split(',').map(p => parseInt(p.trim())).filter(p => p > 0 && p <= 65535);
    if (ports.length === 0) return json({ error: 'No valid ports specified' }, 400, env, request);
    if (ports.length > MAX_PORTS) return json({ error: `Maximum ${MAX_PORTS} ports per scan` }, 400, env, request);

    const results = [];

    // Scan in batches of 5 (respecting CF's 6 simultaneous connection limit)
    for (let i = 0; i < ports.length; i += 5) {
        const batch = ports.slice(i, i + 5);
        const batchResults = await Promise.allSettled(batch.map(async (port) => {
            try {
                const socket = connect({ hostname: host, port });
                const reader = socket.readable.getReader();

                // Try to read a banner with timeout
                let banner = '';
                try {
                    const { value } = await Promise.race([
                        reader.read(),
                        new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 3000)),
                    ]);
                    if (value) banner = new TextDecoder().decode(value).trim().slice(0, 200);
                } catch {}

                try { socket.close(); } catch {}
                return { port, open: true, banner };
            } catch {
                return { port, open: false, banner: '' };
            }
        }));

        for (const r of batchResults) {
            results.push(r.status === 'fulfilled' ? r.value : { port: batch[0], open: false, banner: '' });
        }
    }

    return json({ host, results }, 200, env, request);
}

// ─── Router ──────────────────────────────────────────────────────
export default {
    async fetch(request, env, ctx) {
        // Handle CORS preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, { status: 204, headers: corsHeaders(env, request) });
        }

        const url = new URL(request.url);
        const path = url.pathname;

        try {
            switch (path) {
                case '/api/dns': return await handleDNS(url, env, request);
                case '/api/ssl': return await handleSSL(url, env, request);
                case '/api/headers': return await handleHeaders(url, env, request);
                case '/api/ocsp': return await handleOCSP(request, env);
                case '/api/whois': return await handleWhois(url, env, request);
                case '/api/smtp': return await handleSMTP(url, env, request);
                case '/api/portscan': return await handlePortscan(url, env, request);
                default:
                    return json({ error: 'Not found', endpoints: ['/api/dns', '/api/ssl', '/api/headers', '/api/ocsp', '/api/whois', '/api/smtp', '/api/portscan'] }, 404, env, request);
            }
        } catch (err) {
            return json({ error: `Internal error: ${err.message}` }, 500, env, request);
        }
    },
};
