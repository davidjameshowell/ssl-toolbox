const DEFAULT_API_BASE = '';

let apiBase = DEFAULT_API_BASE;

export function setApiBase(url) {
    apiBase = url.replace(/\/+$/, '');
}

export function getApiBase() {
    return apiBase;
}

export async function apiFetch(path, options = {}) {
    if (!apiBase) throw new Error('API base URL is not configured. Set it in Settings.');

    const url = `${apiBase}${path}`;
    const controller = new AbortController();
    const timeout = options.timeout || 30000;
    const timer = setTimeout(() => controller.abort(), timeout);

    try {
        const resp = await fetch(url, {
            ...options,
            signal: controller.signal,
            headers: {
                'Content-Type': 'application/json',
                ...(options.headers || {}),
            },
        });
        if (!resp.ok) {
            const body = await resp.text().catch(() => '');
            throw new Error(`API error ${resp.status}: ${body || resp.statusText}`);
        }
        return await resp.json();
    } finally {
        clearTimeout(timer);
    }
}
