/**
 * Shared sidebar layout injected into every page.
 *
 * Each page sets  window.__PAGE  before importing this module so we know
 * which nav section to highlight.  Valid values:
 *   'home' | 'pki' | 'security' | 'devtools' | 'network' | 'local'
 *
 * Usage in an HTML page:
 *   <script>window.__PAGE = 'pki';</script>
 *   <script type="module" src="js/layout.js"></script>
 */

const PAGE = window.__PAGE || 'home';

/* ── Navigation definition ─────────────────────────────────────── */
const NAV = [
    {
        heading: 'PKI / Security',
        page: 'pki',
        href: 'pki.html',
        items: [
            { id: 'decoderTab',   icon: 'doc',     label: 'Cert Decoder' },
            { id: 'pfxTab',       icon: 'lock',    label: 'PFX Extractor' },
            { id: 'matcherTab',   icon: 'copy',    label: 'Key Matcher' },
            { id: 'converterTab', icon: 'swap',    label: 'Cert Converter' },
            { id: 'csrTab',       icon: 'plus',    label: 'CSR Generator' },
            { id: 'sshTab',       icon: 'terminal',label: 'SSH Keys' },
            { id: 'asn1Tab',      icon: 'db',      label: 'ASN.1 Parser' },
            { id: 'ciphersTab',   icon: 'shield',  label: 'Cipher Suites' },
        ],
    },
    {
        heading: 'Security Tools',
        page: 'security',
        href: 'security.html',
        items: [
            { id: 'jwtTab',  icon: 'key',    label: 'JWT Tools' },
            { id: 'pgpTab',  icon: 'mail',   label: 'PGP Keys' },
            { id: 'ocspTab', icon: 'check',  label: 'OCSP/CRL Check' },
        ],
    },
    {
        heading: 'Developer Utilities',
        page: 'devtools',
        href: 'devtools.html',
        items: [
            { id: 'encoderTab', icon: 'code',   label: 'Encoder/Decoder' },
            { id: 'hashTab',    icon: 'hash',   label: 'Hash Generator' },
            { id: 'dataconvTab',icon: 'conv',   label: 'Data Converter' },
            { id: 'regexTab',   icon: 'search', label: 'Regex Tester' },
            { id: 'diffTab',    icon: 'diff',   label: 'Text Diff' },
            { id: 'uuidTab',    icon: 'grid',   label: 'UUID Generator' },
        ],
    },
    {
        heading: 'Network Testing',
        page: 'network',
        href: 'network.html',
        items: [
            { id: 'dnsTab',      icon: 'globe',  label: 'DNS Lookup' },
            { id: 'sslcheckTab', icon: 'shield', label: 'SSL Checker' },
            { id: 'headersTab',  icon: 'clip',   label: 'HTTP Headers' },
            { id: 'whoisTab',    icon: 'info',   label: 'WHOIS' },
            { id: 'mailTab',     icon: 'mail',   label: 'Mail Tester' },
            { id: 'portscanTab', icon: 'server', label: 'Port Scanner' },
        ],
    },
];

/* ── SVG icon map (inline, 16×16) ──────────────────────────────── */
const ICONS = {
    doc:      '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />',
    lock:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />',
    copy:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />',
    swap:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7h12m0 0l-4-4m4 4l-4 4m0 6H4m0 0l4 4m-4-4l4-4" />',
    plus:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4" />',
    terminal: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />',
    db:       '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />',
    shield:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />',
    key:      '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />',
    mail:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />',
    check:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />',
    code:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />',
    hash:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 20l4-16m2 16l4-16M6 9h14M4 15h14" />',
    conv:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2 1.5 3 3.5 3h9c2 0 3.5-1 3.5-3V7M4 7c0-2 1.5-3 3.5-3h9C18.5 4 20 5 20 7M9 12h6" />',
    search:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />',
    diff:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7" />',
    grid:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 14v6m-3-3h6M6 10h2a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v2a2 2 0 002 2zm10 0h2a2 2 0 002-2V6a2 2 0 00-2-2h-2a2 2 0 00-2 2v2a2 2 0 002 2zM6 20h2a2 2 0 002-2v-2a2 2 0 00-2-2H6a2 2 0 00-2 2v2a2 2 0 002 2z" />',
    globe:    '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />',
    clip:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />',
    info:     '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />',
    server:   '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2" />',
};

function svg(name) {
    return `<svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">${ICONS[name] || ''}</svg>`;
}

/* ── Build sidebar HTML ────────────────────────────────────────── */
function buildSidebar() {
    const inactive = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white text-sm font-medium transition-colors';
    const active   = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg bg-blue-600 text-white text-sm font-medium transition-colors';
    const groupActive = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg bg-slate-800 text-white text-sm font-medium transition-colors';

    let html = '';
    for (const group of NAV) {
        html += `<p class="text-[10px] font-bold text-slate-500 uppercase tracking-wider px-4 pt-4 pb-1 first:pt-1">${group.heading}</p>`;
        const isThisPage = group.page === PAGE;
        for (const item of group.items) {
            if (isThisPage) {
                // In-page tab button
                html += `<button onclick="switchTab('${item.id}')" id="nav-${item.id}" class="${inactive}">${svg(item.icon)} ${item.label}</button>`;
            } else {
                // Link to other page with tab hash
                html += `<a href="${group.href}#${item.id}" class="${inactive}">${svg(item.icon)} ${item.label}</a>`;
            }
        }
    }
    return html;
}

function buildVaultSection() {
    return `
    <div class="border-t border-slate-800 pt-4 mt-2">
        <div class="flex items-center justify-between mb-3">
            <h3 class="text-xs font-bold text-slate-400 uppercase tracking-wider">Memory Vault</h3>
            <div class="flex items-center gap-1.5">
                <button id="vaultUploadBtn" title="Upload file to vault" class="text-[10px] font-semibold px-2 py-1 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors">Upload</button>
                <button id="vaultClearBtn" title="Clear all vault items" class="text-[10px] font-semibold px-2 py-1 rounded bg-red-900/50 hover:bg-red-800/60 text-red-400 transition-colors">Clear</button>
                <input type="file" id="vaultUploadInput" class="hidden" multiple>
            </div>
        </div>
        <ul id="sidebarStoreList" class="space-y-2">
            <li class="text-slate-500 italic text-xs px-2">Vault is empty</li>
        </ul>
    </div>`;
}

export function injectLayout() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    sidebar.innerHTML = `
    <a href="index.html" class="p-6 border-b border-slate-800 text-left w-full hover:bg-slate-800/50 transition-colors group block">
        <h1 class="text-xl font-bold flex items-center gap-2 group-hover:text-blue-300 transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6 text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
            Toolkit
        </h1>
    </a>
    <nav class="p-4 space-y-1 shrink-0 overflow-y-auto flex-1">
        ${buildSidebar()}
    </nav>
    <div class="flex-1 overflow-y-auto px-4 pb-4">
        ${buildVaultSection()}
    </div>
    <a href="local.html" class="p-4 text-left w-full border-t border-slate-800 shrink-0 bg-slate-900 group hover:bg-slate-800/60 transition-colors block">
        <span class="flex items-center gap-1.5 text-xs text-emerald-500 group-hover:text-emerald-400 transition-colors">
            <svg xmlns="http://www.w3.org/2000/svg" class="h-3.5 w-3.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
            100% Local &mdash; How it works
        </span>
        <span class="block text-[10px] text-slate-600 mt-0.5">Powered by WebAssembly OpenSSL</span>
    </a>`;

    // Apply first tab from hash or default to first tool on the page
    if (PAGE !== 'home' && PAGE !== 'local') {
        const hash = window.location.hash.replace('#', '');
        const group = NAV.find(g => g.page === PAGE);
        const validIds = group ? group.items.map(i => i.id) : [];
        const targetTab = validIds.includes(hash) ? hash : validIds[0];
        if (targetTab && typeof window.switchTab === 'function') {
            window.switchTab(targetTab);
        }
    }
}
