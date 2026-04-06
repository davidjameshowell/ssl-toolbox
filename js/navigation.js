export function switchTab(tabId) {
    ['homeTab', 'localTab', 'pfxTab', 'decoderTab', 'matcherTab', 'converterTab'].forEach((id) => {
        document.getElementById(id).classList.add('hidden');
    });
    document.getElementById(tabId).classList.remove('hidden');

    const inactiveClass = 'w-full flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white font-medium transition-colors';
    const activeClass = 'w-full flex items-center gap-3 px-4 py-3 rounded-lg bg-blue-600 text-white font-medium transition-colors';

    ['pfxTab', 'decoderTab', 'matcherTab', 'converterTab'].forEach((id) => {
        document.getElementById(`nav-${id}`).className = inactiveClass;
    });
    const activeNav = document.getElementById(`nav-${tabId}`);
    if (activeNav) activeNav.className = activeClass;
}

export function initNavigation() {
    window.switchTab = switchTab;
}
