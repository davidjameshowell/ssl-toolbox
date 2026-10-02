export function switchTab(tabId) {
    ['homeTab', 'localTab', 'pfxTab', 'decoderTab', 'matcherTab', 'decryptorTab', 'converterTab'].forEach((id) => {
        document.getElementById(id).classList.add('hidden');
    });
    document.getElementById(tabId).classList.remove('hidden');

    const inactiveClass = 'nav-item';
    const activeClass = 'nav-item nav-active';

    ['pfxTab', 'decoderTab', 'matcherTab', 'decryptorTab', 'converterTab'].forEach((id) => {
        const el = document.getElementById(`nav-${id}`);
        el.className = inactiveClass;
        el.removeAttribute('aria-current');
    });
    const activeNav = document.getElementById(`nav-${tabId}`);
    if (activeNav) {
        activeNav.className = activeClass;
        activeNav.setAttribute('aria-current', 'page');
    }
}

export function initNavigation() {
    window.switchTab = switchTab;
}
