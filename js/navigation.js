export function switchTab(tabId) {
    ['homeTab', 'localTab', 'pfxTab', 'decoderTab', 'matcherTab', 'converterTab'].forEach((id) => {
        document.getElementById(id).classList.add('hidden');
    });
    document.getElementById(tabId).classList.remove('hidden');

    const inactiveClass = 'nav-item';
    const activeClass = 'nav-item nav-active';

    ['pfxTab', 'decoderTab', 'matcherTab', 'converterTab'].forEach((id) => {
        document.getElementById(`nav-${id}`).className = inactiveClass;
    });
    const activeNav = document.getElementById(`nav-${tabId}`);
    if (activeNav) activeNav.className = activeClass;
}

export function initNavigation() {
    window.switchTab = switchTab;
}
