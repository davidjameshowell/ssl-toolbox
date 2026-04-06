export function switchTab(tabId) {
    document.getElementById('homeTab').classList.add('hidden');
    document.getElementById('pfxTab').classList.add('hidden');
    document.getElementById('decoderTab').classList.add('hidden');
    document.getElementById('matcherTab').classList.add('hidden');
    document.getElementById('converterTab').classList.add('hidden');
    document.getElementById(tabId).classList.remove('hidden');

    const inactiveClass = 'w-full flex items-center gap-3 px-4 py-3 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white font-medium transition-colors';
    const activeClass = 'w-full flex items-center gap-3 px-4 py-3 rounded-lg bg-blue-600 text-white font-medium transition-colors';

    document.getElementById('nav-homeTab').className = inactiveClass;
    document.getElementById('nav-pfxTab').className = inactiveClass;
    document.getElementById('nav-decoderTab').className = inactiveClass;
    document.getElementById('nav-matcherTab').className = inactiveClass;
    document.getElementById('nav-converterTab').className = inactiveClass;
    document.getElementById(`nav-${tabId}`).className = activeClass;
}

export function initNavigation() {
    window.switchTab = switchTab;
}
