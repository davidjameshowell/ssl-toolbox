const INACTIVE = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg text-slate-300 hover:bg-slate-800 hover:text-white text-sm font-medium transition-colors';
const ACTIVE   = 'w-full flex items-center gap-3 px-4 py-2.5 rounded-lg bg-blue-600 text-white text-sm font-medium transition-colors';

/**
 * Create a switchTab function scoped to the given tab IDs.
 * Registers itself on window so inline onclick handlers work.
 */
export function createSwitchTab(tabIds) {
    function switchTab(tabId) {
        tabIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) el.classList.add('hidden');
        });
        const target = document.getElementById(tabId);
        if (target) target.classList.remove('hidden');

        tabIds.forEach(id => {
            const nav = document.getElementById(`nav-${id}`);
            if (nav) nav.className = INACTIVE;
        });
        const activeNav = document.getElementById(`nav-${tabId}`);
        if (activeNav) activeNav.className = ACTIVE;
    }
    window.switchTab = switchTab;
    return switchTab;
}

/**
 * Activate the default tab from the URL hash, or the first tab.
 */
export function activateFromHash(tabIds) {
    const hash = window.location.hash.replace('#', '');
    const target = tabIds.includes(hash) ? hash : tabIds[0];
    if (target && window.switchTab) window.switchTab(target);
}
