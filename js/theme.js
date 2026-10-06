const STORAGE_KEY = 'pki-theme';

export function currentTheme() {
    if (typeof document === 'undefined') return 'light';
    return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

function paint() {
    if (typeof document === 'undefined') return;
    const dark = currentTheme() === 'dark';
    const moon = document.getElementById('themeIconMoon');
    const sun = document.getElementById('themeIconSun');
    const label = document.getElementById('themeToggleLabel');
    const btn = document.getElementById('themeToggleBtn');
    if (moon) moon.classList.toggle('hidden', dark);
    if (sun) sun.classList.toggle('hidden', !dark);
    if (label) label.textContent = dark ? 'Light mode' : 'Dark mode';
    if (btn) btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
}

export function initTheme() {
    if (typeof document === 'undefined') return;
    paint();
    document.getElementById('themeToggleBtn')?.addEventListener('click', () => {
        document.documentElement.classList.toggle('dark');
        try {
            localStorage.setItem(STORAGE_KEY, currentTheme());
        } catch (e) {
            // private mode etc. — theme just won't persist
        }
        paint();
    });
}
