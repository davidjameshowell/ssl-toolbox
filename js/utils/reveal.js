const EYE_OPEN = '<svg class="h-4 w-4 reveal-eye" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" /></svg>';
const EYE_OFF = '<svg class="h-4 w-4 reveal-eye-off hidden" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.948 9.948 0 0112 5c4.478 0 8.268 2.943 9.543 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" /></svg>';

function paint(input, btn, show) {
    input.type = show ? 'text' : 'password';
    btn.setAttribute('aria-pressed', show ? 'true' : 'false');
    btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    const open = btn.querySelector('.reveal-eye');
    const closed = btn.querySelector('.reveal-eye-off');
    if (open) open.classList.toggle('hidden', show);
    if (closed) closed.classList.toggle('hidden', !show);
}

/**
 * Enhance every `input[type=password][data-reveal]` with a show/hide toggle.
 * Wraps the input in a relative container and injects the button.
 * Safe to call when no inputs exist; returns the number enhanced.
 */
export function initPasswordReveals(doc) {
    const root = doc || (typeof document !== 'undefined' ? document : null);
    if (!root) return 0;
    const inputs = Array.from(root.querySelectorAll('input[type="password"][data-reveal]'));
    inputs.forEach((input) => {
        if (input.dataset && input.dataset.revealDone) return;
        if (input.dataset) input.dataset.revealDone = '1';
        input.classList.add('pr-11');
        const wrapper = root.createElement('div');
        wrapper.className = 'relative';
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);
        const btn = root.createElement('button');
        btn.type = 'button';
        btn.className = 'absolute inset-y-0 right-0 px-3 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors';
        btn.setAttribute('aria-label', 'Show password');
        btn.setAttribute('aria-pressed', 'false');
        btn.innerHTML = EYE_OPEN + EYE_OFF;
        btn.addEventListener('click', () => paint(input, btn, input.type === 'password'));
        wrapper.appendChild(btn);
    });
    return inputs.length;
}
