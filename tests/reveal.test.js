import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { initPasswordReveals } from '../js/utils/reveal.js';

function makeClassList() {
    const set = new Set();
    return {
        add: (c) => set.add(c),
        toggle: (c, force) => {
            if (force === undefined) {
                if (set.has(c)) set.delete(c);
                else set.add(c);
            } else if (force) {
                set.add(c);
            } else {
                set.delete(c);
            }
        },
        contains: (c) => set.has(c),
    };
}

function makeFakeDom() {
    const listeners = {};
    const eyeOpen = { classList: makeClassList() };
    const eyeOff = { classList: makeClassList() };
    eyeOff.classList.add('hidden');
    const btn = {
        type: '',
        className: '',
        innerHTML: '',
        attrs: {},
        setAttribute: (k, v) => { btn.attrs[k] = v; },
        addEventListener: (ev, fn) => { listeners[ev] = fn; },
        querySelector: (sel) => (sel === '.reveal-eye' ? eyeOpen : sel === '.reveal-eye-off' ? eyeOff : null),
        click: () => listeners.click(),
    };
    const wrapper = { className: '', children: [], appendChild: (n) => wrapper.children.push(n) };
    const input = {
        type: 'password',
        dataset: {},
        classList: makeClassList(),
        parentNode: { insertBefore: () => {} },
    };
    const doc = {
        queried: false,
        querySelectorAll: () => {
            doc.queried = true;
            return [input];
        },
        createElement: (tag) => (tag === 'button' ? btn : wrapper),
    };
    return { doc, input, btn, eyeOpen, eyeOff };
}

describe('password reveal', () => {
    it('returns 0 without a DOM', () => {
        assert.equal(initPasswordReveals(null), 0);
    });

    it('toggles input type and icons on click', () => {
        const { doc, input, btn, eyeOpen, eyeOff } = makeFakeDom();
        assert.equal(initPasswordReveals(doc), 1);
        assert.equal(doc.queried, true);

        btn.click();
        assert.equal(input.type, 'text');
        assert.equal(btn.attrs['aria-pressed'], 'true');
        assert.equal(btn.attrs['aria-label'], 'Hide password');
        assert.equal(eyeOpen.classList.contains('hidden'), true);
        assert.equal(eyeOff.classList.contains('hidden'), false);

        btn.click();
        assert.equal(input.type, 'password');
        assert.equal(btn.attrs['aria-pressed'], 'false');
        assert.equal(eyeOpen.classList.contains('hidden'), false);
        assert.equal(eyeOff.classList.contains('hidden'), true);
    });

    it('skips already-enhanced inputs', () => {
        const { doc, input } = makeFakeDom();
        input.dataset.revealDone = '1';
        // querySelectorAll still returns it, but it must not be wrapped twice
        let wraps = 0;
        const origInsert = input.parentNode.insertBefore;
        input.parentNode.insertBefore = (...a) => {
            wraps += 1;
            return origInsert(...a);
        };
        initPasswordReveals(doc);
        assert.equal(wraps, 0);
    });
});
