import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { switchTab } from '../js/navigation.js';

const TABS = ['homeTab', 'localTab', 'pfxTab', 'decoderTab', 'matcherTab', 'converterTab'];

function installDomStub() {
    const elements = {};
    for (const id of [...TABS, 'nav-pfxTab', 'nav-decoderTab', 'nav-matcherTab', 'nav-converterTab']) {
        elements[id] = { classList: { add(c) { this._c = (this._c || new Set()); this._c.add(c); }, remove(c) { (this._c || new Set()).delete(c); }, contains(c) { return (this._c || new Set()).has(c); } }, className: '' };
        // start visible; switchTab will hide all but target
        elements[id].classList.add('hidden');
    }
    global.document = { getElementById: (id) => elements[id] || null };
    return elements;
}

describe('navigation', () => {
    beforeEach(() => {
        installDomStub();
    });

    it('shows target tab and hides others', () => {
        const els = installDomStub();
        switchTab('matcherTab');
        assert.equal(els['matcherTab'].classList.contains('hidden'), false);
        for (const id of TABS.filter((t) => t !== 'matcherTab')) {
            assert.equal(els[id].classList.contains('hidden'), true);
        }
    });

    it('marks active nav entry', () => {
        const els = installDomStub();
        switchTab('decoderTab');
        assert.match(els['nav-decoderTab'].className, /nav-active/);
        assert.doesNotMatch(els['nav-matcherTab'].className, /nav-active/);
        assert.match(els['nav-matcherTab'].className, /nav-item/);
    });
});
