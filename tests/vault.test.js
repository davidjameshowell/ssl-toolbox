import { describe, it, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { vaultStore } from '../js/state.js';
import { saveToVault, getVaultItemById, removeFromVault, clearVault, detectVaultType, vaultItemTarget, openVaultItem } from '../js/vault.js';

beforeEach(() => {
    vaultStore.length = 0;
});

describe('memory vault', () => {
    it('saves cert and key items with unique ids', () => {
        saveToVault('example', 'cert', '---CERT---');
        saveToVault('example', 'key', '---KEY---');
        assert.equal(vaultStore.length, 2);
        assert.notEqual(vaultStore[0].id, vaultStore[1].id);
        assert.equal(getVaultItemById(vaultStore[0].id).data, '---CERT---');
    });

    it('dedupes identical data', () => {
        saveToVault('a', 'cert', 'same');
        saveToVault('b', 'cert', 'same');
        assert.equal(vaultStore.length, 1);
    });

    it('ignores empty data and misses return null', () => {
        saveToVault('x', 'cert', '');
        saveToVault('y', 'cert', null);
        assert.equal(vaultStore.length, 0);
        assert.equal(getVaultItemById('nope'), null);
    });

    it('clears all items', () => {
        saveToVault('a', 'cert', '1');
        saveToVault('b', 'key', '2');
        clearVault();
        assert.equal(vaultStore.length, 0);
    });

    it('removes single items by id', () => {
        saveToVault('a', 'cert', '1');
        saveToVault('b', 'key', '2');
        const id = vaultStore[0].id;
        assert.equal(removeFromVault(id), true);
        assert.equal(vaultStore.length, 1);
        assert.equal(vaultStore[0].label, 'b');
        assert.equal(removeFromVault('missing'), false);
    });

    it('classifies keys, CSRs and certs for storage', () => {
        assert.equal(detectVaultType('-----BEGIN PRIVATE KEY-----\nabc'), 'key');
        assert.equal(detectVaultType('-----BEGIN ENCRYPTED PRIVATE KEY-----\nabc'), 'key');
        assert.equal(detectVaultType('-----BEGIN CERTIFICATE REQUEST-----\nabc'), 'csr');
        assert.equal(detectVaultType('-----BEGIN CERTIFICATE-----\nabc'), 'cert');
        assert.equal(detectVaultType('-----BEGIN PKCS7-----\nabc'), 'cert');
        assert.equal(detectVaultType(''), 'cert');
    });

    it('routes item types to the right tool', () => {
        assert.deepEqual(vaultItemTarget('cert'), { tab: 'decoderTab', textareaId: 'pemInput' });
        assert.deepEqual(vaultItemTarget('csr'), { tab: 'decoderTab', textareaId: 'pemInput' });
        assert.deepEqual(vaultItemTarget('key'), { tab: 'matcherTab', textareaId: 'matchInput1' });
    });

    it('opens an item into its tool textarea without a DOM', () => {
        saveToVault('a', 'cert', '1');
        // No document in Node — must fail closed, not throw.
        assert.equal(openVaultItem(vaultStore[0].id), false);
        assert.equal(openVaultItem('missing'), false);
    });
});
