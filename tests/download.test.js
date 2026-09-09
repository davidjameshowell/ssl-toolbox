import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { downloadFile } from '../js/utils/download.js';

describe('download helper', () => {
    it('creates a blob URL, clicks, and revokes', async () => {
        const seen = {};
        const fakeAnchor = {
            set href(v) { seen.href = v; },
            get href() { return seen.href; },
            download: '',
            click() { seen.clicked = true; },
        };
        global.Blob = class FakeBlob {
            constructor(parts, opts) { seen.parts = parts; seen.opts = opts; }
        };
        global.URL = { createObjectURL() { seen.created = true; return 'blob:fake'; }, revokeObjectURL(u) { seen.revoked = u; } };
        global.document = { body: { appendChild() { seen.appended = true; }, removeChild() { seen.removed = true; } }, createElement: () => fakeAnchor };

        downloadFile('PEM-DATA', 'key.pem');

        assert.equal(seen.created, true);
        assert.equal(seen.href, 'blob:fake');
        assert.equal(fakeAnchor.download, 'key.pem');
        assert.equal(seen.clicked, true);
        assert.equal(seen.revoked, 'blob:fake');

        delete global.Blob;
        delete global.URL;
        delete global.document;
    });
});
