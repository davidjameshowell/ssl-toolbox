import { initNavigation } from './navigation.js';
import { initPasswordReveals } from './utils/reveal.js';
import { initTheme } from './theme.js';
import { initVaultBindings, updateVaultUI } from './vault.js';
import { initPfxTool } from './tools/pfx.js';
import { initDecoderTool } from './tools/decoder.js';
import { initMatcherTool } from './tools/matcher.js';
import { initDecryptorTool } from './tools/decryptor.js';
import { initConverterTool } from './tools/converter.js';
import { preloadEngine } from './openssl/engine.js';

/**
 * P1: fetch + compile the 3 MB wasm binary once, during idle time, so the first
 * user-initiated operation is a fetch-free, compile-free instantiation. Runs
 * after the UI is wired so it never delays interactivity.
 */
function warmUpEngine() {
    const run = () => {
        preloadEngine().catch(() => {});
    };
    if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(run, { timeout: 3000 });
    } else {
        setTimeout(run, 1000);
    }
}

function initApp() {
    initTheme();
    initPasswordReveals();
    initNavigation();
    initVaultBindings();
    initPfxTool();
    initDecoderTool();
    initMatcherTool();
    initDecryptorTool();
    initConverterTool();
    updateVaultUI();
    warmUpEngine();
}

initApp();
