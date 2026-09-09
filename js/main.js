import { initNavigation } from './navigation.js';
import { initPasswordReveals } from './utils/reveal.js';
import { initTheme } from './theme.js';
import { initVaultBindings, updateVaultUI } from './vault.js';
import { initPfxTool } from './tools/pfx.js';
import { initDecoderTool } from './tools/decoder.js';
import { initMatcherTool } from './tools/matcher.js';
import { initDecryptorTool } from './tools/decryptor.js';
import { initConverterTool } from './tools/converter.js';

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
}

initApp();
