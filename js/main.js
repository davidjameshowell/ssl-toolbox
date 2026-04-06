import { initNavigation } from './navigation.js';
import { initVaultBindings, updateVaultUI } from './vault.js';
import { initPfxTool } from './tools/pfx.js';
import { initDecoderTool } from './tools/decoder.js';
import { initMatcherTool } from './tools/matcher.js';
import { initConverterTool } from './tools/converter.js';

function initApp() {
    initNavigation();
    initVaultBindings();
    initPfxTool();
    initDecoderTool();
    initMatcherTool();
    initConverterTool();
    updateVaultUI();
}

initApp();
