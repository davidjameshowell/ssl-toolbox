import { initNavigation } from './navigation.js';
import { initTheme } from './theme.js';
import { initVaultBindings, updateVaultUI } from './vault.js';
import { initPfxTool } from './tools/pfx.js';
import { initDecoderTool } from './tools/decoder.js';
import { initMatcherTool } from './tools/matcher.js';
import { initConverterTool } from './tools/converter.js';

function initApp() {
    initTheme();
    initNavigation();
    initVaultBindings();
    initPfxTool();
    initDecoderTool();
    initMatcherTool();
    initConverterTool();
    updateVaultUI();
}

initApp();
