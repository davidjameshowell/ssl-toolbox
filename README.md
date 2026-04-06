# WebAssembly PFX Decode Toolkit

Browser-based PKI utilities powered by WebAssembly OpenSSL.

## Features

- PFX extractor
- Certificate decoder
- Key and cert matcher
- Certificate converter
- Local in-browser processing (no server-side crypto operations)

## Project Structure

- `index.html`: Main UI and static entry page.
- `js/`: App source code split by feature.
- `vendor/openssl/`: Emscripten-generated OpenSSL runtime (`openssl.js`, `openssl.wasm`).
- `scripts/server.py`: Local static server with WASM MIME support.
- `archive/`: Non-runtime backup artifacts.
- `Dockerfile`: Reproducible OpenSSL WebAssembly build container.

## Local Development

Run the local static server:

```bash
python3 scripts/server.py
```

Then open:

- `http://localhost:8080`

## Cloudflare Pages

This project is static and compatible with Cloudflare Pages.

Recommended settings:

- Framework preset: `None`
- Build command: *(empty)*
- Build output directory: `/` (root)

## Notes

- `vendor/openssl/` assets are loaded directly by `index.html`.
- Keep `openssl.js` and `openssl.wasm` in the same folder so runtime asset loading works.
