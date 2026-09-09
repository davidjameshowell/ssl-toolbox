# PKI Toolkit

> Browser-based PKI utilities powered by WebAssembly OpenSSL. Zero server-side processing. Zero data egress.

[![Deploy](https://github.com/davidjameshowell/ssl-toolbox/actions/workflows/deploy-cloudflare-pages.yml/badge.svg)](https://github.com/davidjameshowell/ssl-toolbox/actions/workflows/deploy-cloudflare-pages.yml)

PKI Toolkit is a fully client-side web application that brings the full power of OpenSSL to the browser. Every cryptographic operation — certificate decoding, PFX extraction, key matching, format conversion — is executed locally by a WebAssembly build of OpenSSL. No data is ever transmitted to a server.

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Local Development](#local-development)
- [Rebuilding the WebAssembly OpenSSL Binary](#rebuilding-the-webassembly-openssl-binary)
- [Deployment](#deployment)
  - [Cloudflare Workers (Static Assets)](#cloudflare-workers-static-assets)
  - [GitHub Actions Workflows](#github-actions-workflows)
  - [Required Secrets and Variables](#required-secrets-and-variables)
- [Security Model](#security-model)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)

---

## Features

| Tool | Description |
|---|---|
| **Cert Decoder** | Paste PEM certificates and CSRs to inspect subject, issuer, SANs, serial number, signature algorithm, public key, key usages, SHA-256 fingerprint, and expiry status. Chains are sorted leaf→root automatically. |
| **PFX Extractor** | Upload a `.pfx` or `.p12` archive (optionally password-protected) to extract the certificate chain and private key as PEM files. Multi-cert chains list every certificate; certs-only archives work too. Results are auto-saved to the Memory Vault. |
| **Key Matcher** | Verify that a private key corresponds to a certificate or CSR by extracting and comparing public keys. Supports encrypted keys. |
| **Key Decryptor** | Remove the password from an encrypted PEM private key: paste, load from the Vault, or upload the file, enter its password, and get cleartext PEM (text + file download), with auto PKCS#8/Traditional detection and a key-info summary. |
| **Cert Converter** | Convert between PEM, DER, P7B / PKCS#7 (including P7B unpacking back to PEM), and PFX / PKCS#12 formats entirely in-browser. PFX builds accept an optional private-key password for encrypted keys. |
| **Memory Vault** | A session-scoped in-memory store. Save certs, keys, and CSRs between tools without re-uploading. Supports manual upload (auto-detects cert vs key vs CSR), per-item open-in-tool / download / remove, and one-click clear. Cleared on tab close. |

---

## How It Works

OpenSSL is compiled to WebAssembly using [Emscripten](https://emscripten.org/). The resulting `openssl.wasm` binary is served as a static asset and loaded by the browser at runtime. When you interact with a tool:

1. Your file or pasted data is read by the browser's `FileReader` API and stays in tab memory.
2. A sandboxed WASM instance of OpenSSL is initialised in the browser's JavaScript engine.
3. Input bytes are written to the WASM module's linear memory and the appropriate `openssl` subcommand is executed (`x509`, `pkcs12`, `pkey`, `req`, etc.).
4. OpenSSL writes its output back to linear memory; JavaScript reads the result and renders it in the UI or offers it as a browser download.
5. The WASM instance is discarded.

At no point is there an outbound network request carrying user data. You can verify this yourself: open DevTools → Network and apply the XHR/Fetch filter while using any tool.

The WASM sandbox has no access to the OS, filesystem, or network beyond what the JavaScript host explicitly provides — see [Security Model](#security-model) for details.

---

## Project Structure

```
.
├── index.html                      # Single-page application entry point
├── js/
│   ├── main.js                     # App bootstrap and module initialisation
│   ├── navigation.js               # Tab switching logic
│   ├── state.js                    # Shared app state (vault, openssl config)
│   ├── vault.js                    # Memory Vault logic and sidebar UI
│   ├── tools/
│   │   ├── decoder.js              # Certificate Decoder tool
│   │   ├── pfx.js                  # PFX Extractor tool
│   │   ├── matcher.js              # Key Matcher tool
│   │   ├── decryptor.js            # Key Decryptor tool
│   │   └── converter.js            # Certificate Converter tool
│   └── utils/
│       ├── cert.js                 # Certificate metadata parsing helpers
│       ├── decrypt.js              # Encrypted-key decrypt/inspect helpers
│       ├── reveal.js               # Password show/hide toggle helper
│       └── download.js             # Browser download helper
├── vendor/
│   └── openssl/
│       ├── openssl.js              # Emscripten JS glue layer
│       └── openssl.wasm            # Compiled OpenSSL WebAssembly binary
├── scripts/
│   ├── server.py                   # Local static server with correct WASM MIME type
│   └── rebuild_openssl_if_changed.sh  # Rebuilds vendor/openssl/ via Docker when Dockerfile changes
├── Dockerfile                      # Reproducible Emscripten + OpenSSL WASM build
├── .wranglerignore                 # Files excluded from Cloudflare asset uploads
└── .github/
    └── workflows/
        ├── deploy-cloudflare-pages.yml      # Preview and production deploy workflow
        └── cleanup-preview-workers.yml      # Interactive workflow to bulk-delete preview workers
```

---

## Local Development

### Prerequisites

- Python 3 (for the local dev server)
- A modern browser with WebAssembly support (Chrome, Firefox, Safari, Edge)

### Start the development server

```bash
python3 scripts/server.py
```

Then open **http://localhost:8080**. The server automatically attempts to open the browser for you on start.

**CLI options**

| Flag | Default | Description |
|---|---|---|
| `--port PORT` / `-p PORT` | `8080` (or `$PORT`) | TCP port to listen on |
| `--host HOST` | `127.0.0.1` (or `$HOST`) | Interface to bind to. Use `0.0.0.0` to expose on the local network |
| `--no-open` | — | Skip automatic browser launch |

Examples:

```bash
python3 scripts/server.py --port 3000
python3 scripts/server.py --host 0.0.0.0         # LAN-accessible
PORT=9000 python3 scripts/server.py
python3 scripts/server.py --no-open              # CI / headless environments
```

> **Why a custom server?**
> Browsers enforce strict rules on WebAssembly. The server sets three things that a plain `python -m http.server` does not:
> - `Content-Type: application/wasm` — required for the browser to execute `.wasm` files
> - `Cross-Origin-Opener-Policy: same-origin` + `Cross-Origin-Embedder-Policy: require-corp` — enables `SharedArrayBuffer`, which some Emscripten builds require
> - `Cache-Control: no-store` — prevents stale assets during active development
>
> Opening `index.html` directly via `file://` will **not** work.

### Docker (optional)

To run the dev server in a container:

```bash
docker run --rm -p 8080:8080 -v "$(pwd)":/app -w /app python:3 python scripts/server.py --no-open
```

---

## Rebuilding the WebAssembly OpenSSL Binary

The `vendor/openssl/` binaries are pre-built and committed to the repository. You only need to rebuild if you want to update the OpenSSL version or change the Emscripten build flags.

### Automatic (recommended)

The helper script rebuilds only when the `Dockerfile` has changed since the last build:

```bash
bash scripts/rebuild_openssl_if_changed.sh
```

This will:
1. Build the Docker image defined in `Dockerfile` (Emscripten SDK + OpenSSL source)
2. Compile OpenSSL to WebAssembly inside the container
3. Copy the resulting `openssl.js` and `openssl.wasm` into `vendor/openssl/`
4. Skip the entire build if the `Dockerfile` hash hasn't changed

### Manual

```bash
# Build the Docker image
docker build -t pki-toolkit-openssl-builder .

# Extract the compiled artifacts
docker run --rm -v "$(pwd)/vendor/openssl":/out pki-toolkit-openssl-builder \
  sh -c "cp /build/openssl.js /build/openssl.wasm /out/"
```

### Build configuration

The `Dockerfile` compiles OpenSSL with the following key flags:

| Flag | Purpose |
|---|---|
| `linux-generic32` | Generic 32-bit target required for WASM |
| `no-shared`, `no-asm`, `no-threads` | Removes incompatible features |
| `enable-legacy` | Enables legacy provider for older PFX formats (e.g. RC2/3DES) |
| `-sMODULARIZE=1 -sEXPORT_NAME=createOpenSSL` | Wraps the module in a factory function for safe re-instantiation |
| `-sALLOW_MEMORY_GROWTH=1` | Allows the WASM heap to grow for large certificates |
| `-sFORCE_FILESYSTEM=1` | Emscripten virtual FS (required for OpenSSL file I/O model) |

---

## Deployment

### Cloudflare Workers (Static Assets)

This project deploys as a static asset bundle to a [Cloudflare Worker](https://developers.cloudflare.com/workers/static-assets/). No Worker script is written — Wrangler is invoked with `--assets .` which instructs Cloudflare to serve the directory as a static site.

A `.wranglerignore` file excludes non-web assets (`.git/`, `.github/`, `Dockerfile`, `scripts/`, `archive/`, `README.md`) from uploads.

There is no `wrangler.toml` — all configuration is passed as CLI arguments in the workflow.

### GitHub Actions Workflows

#### `deploy-cloudflare-pages.yml`

Triggered on:
- `push` to any branch → deploys a **preview worker**
- `push` of a `v*` tag → deploys the **production worker**
- `delete` of a branch → **deletes** the corresponding preview worker
- `workflow_dispatch` → manual trigger

**Preview worker naming**

Preview workers are named `{WORKER_NAME}-preview-{branch-slug}`. Because Cloudflare enforces a 54-character limit on worker names when previews are enabled, long branch slugs are automatically shortened: the slug is truncated to a readable prefix and a 6-character SHA-256 hash of the full slug is appended (e.g. `my-worker-preview-feature-my-long-bran-a1b2c3`). The same formula is used in the cleanup job so names always match.

#### `cleanup-preview-workers.yml` (manual)

An interactive `workflow_dispatch` workflow to bulk-delete stale preview workers. Useful after merging a batch of branches or resetting a deployment environment.

**Inputs:**

| Input | Type | Default | Description |
|---|---|---|---|
| `keep` | string | *(blank)* | Comma-separated branch names to spare. Applies the same slug logic as the deploy workflow. |
| `dry_run` | boolean | `false` | List workers that would be deleted without actually deleting them. |

The production worker is always protected regardless of the `keep` input.

### Required Secrets and Variables

Configure the following in **Settings → Secrets and variables → Actions** on the repository:

| Name | Type | Required | Description |
|---|---|---|---|
| `CLOUDFLARE_API_TOKEN` | Secret | Yes | API token with Workers Scripts Edit and Account Settings Read permissions |
| `CLOUDFLARE_ACCOUNT_ID` | Secret | Yes | Your Cloudflare account ID |
| `CLOUDFLARE_WORKER_NAME` | Variable | Yes | Base name for the production worker (e.g. `pki-toolkit`) |
| `CLOUDFLARE_WORKER_COMPATIBILITY_DATE` | Variable | No | Overrides the default compatibility date (`2026-04-06`) |

---

## Security Model

PKI Toolkit is designed around the principle that users should never need to trust a server with private key material.

- **No server-side crypto.** All OpenSSL operations run inside a WebAssembly sandbox in your browser tab. The WASM runtime enforces a hard boundary: the module cannot open network sockets, read host files, or access any OS resource outside of what the JavaScript host intentionally exposes.
- **No persistent storage.** The Memory Vault is a plain JavaScript array in the page's runtime memory. It is never written to `localStorage`, `sessionStorage`, IndexedDB, or cookies. Closing or refreshing the tab immediately discards all vault contents. (The only `localStorage` entry is your light/dark theme choice.)
- **No telemetry.** The application makes no outbound requests with user data. The only outbound requests are for the Tailwind CSS CDN on page load (a standard CDN request with no user data) and Cloudflare's own Wrangler telemetry during deployment (which is unrelated to runtime usage). Fonts are self-hosted same-origin `woff2` files — no font CDN.
- **Auditable.** The full source is available in this repository. You can inspect the network activity in DevTools → Network while using any tool to verify no data leaves the browser.
- **Offline-capable.** Once the page and its assets have loaded, the application works with no network connection.

---

## Contributing

Contributions are welcome. Please follow the process below.

### Branching

- Branch from `main`: `feature/<short-description>`, `fix/<short-description>`, `chore/<short-description>`
- Keep branches focused on a single concern
- Delete branches after merging (the cleanup workflow will automatically remove the preview worker)

### Pull Requests

- Target `main`
- Include a clear description of what changed and why
- Preview deployments are created automatically for every branch push — include the preview URL in the PR description if it demonstrates a visual change
- Squash or rebase before merging to keep the commit history linear

### Commit Style

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add certificate transparency log lookup
fix: restore scroll container on localTab
chore: bump openssl to 3.6.1
docs: update deployment prerequisites
```

### Updating the WASM binary

If your change requires a new OpenSSL build, run `scripts/rebuild_openssl_if_changed.sh`, commit the updated `vendor/openssl/openssl.js` and `vendor/openssl/openssl.wasm`, and note the OpenSSL version in the PR description.

---

## Disclaimer

This project was built with the assistance of AI — crafted with love by [GitHub Copilot](https://github.com/features/copilot).

All cryptographic logic, WebAssembly integration, and security design decisions were reviewed by the project maintainers. AI assistance was used for UI implementation, tooling, workflow automation, and documentation. No AI-generated code handles key material directly — that responsibility belongs entirely to the auditable, well-established OpenSSL library running in the WASM sandbox.

Want to build something like this yourself? GitHub Copilot is available at [github.com/features/copilot](https://github.com/features/copilot).

