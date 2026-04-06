#!/usr/bin/env python3
"""
Local development server for PKI Toolkit.

Serves the project root as a static site with the correct MIME types and
security headers required by modern browsers for WebAssembly and ES modules.

Usage:
    python3 scripts/server.py [--port PORT] [--host HOST] [--no-open]

Examples:
    python3 scripts/server.py                 # http://localhost:8080
    python3 scripts/server.py --port 3000     # http://localhost:3000
    python3 scripts/server.py --host 0.0.0.0  # bind to all interfaces
"""

import argparse
import os
import sys
import http.server
import socketserver
import threading
from pathlib import Path


# ---------------------------------------------------------------------------
# MIME type overrides
# ---------------------------------------------------------------------------
MIME_OVERRIDES = {
    ".wasm": "application/wasm",
    ".js":   "text/javascript; charset=utf-8",
    ".mjs":  "text/javascript; charset=utf-8",
    ".html": "text/html; charset=utf-8",
    ".css":  "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".svg":  "image/svg+xml; charset=utf-8",
}

# Security / compatibility headers added to every response.
# Cross-Origin-Embedder-Policy + Cross-Origin-Opener-Policy enable
# SharedArrayBuffer (required by some Emscripten builds).
EXTRA_HEADERS = {
    "Cross-Origin-Opener-Policy":   "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "X-Content-Type-Options":       "nosniff",
    "Cache-Control":                "no-store",
}

# ANSI colour helpers (disabled on Windows or non-TTY)
_USE_COLOUR = sys.stdout.isatty() and sys.platform != "win32"

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _USE_COLOUR else text

GREEN  = lambda t: _c("32", t)
YELLOW = lambda t: _c("33", t)
CYAN   = lambda t: _c("36", t)
BOLD   = lambda t: _c("1",  t)
DIM    = lambda t: _c("2",  t)
RED    = lambda t: _c("31", t)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------
class DevHandler(http.server.SimpleHTTPRequestHandler):
    """Static file handler with corrected MIME types and dev-friendly headers."""

    def end_headers(self) -> None:
        suffix = Path(self.path.split("?")[0]).suffix.lower()
        mime = MIME_OVERRIDES.get(suffix)
        if mime:
            self.send_header("Content-Type", mime)
        for name, value in EXTRA_HEADERS.items():
            self.send_header(name, value)
        super().end_headers()

    def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
        code = args[1] if len(args) > 1 else "???"
        try:
            code_int = int(code)
            colour = GREEN if code_int < 300 else (YELLOW if code_int < 400 else RED)
        except ValueError:
            colour = DIM

        method_path = args[0] if args else fmt
        print(
            f"  {DIM(self.log_date_time_string())}  "
            f"{colour(str(code))}  "
            f"{method_path}"
        )

    def log_error(self, fmt: str, *args) -> None:  # type: ignore[override]
        print(RED(f"  ERROR  {fmt % args}"), file=sys.stderr)


# ---------------------------------------------------------------------------
# Server bootstrap
# ---------------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PKI Toolkit local development server",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=int(os.environ.get("PORT", 8080)),
        help="TCP port to listen on (default: 8080, or $PORT env var)",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("HOST", "127.0.0.1"),
        help="Interface to bind to (default: 127.0.0.1, or $HOST env var). "
             "Use 0.0.0.0 to expose on all interfaces.",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Do not attempt to open the browser automatically.",
    )
    return parser.parse_args()


def _open_browser(url: str) -> None:
    """Try to open the browser after a short delay (non-fatal)."""
    import time, webbrowser
    time.sleep(0.4)
    try:
        webbrowser.open(url)
    except Exception:
        pass


def main() -> None:
    args = parse_args()

    # Resolve the project root (one level up from scripts/)
    project_root = Path(__file__).resolve().parent.parent
    os.chdir(project_root)

    socketserver.TCPServer.allow_reuse_address = True

    try:
        with socketserver.TCPServer((args.host, args.port), DevHandler) as httpd:
            display_host = "localhost" if args.host in ("", "0.0.0.0", "127.0.0.1") else args.host
            url = f"http://{display_host}:{args.port}"

            print()
            print(f"  {BOLD('PKI Toolkit')} — local dev server")
            print(f"  {DIM('Serving')}  {CYAN(str(project_root))}")
            print(f"  {DIM('URL')}      {CYAN(url)}")
            if args.host == "0.0.0.0":
                print(f"  {YELLOW('⚠  Bound to all interfaces — accessible on the local network')}")
            print(f"  {DIM('Stop')}     Ctrl+C")
            print()

            if not args.no_open:
                threading.Thread(target=_open_browser, args=(url,), daemon=True).start()

            httpd.serve_forever()

    except OSError as exc:
        if exc.errno == 98:  # Address already in use
            print(RED(f"\n  Port {args.port} is already in use. Try --port <another port>."), file=sys.stderr)
        else:
            print(RED(f"\n  Failed to start server: {exc}"), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n  {DIM('Server stopped.')}")


if __name__ == "__main__":
    main()
