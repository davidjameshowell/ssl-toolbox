#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKERFILE_PATH="$ROOT_DIR/Dockerfile"
VENDOR_DIR="$ROOT_DIR/vendor/openssl"
TARGET_JS="$VENDOR_DIR/openssl.js"
TARGET_WASM="$VENDOR_DIR/openssl.wasm"
IMAGE_TAG="ssl-toolbox-openssl-builder:local"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing required command: $1"
    exit 1
  fi
}

validate_js() {
  local file="$1"
  if [[ ! -s "$file" ]]; then
    echo "Invalid JS artifact: file is missing or empty: $file"
    exit 1
  fi

  # Require at least one non-whitespace character.
  if ! grep -q '[^[:space:]]' "$file"; then
    echo "Invalid JS artifact: file contains only whitespace: $file"
    exit 1
  fi
}

validate_wasm() {
  local file="$1"
  if [[ ! -s "$file" ]]; then
    echo "Invalid WASM artifact: file is missing or empty: $file"
    exit 1
  fi

  # WASM binaries should start with magic bytes: 00 61 73 6d
  local magic
  magic="$(xxd -p -l 4 "$file")"
  if [[ "$magic" != "0061736d" ]]; then
    echo "Invalid WASM artifact: bad magic bytes in $file (got: $magic)"
    exit 1
  fi
}

compare_and_replace() {
  local src="$1"
  local dest="$2"
  local label="$3"

  if [[ ! -f "$dest" ]]; then
    cp "$src" "$dest"
    echo "$label: target missing; copied freshly built artifact."
    return
  fi

  if cmp -s "$src" "$dest"; then
    echo "$label: no changes detected."
  else
    cp "$src" "$dest"
    echo "$label: updated tracked artifact with rebuilt output."
  fi
}

main() {
  require_cmd docker
  require_cmd xxd
  require_cmd grep
  require_cmd cmp

  mkdir -p "$VENDOR_DIR"

  tmp_dir="$(mktemp -d)"
  container_name="ssl_toolbox_openssl_build_$$"
  cleanup() {
    docker rm -f "$container_name" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
  }
  trap cleanup EXIT

  echo "Building OpenSSL WebAssembly image..."
  docker build -f "$DOCKERFILE_PATH" -t "$IMAGE_TAG" "$ROOT_DIR"

  echo "Extracting build artifacts from image..."
  docker create --name "$container_name" "$IMAGE_TAG" >/dev/null
  docker cp "$container_name:/build/openssl.js" "$tmp_dir/openssl.js"
  docker cp "$container_name:/build/openssl.wasm" "$tmp_dir/openssl.wasm"

  validate_js "$tmp_dir/openssl.js"
  validate_wasm "$tmp_dir/openssl.wasm"

  compare_and_replace "$tmp_dir/openssl.js" "$TARGET_JS" "openssl.js"
  compare_and_replace "$tmp_dir/openssl.wasm" "$TARGET_WASM" "openssl.wasm"

  echo "OpenSSL artifacts validated and synchronized."
}

main "$@"
