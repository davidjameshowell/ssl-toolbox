# Use the official Emscripten SDK base image
FROM emscripten/emsdk:latest

WORKDIR /build

# Download OpenSSL 3.x source
RUN apt-get update && apt-get install -y wget && \
    wget https://github.com/openssl/openssl/releases/download/openssl-3.6.1/openssl-3.6.1.tar.gz && \
    tar -xzf openssl-3.6.1.tar.gz

WORKDIR /build/openssl-3.6.1

# Configure OpenSSL for WebAssembly.
# Pass linker flags directly to Configure so OpenSSL emits a modularized WebAssembly build.
RUN CC=emcc AR=emar RANLIB=emranlib ./Configure linux-generic32 \
    no-shared no-asm no-threads no-engine no-dso no-hw \
    no-sock no-ui-console no-tests \
    enable-legacy \
    LDFLAGS="-sWASM=1 -sEXIT_RUNTIME=0 -sINVOKE_RUN=0 -sEXPORTED_RUNTIME_METHODS=callMain,FS,ENV -sFORCE_FILESYSTEM=1 -sALLOW_MEMORY_GROWTH=1 -sMODULARIZE=1 -sEXPORT_NAME=createOpenSSL"

# Build ONLY the core software, skipping testing suites.
RUN emmake make build_sw -j$(nproc)

# Move the finished binaries to the main build directory 
RUN cp apps/openssl /build/openssl.js && \
    cp apps/openssl.wasm /build/openssl.wasm
