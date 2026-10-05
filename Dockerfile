# Pinned Emscripten SDK — reproducible WASM builds instead of tracking :latest.
FROM emscripten/emsdk:3.1.74

WORKDIR /build

ARG OPENSSL_VERSION=3.6.1

# Download OpenSSL 3.x source
RUN apt-get update && apt-get install -y --no-install-recommends wget ca-certificates && \
    wget -q "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" && \
    tar -xzf "openssl-${OPENSSL_VERSION}.tar.gz" && \
    mv "openssl-${OPENSSL_VERSION}" openssl-src && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build/openssl-src

# Configure OpenSSL for WebAssembly.
#
# Optimisation notes:
#  - `CC="emcc -O3"` compiles the C sources optimised (emcc defaults to -O0
#    otherwise); the same -O3 is added to LDFLAGS for the final link.
#  - Only the feature set this toolkit exercises is kept. The CLI still builds
#    x509 / req / pkey / pkcs7 / pkcs12 / crl2pkcs7, but SRP, OCSP, CMP, TS, CT
#    and datagram BIOs are dropped to shrink the binary.
#  - `enable-legacy` is retained (legacy PKCS#12 PBE + RC2/3DES support).
#  - `-sENVIRONMENT=web,worker,node` keeps the Node test harness working while
#    allowing future worker offload.
RUN CC="emcc -O3" AR=emar RANLIB=emranlib ./Configure linux-generic32 \
    no-shared no-asm no-threads no-engine no-dso no-hw \
    no-sock no-ui-console no-tests \
    no-srp no-ocsp no-cmp no-ts no-ct no-dgram \
    enable-legacy \
    LDFLAGS="-O3 -sWASM=1 -sEXIT_RUNTIME=0 -sINVOKE_RUN=0 -sASSERTIONS=0 -sMALLOC=emmalloc -sENVIRONMENT=web,worker,node -sEXPORTED_RUNTIME_METHODS=callMain,FS,ENV -sFORCE_FILESYSTEM=1 -sALLOW_MEMORY_GROWTH=1 -sMODULARIZE=1 -sEXPORT_NAME=createOpenSSL"

# Build ONLY the core software, skipping testing suites.
RUN emmake make build_sw -j$(nproc)

# Move the finished binaries to the main build directory
RUN cp apps/openssl /build/openssl.js && \
    cp apps/openssl.wasm /build/openssl.wasm
