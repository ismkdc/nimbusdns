# =============================================================================
# NimbusDNS -- Distroless multi-stage build
# =============================================================================
FROM docker.io/rust:1.96-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libsqlite3-dev libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin nimbusdns

FROM debian:trixie-slim AS libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* && \
    # Copy all needed .so files to /runtime with ldconfig
    mkdir -p /runtime/lib /runtime/usr/lib && \
    ldconfig -p | awk '{print $NF}' | grep -E 'lib(ssl|crypto|sqlite3)' | \
    while read f; do cp -L "$f" /runtime/lib/ 2>/dev/null; done && \
    cp -L /lib/*/libc.so.* /lib/*/libm.so.* /lib/*/libpthread.so.* \
          /lib/*/libdl.so.* /lib/*/libresolv.so.* /lib/*/librt.so.* \
          /runtime/lib/ 2>/dev/null; \
    cp -L /usr/lib/*/libssl.so.* /usr/lib/*/libcrypto.so.* \
          /usr/lib/*/libsqlite3.so.* /runtime/usr/lib/ 2>/dev/null; \
    echo "Runtime libs collected"

FROM gcr.io/distroless/cc-debian13
COPY --from=libs /runtime/lib/* /lib/
COPY --from=libs /runtime/usr/lib/* /usr/lib/
COPY --from=libs /etc/ssl /etc/ssl
COPY --from=builder /app/target/release/nimbusdns /usr/bin/nimbusdns
COPY --from=builder /app/nimbus.toml /etc/nimbusdns/nimbus.toml

EXPOSE 53/udp 53/tcp 80/tcp 67/udp
ENTRYPOINT ["/usr/bin/nimbusdns"]
CMD ["-f"]
