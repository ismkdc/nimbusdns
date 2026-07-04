# =============================================================================
# NimbusDNS — Distroless multi-stage build
# =============================================================================
FROM docker.io/rust:1.96-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libsqlite3-dev libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin nimbusdns && \
    strip target/release/nimbusdns && \
    # Collect runtime .so files
    mkdir /runtime && \
    ldd target/release/nimbusdns | \
    awk '/=> \// {print $3}' | sort -u | \
    xargs -I{} cp -L --parents {} /runtime/ 2>/dev/null; \
    for lib in libc.so.* libm.so.* libpthread.so.* libdl.so.* \
               libresolv.so.* librt.so.* libssl.so.* libcrypto.so.* \
               libsqlite3.so.*; do \
      find /usr/lib /lib -name "$lib" -exec cp -L --parents {} /runtime/ \; 2>/dev/null; \
    done; \
    find /runtime -name "ld-linux*.so*" -o -name "ld-*.so*" | head -1 || \
      cp -L /lib64/ld-linux-x86-64.so.2 /runtime/lib64/ 2>/dev/null; \
    echo "Runtime libs collected"

FROM gcr.io/distroless/cc-debian12
COPY --from=builder /runtime/ /
COPY --from=builder /app/target/release/nimbusdns /usr/bin/nimbusdns
COPY --from=builder /app/nimbus.toml /etc/nimbusdns/nimbus.toml

EXPOSE 53/udp 53/tcp 80/tcp 67/udp
ENTRYPOINT ["/usr/bin/nimbusdns"]
CMD ["-f"]
