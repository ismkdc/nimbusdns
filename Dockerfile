# =============================================================================
# NimbusDNS — Distroless multi-stage build
# =============================================================================
FROM docker.io/rust:1.96-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libsqlite3-dev libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin nimbusdns

FROM debian:bookworm-slim AS libs
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM gcr.io/distroless/cc-debian12
COPY --from=libs /lib/x86_64-linux-gnu/libssl.so* /lib/x86_64-linux-gnu/
COPY --from=libs /lib/x86_64-linux-gnu/libcrypto.so* /lib/x86_64-linux-gnu/
COPY --from=libs /lib/x86_64-linux-gnu/libsqlite3.so* /lib/x86_64-linux-gnu/
COPY --from=libs /usr/lib/x86_64-linux-gnu/libssl.so* /usr/lib/x86_64-linux-gnu/
COPY --from=libs /usr/lib/x86_64-linux-gnu/libcrypto.so* /usr/lib/x86_64-linux-gnu/
COPY --from=libs /usr/lib/x86_64-linux-gnu/libsqlite3.so* /usr/lib/x86_64-linux-gnu/
COPY --from=libs /etc/ssl /etc/ssl
COPY --from=builder /app/target/release/nimbusdns /usr/bin/nimbusdns
COPY --from=builder /app/nimbus.toml /etc/nimbusdns/nimbus.toml

EXPOSE 53/udp 53/tcp 80/tcp 67/udp
ENTRYPOINT ["/usr/bin/nimbusdns"]
CMD ["-f"]
