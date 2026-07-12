# =============================================================================
# NimbusDNS -- Distroless multi-stage build
# =============================================================================
FROM docker.io/rust:1.97-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libsqlite3-dev libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin nimbusdns

FROM gcr.io/distroless/cc-debian13
COPY --from=builder /etc/ssl/certs /etc/ssl/certs
COPY --from=builder /app/target/release/nimbusdns /usr/bin/nimbusdns
COPY --from=builder /app/nimbus.toml /etc/nimbusdns/nimbus.toml

EXPOSE 53/udp 53/tcp 80/tcp 67/udp
ENTRYPOINT ["/usr/bin/nimbusdns"]
CMD ["-f"]
