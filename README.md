# NimbusDNS

DNS-over-TLS server with web panel, DHCP, ad blocking, and admin auth.

## Features

- **DNS-over-TLS (DoT)** - Encrypted upstream DNS to Cloudflare, Google, Quad9, OpenDNS, Mullvad
- **Ad Blocking** - StevenBlack hosts blocklist with auto-refresh
- **Web Panel** - Dark theme, responsive, setup wizard, session auth + optional TOTP
- **DHCP Server** - Built-in DHCP with IP pool management
- **Query Log** - Searchable query history with overTime stats
- **Performance** - Rust, LRU cache, batch DB writes, EDNS0, graceful shutdown

## Quick Start

### Docker

```bash
docker pull ismkdc/nimbusdns:latest

docker run -d --name nimbusdns --restart unless-stopped --network host \
  -v /etc/nimbusdns/nimbus.toml:/etc/nimbusdns/nimbus.toml:ro \
  -v nimbusdns-data:/var/lib/nimbusdns \
  --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  ismkdc/nimbusdns:latest
```

### Docker Compose

```yaml
services:
  nimbusdns:
    image: ismkdc/nimbusdns:latest
    container_name: nimbusdns
    restart: unless-stopped
    network_mode: "host"
    cap_add:
      - NET_ADMIN
      - NET_BIND_SERVICE
    volumes:
      - nimbusdns-data:/var/lib/nimbusdns
    environment:
      - NIMBUS_dns_upstreams=tls://8.8.8.8#853#dns.google
      - NIMBUS_dns_bind=0.0.0.0:53
      - NIMBUS_dns_blocking_mode=NULL
      - NIMBUS_dns_query_log=true
      - NIMBUS_webserver_port=80o
      - NIMBUS_dhcp_enabled=true
      - NIMBUS_dhcp_pool_start=192.168.1.100
      - NIMBUS_dhcp_pool_end=192.168.1.200
      - NIMBUS_dhcp_router=192.168.1.1
      - NIMBUS_dhcp_lease_time=86400
      - NIMBUS_blocking_source_url=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      - NIMBUS_blocking_refresh_interval=86400
    volumes:
      - nimbusdns-data:/var/lib/nimbusdns

volumes:
  nimbusdns-data:
```

Save as `docker-compose.yml` and run:

```bash
docker compose up -d
```

## Configuration

The same configuration file format works on all platforms. Place `nimbus.toml` next to the binary or at:

- **Linux/macOS:** `/etc/nimbusdns/nimbus.toml`
- **macOS (homebrew):** `$(brew --prefix)/etc/nimbusdns/nimbus.toml`
- **Windows:** `%PROGRAMDATA%\nimbusdns\nimbus.toml`

Example `nimbus.toml`:

```toml
[dns]
upstreams = [{Tls = {address = "8.8.8.8", port = 853, hostname = "dns.google"}}]
bind = "0.0.0.0:53"
blocking-mode = "NULL"
query-log = true

[webserver]
ports = ["80o"]

[dhcp]
enabled = true
pool-start = "192.168.1.100"
pool-end = "192.168.1.200"
router = "192.168.1.1"
lease-time = 86400

[blocking]
source-url = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
refresh-interval = 86400
```

## Build from Source

```bash
cargo build --release --bin nimbusdns
```

## Docker Build

```bash
docker build -t nimbusdns .
```

## License

[MIT](LICENSE)
