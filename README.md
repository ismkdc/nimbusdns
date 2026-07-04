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
  -v /etc/nimbusdns:/etc/nimbusdns \
  -v /var/lib/nimbusdns:/tmp \
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
      - /var/lib/nimbusdns:/tmp
    environment:
      - FTLCONF_dns_upstreams=tls://8.8.8.8#853#dns.google
      - FTLCONF_dns_bind=0.0.0.0:53
      - FTLCONF_dns_blocking_mode=NULL
      - FTLCONF_dns_query_log=true
      - FTLCONF_webserver_port=80o
      - FTLCONF_dhcp_enabled=true
      - FTLCONF_dhcp_pool_start=192.168.1.100
      - FTLCONF_dhcp_pool_end=192.168.1.200
      - FTLCONF_dhcp_router=192.168.1.1
      - FTLCONF_dhcp_lease_time=86400
      - FTLCONF_blocking_source_url=https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts
      - FTLCONF_blocking_refresh_interval=86400
```

Save as `docker-compose.yml` and run:

```bash
docker compose up -d
```

## Configuration

Edit `/etc/nimbusdns/nimbus.toml`:

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

MIT
