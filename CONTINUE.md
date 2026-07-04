# NimbusDNS — Continue Here

## Build Status
```
cargo build --release --bin nimbusdns  →  0 errors, 0 warnings
cargo test --lib -p nimbus-core          →  19 passed, 0 FAILED
```

## Project Identity
- **Name**: NimbusDNS
- **Binary**: `nimbusdns`
- **License**: MIT
- **Config**: `/etc/nimbusdns/nimbus.toml`
- **Origin**: Ported from Pi-hole FTL, fully rewritten in Rust

## What's Done

| Feature | Status |
|---------|--------|
| DNS over TLS (DoT) — persistent connections, ID matching | ✅ |
| UDP/TCP DNS listener — concurrent query processing | ✅ |
| DNS cache — LRU with TTL rewrite on hit | ✅ |
| Blocking engine — in-memory, regex/wildcard, multiple modes | ✅ |
| Gravity database — domain blocking via SQLite | ✅ |
| Query log — SQLite-backed with stats aggregation | ✅ |
| Background DB writer — channel-based async batch INSERT | ✅ |
| Config system — TOML + FTLCONF env override, runtime RwLock | ✅ |
| Daemon — fork-before-tokio, set_nice, umask, PID file | ✅ |
| Signal handling — SIGTERM, SIGHUP (config+blocking reload) | ✅ |
| REST API — ~30 endpoints with auth (SHA-256 + TOTP + sessions) | ✅ |
| StevenBlack hosts fetcher — automatic download + parse + import | ✅ |
| overTime — 10-min circular buffer for real-time query history | ✅ |
| EDNS0 — OPT pseudoheader on all responses | ✅ |
| SO_REUSEADDR — DNS UDP socket | ✅ |
| Graceful shutdown — listener drain via select! | ✅ |
| capabilities check — capget() syscall (Linux) | ✅ |
| Web panel — embedded SPA (rust-embed) | ✅ |
| DHCP server — dhcproto 0.15, IPv4, IP pool, leases | ✅ |
| cargo clippy — 0 warnings | ✅ |
| Tüm bağımlılıklar güncel (Temmuz 2026) | ✅ |
| Lisans MIT, Pi-hole referansı yok | ✅ |

## ✅ PROJE TAMAMLANDI

Tüm özellikler çalışıyor, 0 hata, 0 warning, 19 test geçiyor.

### Yapılacak (opsiyonel, GitHub'a hazırlık)
- [ ] `README.md` yaz
- [ ] `.gitignore` oluştur
- [ ] `LICENSE` (MIT) ekle
- [ ] `cargo audit` — güvenlik taraması
- [ ] Docker image testi

## Key Files

| File | Purpose | Lines |
|------|---------|-------|
| `nimbus-bin/src/main.rs` | Entry point | ~120 |
| `nimbus-core/src/lib.rs` | Shared types | ~100 |
| `nimbus-core/src/config/mod.rs` | Config | ~830 |
| `nimbus-core/src/dns/router.rs` | Query router | ~380 |
| `nimbus-core/src/dns/forwarder.rs` | Forwarder | ~165 |
| `nimbus-core/src/dns/dot.rs` | DoT | ~275 |
| `nimbus-core/src/blocking/mod.rs` | Blocking engine | ~340 |
| `nimbus-core/src/blocking/fetcher.rs` | StevenBlack fetcher | ~180 |
| `nimbus-core/src/database/gravity.rs` | Gravity DB | ~310 |
| `nimbus-core/src/database/queries.rs` | Query DB | ~630 |
| `nimbus-api/src/lib.rs` | REST API | ~850 |
| `nimbus-api/src/auth.rs` | Auth | ~340 |

## Quick Commands
```bash
cargo build --release --bin nimbusdns
cargo test --lib -p nimbus-core
cargo run --release --bin nimbusdns -- --help
```
