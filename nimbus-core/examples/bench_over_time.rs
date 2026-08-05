//! Micro-benchmark for the DNS hot-path stats sink (`over_time::OverTime`).
//!
//! `OverTime::record_query` runs once per DNS query. It takes a write lock on
//! the global 144-slot circular buffer and, when a client IP is given, a
//! second write lock on the per-client history map. This measures the
//! per-query cost single-threaded vs. under contention, plus a no-lock
//! baseline (the atomic counters record_query already maintains), so we can
//! decide whether those two locks are a bottleneck worth removing.
//!
//! Run: `cargo run -p nimbus-core --release --example bench_over_time`

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use nimbus_core::database::queries::QueryStatus;
use nimbus_core::over_time::OverTime;

const ITERATIONS: usize = 2_000_000;

fn bench<F>(name: &str, f: F)
where
    F: FnOnce(),
{
    let start = Instant::now();
    f();
    let elapsed = start.elapsed();
    let per_op = elapsed.as_nanos() as f64 / ITERATIONS as f64;
    let ops_per_sec = ITERATIONS as f64 / elapsed.as_secs_f64();
    println!("{name:<40} {:>9.0} ns/op  {:>8.1} M ops/s", per_op, ops_per_sec / 1e6);
}

fn main() {
    let now = chrono::Utc::now().timestamp();
    println!("ITERATIONS = {ITERATIONS}\n");

    // Baseline: just the 4 atomic counters record_query updates (no locks).
    let t = AtomicI64::new(0);
    let b = AtomicI64::new(0);
    let c = AtomicI64::new(0);
    let f = AtomicI64::new(0);
    bench("4 atomic counters (no locks)", || {
        for _ in 0..ITERATIONS {
            t.fetch_add(1, Ordering::Relaxed);
            f.fetch_add(1, Ordering::Relaxed);
            b.load(Ordering::Relaxed);
            c.load(Ordering::Relaxed);
        }
    });
    // Keep the atomics alive so the compiler can't elide the loop.
    let _ = (t.load(Ordering::Relaxed), b.load(Ordering::Relaxed), c.load(Ordering::Relaxed), f.load(Ordering::Relaxed));

    // Single-threaded: no client IP → one write lock per query
    bench("record_query(None) 1 thread", || {
        let ot = OverTime::new();
        for _ in 0..ITERATIONS {
            ot.record_query(now, None, QueryStatus::Forwarded);
        }
    });

    // Single-threaded: with client IP → two write locks per query
    bench("record_query(Some ip) 1 thread", || {
        let ot = OverTime::new();
        for _ in 0..ITERATIONS {
            ot.record_query(now, Some("192.168.1.42"), QueryStatus::Forwarded);
        }
    });

    // 8 threads, no client IP
    let ot = Arc::new(OverTime::new());
    bench("record_query(None) 8 threads", || {
        let mut handles = Vec::new();
        for _ in 0..8 {
            let ot = ot.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..ITERATIONS / 8 {
                    ot.record_query(now, None, QueryStatus::Forwarded);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });

    // 8 threads, with client IP (one IP per thread, bounded map growth)
    let ot = Arc::new(OverTime::new());
    bench("record_query(Some ip) 8 threads", || {
        let mut handles = Vec::new();
        for t in 0..8 {
            let ot = ot.clone();
            handles.push(thread::spawn(move || {
                let client = format!("192.168.1.{t}");
                for _ in 0..ITERATIONS / 8 {
                    ot.record_query(now, Some(&client), QueryStatus::Forwarded);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
    });
}
