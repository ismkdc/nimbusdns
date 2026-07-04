// =============================================================================
// NimbusDNS Rust Port - Binary Entry Point
// =============================================================================
// Daemonization (fork) happens BEFORE tokio runtime starts.
// This ensures the child process has a clean runtime state.

use std::sync::Arc;

use clap::Parser;
use tokio::sync::watch;
use tracing::{info, warn};

use nimbus_core::*;

/// NimbusDNS: NimbusDNS DNS engine with native DNS-over-TLS support
#[derive(Parser, Debug)]
#[command(name = "nimbusdns", version, about)]
struct Args {
    #[arg(short = 'c', long, default_value = "/etc/nimbusdns/nimbus.toml")]
    config: std::path::PathBuf,
    #[arg(short = 'f', long)]
    foreground: bool,
    #[arg(long)]
    dump_config: bool,
    #[arg(long)]
    test_config: bool,
}

// -- Sync entry point: fork first, then enter async runtime --------------
fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging BEFORE fork so parent can log
    logging::init()?;
    info!("########## NimbusDNS started on {}! ##########", hostname());

    // Read configuration
    let cfg = config::Config::load(&args.config)?;
    info!("Parsed config file {} successfully", args.config.display());

    if args.dump_config {
        println!("{}", toml::to_string_pretty(&cfg)?);
        return Ok(());
    }
    if args.test_config {
        info!("Configuration is valid");
        return Ok(());
    }

    // Daemonize BEFORE entering tokio runtime
    if !args.foreground {
        daemon::daemonize_early()?;
    }

    // Enter async runtime
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async_main(args, cfg))
}

// -- Async entry point (runs after fork in child process) ---------------
async fn async_main(args: Args, cfg: config::Config) -> anyhow::Result<()> {
    // Check for another nimbusdns instance
    if cfg.misc.check_other_instance {
        daemon::check_other_instance(&cfg.files.pid_file);
    }

    // Initialize database
    let db = database::Database::open(&cfg.database)
        .map_err(|e| anyhow::anyhow!("Database::open failed: {}", e))?;
    info!("Database initialized");

    // Save PID file
    daemon::save_pid(&cfg.files.pid_file)?;

    // Set process priority (nice)
    daemon::set_nice(cfg.misc.nice)?;

    // Initialize state and signal handling
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (reload_tx, reload_rx) = watch::channel(false);

    // Start background database writer + DHCP server (before wrapping in Arc)
    let mut app_state = AppState::with_config_path(cfg, db, args.config.clone());
    let writer = database::writer::start(
        app_state.database.nimbus_db.clone(),
        shutdown_rx.clone(),
    );
    app_state.db_writer = Some(writer);

    // Start DHCP server and store handle in AppState
    let dhcp_config = Arc::new(parking_lot::RwLock::new(app_state.config.read().dhcp.clone()));
    app_state.dhcp_config = Some(dhcp_config.clone());
    if let Some(server) = nimbus_core::dhcp::start(dhcp_config, shutdown_rx.clone()).await {
        app_state.dhcp_server = Some(server);
        info!("DHCP server started");
    } else {
        info!("DHCP server disabled");
    }

    // Initialize blocking engine (loaded into AppState for live reload)
    let blocking_engine = Arc::new(
        nimbus_core::blocking::BlockingEngine::load(
            &app_state.database.gravity,
            &app_state.config.read(),
        ).map_err(|e| anyhow::anyhow!("Failed to load blocking lists: {}", e))?,
    );
    info!("Blocking engine loaded ({} total blocked, mode: {:?})",
        blocking_engine.stats().total_blocked, blocking_engine.mode());
    app_state.blocking = Some(blocking_engine);

    let state = Arc::new(app_state);
    info!("Background database writer started");

    // Start StevenBlack hosts fetcher
    {
        let cfg = state.config.read();
        let url = cfg.blocking.source_url.clone();
        let interval = std::time::Duration::from_secs(cfg.blocking.refresh_interval);
        drop(cfg);
        nimbus_core::blocking::fetcher::start(
            state.database.gravity.clone(),
            url,
            interval,
            shutdown_rx.clone(),
            state.blocking.clone(),
        );
    }

    // Signal handling
    let signals_task = signals::setup(shutdown_tx.clone(), reload_tx);
    tokio::spawn(signals_task);

    // SIGHUP reload watcher: reloads config + blocking lists
    let reload_state = state.clone();
    let mut reload_rx = reload_rx;
    tokio::spawn(async move {
        loop {
            if reload_rx.changed().await.is_err() {
                break;
            }
            info!("Reload triggered by SIGHUP");

            // Reload config file
            let config_path = reload_state.config_path.clone();
            match nimbus_core::config::Config::load(&config_path) {
                Ok(new_config) => {
                    *reload_state.config.write() = new_config;
                    info!("Configuration reloaded from {}", config_path.display());
                }
                Err(e) => {
                    warn!("Failed to reload config: {}", e);
                }
            }

            // Reload blocking lists from gravity DB into the running engine
            if let Some(ref engine) = reload_state.blocking {
                if let Err(e) = engine.reload(&reload_state.database.gravity) {
                    warn!("Failed to reload blocking lists: {}", e);
                } else {
                    info!("Blocking lists reloaded ({} total blocked)",
                        engine.stats().total_blocked);
                }
            }
        }
    });

    // Start DNS forwarder (with DoT)
    let dns_handle = dns::start(state.clone(), shutdown_rx.clone()).await
        .map_err(|e| anyhow::anyhow!("dns::start failed: {}", e))?;
    info!("DNS forwarder started with DoT support");

    // Start HTTP API server (includes embedded web panel)
    let api_handle = nimbus_api::serve(state.clone(), shutdown_rx.clone()).await
        .map_err(|e| anyhow::anyhow!("API serve failed: {}", e))?;
    info!("API + Web server started");

    // Wait for shutdown signal
    info!("NimbusDNS started successfully, awaiting signals...");
    let mut rx = shutdown_rx.clone();
    rx.changed().await.ok();
    info!("Shutdown signal received, beginning graceful shutdown...");

    // Graceful shutdown
    dns_handle.shutdown();
    api_handle.shutdown();

    // Remove PID file
    let pid_path = state.config.read().files.pid_file.clone();
    daemon::remove_pid(&pid_path);

    state.database.close()?;

    info!("########## NimbusDNS terminated! ##########");
    Ok(())
}
