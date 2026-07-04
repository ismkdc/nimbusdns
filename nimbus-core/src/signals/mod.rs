use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use tokio::sync::watch;
use tracing::{info, warn, error, debug};
use futures_util::StreamExt;

pub fn setup(
    shutdown_tx: watch::Sender<bool>,
    reload_tx: watch::Sender<bool>,
) -> impl futures_util::Future<Output = ()> {
    let signals = match Signals::new([
        SIGTERM, SIGINT, SIGQUIT, SIGHUP, SIGUSR1, SIGUSR2, SIGCHLD,
    ]) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to set up signal handlers: {}", e);
            return futures_util::future::Either::Left(async {});
        }
    };

    let handle = signals.handle();
    let fut = async move {
        info!("Signal handlers initialized");
        let mut signals_stream = signals;
        while let Some(signal) = signals_stream.next().await {
            match signal {
                SIGTERM | SIGINT | SIGQUIT => {
                    info!("Received termination signal, starting graceful shutdown");
                    let _ = shutdown_tx.send(true);
                    handle.close();
                    break;
                }
                SIGHUP => {
                    info!("Received SIGHUP, reloading configuration");
                    let _ = reload_tx.send(true);
                }
                SIGUSR1 => info!("Received SIGUSR1"),
                SIGUSR2 => info!("Received SIGUSR2"),
                SIGCHLD => debug!("Received SIGCHLD"),
                _ => warn!("Unknown signal: {}", signal),
            }
        }
        info!("Signal handler terminated");
    };
    futures_util::future::Either::Right(fut)
}
