// =============================================================================
// Daemon Lifecycle
// =============================================================================

use std::fs;
use std::path::Path;

#[cfg(unix)]
use libc::{setpriority, PRIO_PROCESS};
use tracing::{info, warn, debug};

/// Daemonize BEFORE entering tokio runtime.
/// Double-fork: parent exits, grandchild continues as daemon.
/// Only available on Unix.
#[cfg(unix)]
pub fn daemonize_early() -> anyhow::Result<()> {
    info!("Daemonizing (early fork)...");

    // First fork
    match unsafe { libc::fork() } {
        -1 => return Err(anyhow::anyhow!("First fork failed")),
        n if n > 0 => {
            // Parent: exit successfully
            info!("NimbusDNS started!");
            std::process::exit(0);
        }
        _ => {}
    }

    // Child: create new session
    unsafe { libc::setsid(); }

    // Second fork
    match unsafe { libc::fork() } {
        -1 => return Err(anyhow::anyhow!("Second fork failed")),
        n if n > 0 => {
            // First child: exit immediately
            std::process::exit(0);
        }
        _ => {}
    }

    // Grandchild: the actual daemon process
    unsafe { libc::umask(0o077); } // Restrictive: no group/other access

    // chdir to root to avoid blocking unmounts
    if let Err(e) = std::env::set_current_dir("/") {
        warn!("Failed to chdir to /: {}", e);
    }

    // Redirect stdin/stdout/stderr to /dev/null
    if let Ok(null) = std::fs::File::open("/dev/null") {
        use std::os::fd::AsRawFd;
        let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDIN_FILENO) };
        let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDOUT_FILENO) };
        let _ = unsafe { libc::dup2(null.as_raw_fd(), libc::STDERR_FILENO) };
    }

    info!("Daemonized successfully (PID: {})", std::process::id());
    Ok(())
}

/// Windows stub for daemonize_early (no-op, always runs in foreground)
#[cfg(not(unix))]
pub fn daemonize_early() -> anyhow::Result<()> {
    info!("Running in foreground (daemonize not supported on this platform)");
    Ok(())
}

/// Set the process nice value
#[cfg(unix)]
pub fn set_nice(nice_value: i32) -> anyhow::Result<()> {
    if nice_value == -999 {
        debug!("Not changing process priority (nice == -999)");
        return Ok(());
    }

    let which = PRIO_PROCESS;
    let pid = std::process::id() as libc::id_t;
    let ret = unsafe { setpriority(which, pid, nice_value as libc::c_int) };
    if ret == 0 {
        info!("Set process priority to nice {}", nice_value);
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::EACCES) | Some(libc::EPERM) => {
                warn!("Cannot set priority to {} (CAP_SYS_NICE required)", nice_value);
                Ok(())
            }
            _ => {
                warn!("Cannot set process priority to {}: {}", nice_value, err);
                Ok(())
            }
        }
    }
}

#[cfg(not(unix))]
pub fn set_nice(_nice_value: i32) -> anyhow::Result<()> {
    debug!("Process priority not supported on this platform");
    Ok(())
}

/// Save PID to file
pub fn save_pid(path: &Path) -> anyhow::Result<()> {
    let pid = std::process::id();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, pid.to_string())?;
    info!("PID of nimbusdns process: {}", pid);
    Ok(())
}

/// Remove PID file
pub fn remove_pid(path: &Path) {
    if path.exists() {
        match fs::remove_file(path) {
            Ok(()) => info!("PID file removed"),
            Err(e) => warn!("Unable to remove PID file: {}", e),
        }
    }
}

/// Check if another instance is running
#[cfg(unix)]
pub fn check_other_instance(pid_path: &Path) -> bool {
    if !pid_path.exists() {
        return false;
    }
    let pid_str = match fs::read_to_string(pid_path) {
        Ok(s) => s.trim().to_string(),
        Err(_) => return false,
    };
    let pid: i32 = match pid_str.parse() {
        Ok(p) => p,
        Err(_) => return false,
    };

    match unsafe { libc::kill(pid, 0) } {
        0 => {
            warn!("Another nimbusdns process is already running (PID: {})", pid);
            true
        }
        _ => false,
    }
}

#[cfg(not(unix))]
pub fn check_other_instance(_pid_path: &Path) -> bool {
    false
}
