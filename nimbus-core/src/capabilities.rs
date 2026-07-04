// =============================================================================
// Capabilities Check - stub (CAP_* constants not available in libc crate)
// =============================================================================

/// Check if the process has a specific capability (always returns true).
pub fn has_capability(_cap: i32) -> bool {
    true
}

/// Check capabilities at startup (no-op).
pub fn check_startup_capabilities() {
    tracing::info!("Capability checks not available");
}
