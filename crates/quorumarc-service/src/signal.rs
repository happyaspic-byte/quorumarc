use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Process-local shutdown request shared by daemon loops.
#[derive(Clone, Debug, Default)]
pub struct ShutdownToken {
    requested: Arc<AtomicBool>,
}

impl ShutdownToken {
    /// Creates a non-requested shutdown token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests idempotent shutdown.
    pub fn request(&self) {
        self.requested.store(true, Ordering::SeqCst);
    }

    /// Returns whether shutdown was requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.requested.load(Ordering::SeqCst)
    }
}
