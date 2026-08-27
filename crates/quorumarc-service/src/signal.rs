use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::{Handle, Signals};

#[derive(Debug, Default)]
struct ShutdownState {
    requested: Mutex<bool>,
    changed: Condvar,
}

/// Process-local shutdown request shared by daemon loops.
#[derive(Clone, Debug, Default)]
pub struct ShutdownToken {
    state: Arc<ShutdownState>,
}

/// Registered process-signal worker removed when the guard is dropped.
#[derive(Debug)]
pub struct SignalGuard {
    handle: Handle,
    worker: Option<JoinHandle<()>>,
}

/// Signal-handler installation refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalError {
    RegistrationFailed,
}

impl ShutdownToken {
    /// Creates a non-requested shutdown token.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Requests idempotent shutdown and wakes blocked daemon loops.
    pub fn request(&self) {
        if let Ok(mut requested) = self.state.requested.lock() {
            *requested = true;
            self.state.changed.notify_all();
        }
    }

    /// Returns whether shutdown was requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.state
            .requested
            .lock()
            .map_or(true, |requested| *requested)
    }

    /// Blocks until shutdown is requested.
    pub fn wait(&self) {
        let Ok(requested) = self.state.requested.lock() else {
            return;
        };
        let _guard = self
            .state
            .changed
            .wait_while(requested, |requested| !*requested);
    }

    /// Waits up to `timeout` for a shutdown request.
    pub fn wait_timeout(&self, timeout: std::time::Duration) {
        let Ok(requested) = self.state.requested.lock() else {
            return;
        };
        if *requested {
            return;
        }
        let _ = self
            .state
            .changed
            .wait_timeout_while(requested, timeout, |requested| !*requested);
    }

    /// Registers SIGTERM and SIGINT as event-driven shutdown requests.
    pub fn register_process_signals(&self) -> Result<SignalGuard, SignalError> {
        let mut signals =
            Signals::new([SIGTERM, SIGINT]).map_err(|_error| SignalError::RegistrationFailed)?;
        let handle = signals.handle();
        let shutdown = self.clone();
        let worker = std::thread::Builder::new()
            .name("quorumarc-signal".to_owned())
            .spawn(move || {
                if signals.forever().next().is_some() {
                    shutdown.request();
                }
            })
            .map_err(|_error| SignalError::RegistrationFailed)?;
        Ok(SignalGuard {
            handle,
            worker: Some(worker),
        })
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        self.handle.close();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
