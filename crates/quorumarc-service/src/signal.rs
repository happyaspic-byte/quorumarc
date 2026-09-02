use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;

use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::{Handle, Signals};

#[derive(Debug, Default)]
struct ProcessState {
    shutdown_requested: bool,
    reload_generation: u64,
}

#[derive(Debug, Default)]
struct ShutdownState {
    process: Mutex<ProcessState>,
    changed: Condvar,
}

/// Process-local shutdown request shared by daemon loops.
#[derive(Clone, Debug, Default)]
pub struct ShutdownToken {
    state: Arc<ShutdownState>,
}

/// Event-driven configuration-reload requests paired with process shutdown.
#[derive(Clone, Debug)]
pub struct ReloadToken {
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
        if let Ok(mut process) = self.state.process.lock() {
            process.shutdown_requested = true;
            self.state.changed.notify_all();
        }
    }

    /// Returns whether shutdown was requested.
    #[must_use]
    pub fn is_requested(&self) -> bool {
        self.state
            .process
            .lock()
            .map_or(true, |process| process.shutdown_requested)
    }

    /// Blocks until shutdown is requested.
    pub fn wait(&self) {
        let Ok(process) = self.state.process.lock() else {
            return;
        };
        let _guard = self
            .state
            .changed
            .wait_while(process, |process| !process.shutdown_requested);
    }

    /// Waits up to `timeout` for a shutdown request.
    pub fn wait_timeout(&self, timeout: std::time::Duration) {
        let Ok(process) = self.state.process.lock() else {
            return;
        };
        if process.shutdown_requested {
            return;
        }
        let _ = self
            .state
            .changed
            .wait_timeout_while(process, timeout, |process| !process.shutdown_requested);
    }

    /// Returns a reload token cancelled by this shutdown token.
    #[must_use]
    pub fn reload_token(&self) -> ReloadToken {
        ReloadToken {
            state: Arc::clone(&self.state),
        }
    }

    /// Registers SIGHUP reload and SIGTERM/SIGINT shutdown requests.
    pub fn register_process_signals(&self) -> Result<SignalGuard, SignalError> {
        let mut signals = Signals::new([SIGHUP, SIGTERM, SIGINT])
            .map_err(|_error| SignalError::RegistrationFailed)?;
        let handle = signals.handle();
        let shutdown = self.clone();
        let reload = self.reload_token();
        let worker = std::thread::Builder::new()
            .name("quorumarc-signal".to_owned())
            .spawn(move || {
                for signal in signals.forever() {
                    if signal == SIGHUP {
                        reload.request();
                    } else {
                        shutdown.request();
                        break;
                    }
                }
            })
            .map_err(|_error| SignalError::RegistrationFailed)?;
        Ok(SignalGuard {
            handle,
            worker: Some(worker),
        })
    }
}

impl ReloadToken {
    /// Requests one reload generation and wakes reload waiters.
    pub fn request(&self) {
        if let Ok(mut process) = self.state.process.lock() {
            process.reload_generation = process.reload_generation.saturating_add(1);
            self.state.changed.notify_all();
        }
    }

    /// Blocks until a newer reload generation or process shutdown.
    #[must_use]
    pub fn wait_after(&self, observed_generation: u64) -> Option<u64> {
        let Ok(process) = self.state.process.lock() else {
            return None;
        };
        let Ok(process) = self.state.changed.wait_while(process, |process| {
            !process.shutdown_requested && process.reload_generation <= observed_generation
        }) else {
            return None;
        };
        if process.shutdown_requested {
            None
        } else {
            Some(process.reload_generation)
        }
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
