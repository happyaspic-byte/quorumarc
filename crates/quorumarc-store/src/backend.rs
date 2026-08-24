use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;

/// Minimal filesystem boundary used by the authority store.
///
/// Implementations must not report success for `sync_file` until file data and
/// metadata have reached the implementation's durability boundary. They must
/// not report success for `rename` before the new name is visible atomically.
pub trait StorageBackend {
    /// Creates a directory and any missing parents.
    fn create_dir_all(&mut self, path: &Path) -> io::Result<()>;

    /// Reads a complete file, returning `None` only when it does not exist.
    fn read_file(&mut self, path: &Path) -> io::Result<Option<Vec<u8>>>;

    /// Replaces or creates a file with the supplied bytes.
    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()>;

    /// Synchronises one file's data and metadata.
    fn sync_file(&mut self, path: &Path) -> io::Result<()>;

    /// Atomically renames `from` to `to` on the target filesystem.
    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()>;

    /// Synchronises directory metadata after a rename.
    ///
    /// A platform that cannot synchronise directories must return
    /// [`io::ErrorKind::Unsupported`]. Other errors indicate uncertain
    /// durability and are fail-closed by the store.
    fn sync_directory(&mut self, path: &Path) -> io::Result<()>;

    /// Removes a file, returning success when it was already absent.
    fn remove_file_if_exists(&mut self, path: &Path) -> io::Result<()>;
}

/// Standard filesystem implementation for local Ubuntu filesystems.
#[derive(Clone, Copy, Debug, Default)]
pub struct FileBackend;

impl StorageBackend for FileBackend {
    fn create_dir_all(&mut self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }

    fn read_file(&mut self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        let mut file = match File::open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Ok(Some(bytes))
    }

    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)?;
        file.write_all(bytes)
    }

    fn sync_file(&mut self, path: &Path) -> io::Result<()> {
        OpenOptions::new().read(true).write(true).open(path)?.sync_all()
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        sync_directory(path)
    }

    fn remove_file_if_exists(&mut self, path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "directory synchronisation is unavailable on this platform",
    ))
}

/// Backend operation at which a deterministic failure may be injected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultOperation {
    /// Directory creation.
    CreateDirectory,
    /// File read.
    Read,
    /// Temporary-file write.
    Write,
    /// File synchronisation.
    SyncFile,
    /// Atomic rename.
    Rename,
    /// Parent-directory synchronisation.
    SyncDirectory,
    /// Stale temporary-file cleanup.
    Remove,
}

impl FaultOperation {
    const COUNT: usize = 7;

    const fn index(self) -> usize {
        match self {
            Self::CreateDirectory => 0,
            Self::Read => 1,
            Self::Write => 2,
            Self::SyncFile => 3,
            Self::Rename => 4,
            Self::SyncDirectory => 5,
            Self::Remove => 6,
        }
    }
}

/// Failure applied when a matching fault rule fires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FaultMode {
    /// Fails before the operation reaches the wrapped backend.
    Error(io::ErrorKind),
    /// Writes a prefix and then reports failure.
    ///
    /// This mode is valid only for [`FaultOperation::Write`].
    PartialWrite {
        /// Maximum prefix length written.
        bytes: usize,
        /// Error kind returned after the prefix write.
        error_kind: io::ErrorKind,
    },
}

/// One deterministic, one-shot backend failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultRule {
    /// Operation to fail.
    pub operation: FaultOperation,
    /// One-based occurrence of the operation to fail.
    pub occurrence: u64,
    /// Failure behavior.
    pub mode: FaultMode,
}

/// Storage adapter that injects deterministic, one-shot failures.
pub struct FaultInjectingBackend<B> {
    inner: B,
    counters: [u64; FaultOperation::COUNT],
    rules: Vec<FaultRule>,
}

impl<B> FaultInjectingBackend<B> {
    /// Wraps a backend with the supplied fault schedule.
    #[must_use]
    pub fn new(inner: B, rules: Vec<FaultRule>) -> Self {
        Self {
            inner,
            counters: [0; FaultOperation::COUNT],
            rules,
        }
    }

    /// Returns the wrapped backend after testing.
    #[must_use]
    pub fn into_inner(self) -> B {
        self.inner
    }

    fn next_fault(&mut self, operation: FaultOperation) -> Option<FaultMode> {
        let index = operation.index();
        self.counters[index] = self.counters[index].saturating_add(1);
        let occurrence = self.counters[index];
        let position = self
            .rules
            .iter()
            .position(|rule| rule.operation == operation && rule.occurrence == occurrence)?;
        Some(self.rules.remove(position).mode)
    }

    fn injected_error(operation: FaultOperation, kind: io::ErrorKind) -> io::Error {
        io::Error::new(kind, format!("injected {operation:?} failure"))
    }

    fn fail_before(&mut self, operation: FaultOperation) -> io::Result<()> {
        match self.next_fault(operation) {
            None => Ok(()),
            Some(FaultMode::Error(kind)) => Err(Self::injected_error(operation, kind)),
            Some(FaultMode::PartialWrite { error_kind, .. }) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "partial-write fault for {operation:?} is invalid; requested {error_kind:?}"
                ),
            )),
        }
    }
}

impl<B: StorageBackend> StorageBackend for FaultInjectingBackend<B> {
    fn create_dir_all(&mut self, path: &Path) -> io::Result<()> {
        self.fail_before(FaultOperation::CreateDirectory)?;
        self.inner.create_dir_all(path)
    }

    fn read_file(&mut self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        self.fail_before(FaultOperation::Read)?;
        self.inner.read_file(path)
    }

    fn write_file(&mut self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        match self.next_fault(FaultOperation::Write) {
            None => self.inner.write_file(path, bytes),
            Some(FaultMode::Error(kind)) => {
                Err(Self::injected_error(FaultOperation::Write, kind))
            }
            Some(FaultMode::PartialWrite {
                bytes: prefix_length,
                error_kind,
            }) => {
                let prefix_end = prefix_length.min(bytes.len());
                self.inner.write_file(path, &bytes[..prefix_end])?;
                Err(Self::injected_error(FaultOperation::Write, error_kind))
            }
        }
    }

    fn sync_file(&mut self, path: &Path) -> io::Result<()> {
        self.fail_before(FaultOperation::SyncFile)?;
        self.inner.sync_file(path)
    }

    fn rename(&mut self, from: &Path, to: &Path) -> io::Result<()> {
        self.fail_before(FaultOperation::Rename)?;
        self.inner.rename(from, to)
    }

    fn sync_directory(&mut self, path: &Path) -> io::Result<()> {
        self.fail_before(FaultOperation::SyncDirectory)?;
        self.inner.sync_directory(path)
    }

    fn remove_file_if_exists(&mut self, path: &Path) -> io::Result<()> {
        self.fail_before(FaultOperation::Remove)?;
        self.inner.remove_file_if_exists(path)
    }
}
