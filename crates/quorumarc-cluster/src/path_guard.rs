use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};

use fs2::FileExt;

use crate::{ClusterError, err};

pub(crate) fn reject_symlink_components(path: &Path) -> Result<(), ClusterError> {
    let absolute = absolute_lexical(path)?;
    let mut current = PathBuf::new();
    for component in absolute.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(err(
                    "PATH_SYMLINK_REFUSED",
                    format!("{} contains symlink {}", path.display(), current.display()),
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(err(
                    "PATH_INSPECTION_FAILED",
                    format!("{}: {error}", current.display()),
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn prepare_file_parent(path: &Path) -> Result<(), ClusterError> {
    reject_symlink_components(path)?;
    let parent = file_parent(path);
    fs::create_dir_all(parent).map_err(|error| {
        err(
            "PATH_CREATE_FAILED",
            format!("{}: {error}", parent.display()),
        )
    })?;
    reject_symlink_components(parent)
}

pub(crate) fn prepare_store_directory(path: &Path) -> Result<(), ClusterError> {
    reject_symlink_components(path)?;
    fs::create_dir_all(path)
        .map_err(|error| err("PATH_CREATE_FAILED", format!("{}: {error}", path.display())))?;
    reject_symlink_components(path)
}

pub(crate) fn require_disjoint_store_and_file(
    store: &Path,
    file: &Path,
) -> Result<(), ClusterError> {
    let store_absolute = absolute_lexical(store)?;
    let file_absolute = absolute_lexical(file)?;
    if file_absolute == store_absolute
        || file_absolute.starts_with(&store_absolute)
        || store_absolute.starts_with(&file_absolute)
    {
        return Err(err(
            "PATH_ALIAS_REFUSED",
            format!(
                "store {} and file {} are not disjoint",
                store.display(),
                file.display()
            ),
        ));
    }
    prepare_store_directory(store)?;
    prepare_file_parent(file)?;
    let canonical_store = fs::canonicalize(store).map_err(|error| {
        err(
            "PATH_CANONICALIZE_FAILED",
            format!("{}: {error}", store.display()),
        )
    })?;
    let canonical_parent = fs::canonicalize(file_parent(file)).map_err(|error| {
        err(
            "PATH_CANONICALIZE_FAILED",
            format!("{}: {error}", file_parent(file).display()),
        )
    })?;
    let file_name = file.file_name().ok_or_else(|| {
        err(
            "PATH_INVALID",
            format!("{} has no file name", file.display()),
        )
    })?;
    let canonical_file = if file.exists() {
        fs::canonicalize(file).map_err(|error| {
            err(
                "PATH_CANONICALIZE_FAILED",
                format!("{}: {error}", file.display()),
            )
        })?
    } else {
        canonical_parent.join(file_name)
    };
    if canonical_file == canonical_store
        || canonical_file.starts_with(&canonical_store)
        || canonical_store.starts_with(&canonical_file)
    {
        return Err(err(
            "PATH_ALIAS_REFUSED",
            "canonical store and WAL paths overlap",
        ));
    }
    for state_name in ["authority.journal", "authority.journal.tmp"] {
        let state_file = store.join(state_name);
        if same_existing_file(&state_file, file)? {
            return Err(err(
                "PATH_ALIAS_REFUSED",
                format!(
                    "{} and {} are hard-link aliases",
                    state_file.display(),
                    file.display()
                ),
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_keys_disjoint(
    keys: &[&Path],
    store: Option<&Path>,
    wal: Option<&Path>,
) -> Result<(), ClusterError> {
    let store_absolute = store.map(absolute_lexical).transpose()?;
    let wal_absolute = wal.map(absolute_lexical).transpose()?;
    for (index, first) in keys.iter().enumerate() {
        for second in keys.iter().skip(index.saturating_add(1)) {
            if same_existing_file(first, second)? {
                return Err(err(
                    "PATH_ALIAS_REFUSED",
                    format!(
                        "key files {} and {} are hard-link aliases",
                        first.display(),
                        second.display()
                    ),
                ));
            }
        }
    }
    for key in keys {
        let key_absolute = absolute_lexical(key)?;
        if store_absolute
            .as_ref()
            .is_some_and(|value| key_absolute.starts_with(value))
            || wal_absolute.as_ref() == Some(&key_absolute)
        {
            return Err(err(
                "PATH_ALIAS_REFUSED",
                format!("key {} aliases writable state", key.display()),
            ));
        }
        if let Some(value) = wal {
            if same_existing_file(key, value)? {
                return Err(err(
                    "PATH_ALIAS_REFUSED",
                    format!("key {} is a hard-link alias of the WAL", key.display()),
                ));
            }
        }
        if let Some(directory) = store {
            for state_name in ["authority.journal", "authority.journal.tmp"] {
                let state_file = directory.join(state_name);
                if same_existing_file(key, &state_file)? {
                    return Err(err(
                        "PATH_ALIAS_REFUSED",
                        format!(
                            "key {} is a hard-link alias of {}",
                            key.display(),
                            state_file.display()
                        ),
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn require_ready_disjoint(
    ready: &Path,
    keys: &[&Path],
    store: Option<&Path>,
    wal: Option<&Path>,
) -> Result<(), ClusterError> {
    let ready_absolute = absolute_lexical(ready)?;
    for key in keys {
        if ready_absolute == absolute_lexical(key)? || same_existing_file(ready, key)? {
            return Err(err(
                "PATH_ALIAS_REFUSED",
                format!(
                    "ready file {} aliases key {}",
                    ready.display(),
                    key.display()
                ),
            ));
        }
    }
    if let Some(directory) = store {
        let store_absolute = absolute_lexical(directory)?;
        if ready_absolute == store_absolute
            || ready_absolute.starts_with(&store_absolute)
            || store_absolute.starts_with(&ready_absolute)
        {
            return Err(err(
                "PATH_ALIAS_REFUSED",
                format!(
                    "ready file {} overlaps store {}",
                    ready.display(),
                    directory.display()
                ),
            ));
        }
        for state_path in [
            directory.join("authority.journal"),
            directory.join("authority.journal.tmp"),
            store_lock_path(directory),
        ] {
            if same_existing_file(ready, &state_path)? {
                return Err(err(
                    "PATH_ALIAS_REFUSED",
                    format!(
                        "ready file {} aliases state {}",
                        ready.display(),
                        state_path.display()
                    ),
                ));
            }
        }
    }
    if let Some(file) = wal {
        let wal_absolute = absolute_lexical(file)?;
        let lock_absolute = absolute_lexical(&file_lock_path(file))?;
        if ready_absolute == wal_absolute || ready_absolute == lock_absolute {
            return Err(err(
                "PATH_ALIAS_REFUSED",
                format!("ready file {} aliases WAL ownership", ready.display()),
            ));
        }
        for state_path in [file.to_path_buf(), file_lock_path(file)] {
            if same_existing_file(ready, &state_path)? {
                return Err(err(
                    "PATH_ALIAS_REFUSED",
                    format!(
                        "ready file {} aliases state {}",
                        ready.display(),
                        state_path.display()
                    ),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn same_existing_file(left: &Path, right: &Path) -> Result<bool, ClusterError> {
    use std::os::unix::fs::MetadataExt;

    let left_metadata = match fs::metadata(left) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(err(
                "PATH_INSPECTION_FAILED",
                format!("{}: {error}", left.display()),
            ));
        }
    };
    let right_metadata = match fs::metadata(right) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(err(
                "PATH_INSPECTION_FAILED",
                format!("{}: {error}", right.display()),
            ));
        }
    };
    Ok(left_metadata.dev() == right_metadata.dev() && left_metadata.ino() == right_metadata.ino())
}

#[cfg(not(unix))]
fn same_existing_file(_left: &Path, _right: &Path) -> Result<bool, ClusterError> {
    Ok(false)
}

pub(crate) fn write_ready_file(path: &Path, contents: &str) -> Result<(), ClusterError> {
    prepare_file_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            return Err(err(
                "READY_FILE_FAILED",
                format!("{} already exists", path.display()),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(err(
                "READY_FILE_FAILED",
                format!("{}: {error}", path.display()),
            ));
        }
    }
    let staging = ready_staging_path(path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&staging)
        .map_err(|error| {
            err(
                "READY_FILE_FAILED",
                format!("{}: {error}", staging.display()),
            )
        })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            let _cleanup = fs::remove_file(&staging);
            err(
                "READY_FILE_FAILED",
                format!("{}: {error}", staging.display()),
            )
        })?;
    // A sibling hard link publishes the fully synced inode atomically and,
    // unlike rename, can never replace a readiness file created in the gap
    // between the initial existence check and publication.
    fs::hard_link(&staging, path).map_err(|error| {
        let _cleanup = fs::remove_file(&staging);
        err("READY_FILE_FAILED", format!("{}: {error}", path.display()))
    })?;
    if let Err(error) = fs::remove_file(&staging) {
        let _cleanup = fs::remove_file(path);
        return Err(err(
            "READY_FILE_FAILED",
            format!("{}: {error}", staging.display()),
        ));
    }
    sync_parent(path).map_err(|error| {
        let _cleanup = fs::remove_file(path);
        err("READY_FILE_FAILED", format!("{}: {error}", path.display()))
    })
}

#[derive(Debug)]
pub(crate) struct OwnerLock {
    _file: File,
    _path_lock: Option<File>,
    unlink_if_empty: Option<PathBuf>,
}

impl Drop for OwnerLock {
    fn drop(&mut self) {
        let Some(path) = self.unlink_if_empty.as_ref() else {
            return;
        };
        let Ok(owned) = self._file.metadata() else {
            return;
        };
        if owned.len() != 0 {
            return;
        }
        let Ok(current) = fs::metadata(path) else {
            return;
        };
        if current.len() != 0 {
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.dev() != owned.dev() || current.ino() != owned.ino() {
                return;
            }
        }
        let _cleanup = fs::remove_file(path);
    }
}

impl OwnerLock {
    pub(crate) fn for_store(store: &Path, role: &str) -> Result<Self, ClusterError> {
        prepare_store_directory(store)?;
        Ok(Self {
            _file: Self::acquire_path(store_lock_path(store), role)?,
            _path_lock: None,
            unlink_if_empty: None,
        })
    }

    pub(crate) fn for_file(file: &Path, role: &str) -> Result<Self, ClusterError> {
        prepare_file_parent(file)?;
        let path_lock = Self::acquire_path(file_lock_path(file), role)?;
        reject_symlink_components(file)?;
        let (owned, created) = match OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(file)
        {
            Ok(file) => (file, true),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => (
                OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(file)
                    .map_err(|error| {
                        err("OWNER_LOCK_REFUSED", format!("{}: {error}", file.display()))
                    })?,
                false,
            ),
            Err(error) => {
                return Err(err(
                    "OWNER_LOCK_REFUSED",
                    format!("{}: {error}", file.display()),
                ));
            }
        };
        if let Err(error) = owned.try_lock_exclusive() {
            if created {
                let _cleanup = fs::remove_file(file);
            }
            return Err(err(
                "OWNER_LOCK_REFUSED",
                format!(
                    "{} is already owned by another process ({role}): {error}",
                    file.display()
                ),
            ));
        }
        Ok(Self {
            _file: owned,
            _path_lock: Some(path_lock),
            unlink_if_empty: created.then(|| file.to_path_buf()),
        })
    }

    fn acquire_path(path: PathBuf, role: &str) -> Result<File, ClusterError> {
        reject_symlink_components(&path)?;
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&path)
            .map_err(|error| err("OWNER_LOCK_REFUSED", format!("{}: {error}", path.display())))?;
        file.try_lock_exclusive().map_err(|error| {
            err(
                "OWNER_LOCK_REFUSED",
                format!("{} is already owned: {error}", path.display()),
            )
        })?;
        file.set_len(0)
            .and_then(|()| {
                file.write_all(format!("role={role} pid={}", std::process::id()).as_bytes())
            })
            .and_then(|()| file.sync_all())
            .and_then(|()| sync_parent(&path))
            .map_err(|error| err("OWNER_LOCK_FAILED", format!("{}: {error}", path.display())))?;
        Ok(file)
    }
}

fn store_lock_path(store: &Path) -> PathBuf {
    store.join(".quorumarc.owner")
}

fn file_lock_path(file: &Path) -> PathBuf {
    let mut name = file
        .file_name()
        .map_or_else(|| OsString::from("state"), OsString::from);
    name.push(".quorumarc.owner");
    file_parent(file).join(name)
}

fn ready_staging_path(file: &Path) -> PathBuf {
    let mut name = file
        .file_name()
        .map_or_else(|| OsString::from("ready"), OsString::from);
    name.push(".quorumarc.staging");
    file_parent(file).join(name)
}

fn absolute_lexical(path: &Path) -> Result<PathBuf, ClusterError> {
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|error| err("PATH_CURRENT_DIR_FAILED", error.to_string()))?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(err("PATH_TRAVERSAL_REFUSED", path.display().to_string()));
                }
            }
            Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
        }
    }
    Ok(normalized)
}

fn file_parent(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        Some(_) | None => Path::new("."),
    }
}

fn sync_parent(path: &Path) -> std::io::Result<()> {
    File::open(file_parent(path))?.sync_all()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Barrier};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn directory() -> PathBuf {
        let value = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-cluster-path-{}-{value}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create path test directory");
        path
    }

    #[test]
    fn store_cannot_contain_wal() {
        let root = directory();
        let store = root.join("authority");
        let wal = store.join("replica.wal");
        let error =
            require_disjoint_store_and_file(&store, &wal).expect_err("overlapping paths must fail");
        assert_eq!(error.reason_code(), "PATH_ALIAS_REFUSED");
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[test]
    fn owner_lock_is_cross_role_exclusive_and_released() {
        let root = directory();
        let first = OwnerLock::for_store(&root, "candidate").expect("first lock");
        let error = OwnerLock::for_store(&root, "witness").expect_err("second role must fail");
        assert_eq!(error.reason_code(), "OWNER_LOCK_REFUSED");
        drop(first);
        let second = OwnerLock::for_store(&root, "witness").expect("released lock");
        drop(second);
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[test]
    fn wal_owner_lock_rejects_hard_link_aliases_and_releases() {
        let root = directory();
        let wal = root.join("primary.wal");
        let alias = root.join("handoff.wal");
        fs::write(&wal, b"durable-wal").expect("create WAL");
        fs::hard_link(&wal, &alias).expect("create hard-link alias");

        let first = OwnerLock::for_file(&wal, "continuous-primary").expect("first WAL lock");
        let error = OwnerLock::for_file(&alias, "lifecycle-node")
            .expect_err("hard-link alias must share WAL ownership");
        assert_eq!(error.reason_code(), "OWNER_LOCK_REFUSED");
        drop(first);
        let second = OwnerLock::for_file(&alias, "lifecycle-node").expect("released WAL lock");
        drop(second);
        assert_eq!(fs::read(&wal).expect("read unchanged WAL"), b"durable-wal");
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[test]
    fn empty_wal_lock_drop_preserves_replaced_path() {
        let root = directory();
        let wal = root.join("primary.wal");
        let displaced = root.join("displaced.wal");
        let owner = OwnerLock::for_file(&wal, "continuous-primary").expect("create WAL lock");
        fs::rename(&wal, &displaced).expect("move locked inode");
        fs::write(&wal, b"replacement").expect("create replacement WAL");

        drop(owner);

        assert_eq!(
            fs::read(&wal).expect("read replacement WAL"),
            b"replacement"
        );
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[test]
    fn ready_file_cannot_alias_a_missing_wal_or_owner_lock() {
        let root = directory();
        let wal = root.join("replica.wal");
        let error = require_ready_disjoint(&wal, &[], None, Some(&wal))
            .expect_err("ready path equal to WAL must fail before creation");
        assert_eq!(error.reason_code(), "PATH_ALIAS_REFUSED");
        let lock = file_lock_path(&wal);
        let error = require_ready_disjoint(&lock, &[], None, Some(&wal))
            .expect_err("ready path equal to lock must fail");
        assert_eq!(error.reason_code(), "PATH_ALIAS_REFUSED");
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[test]
    fn readiness_is_published_only_after_complete_staging_write() {
        let root = directory();
        let ready = root.join("node.ready");
        let staging = ready_staging_path(&ready);
        write_ready_file(&ready, "127.0.0.1:12345").expect("publish readiness");
        assert_eq!(
            fs::read_to_string(&ready).expect("read readiness"),
            "127.0.0.1:12345"
        );
        assert!(!staging.exists());
        let duplicate = write_ready_file(&ready, "127.0.0.1:54321")
            .expect_err("existing readiness must not be overwritten");
        assert_eq!(duplicate.reason_code(), "READY_FILE_FAILED");
        assert_eq!(
            fs::read_to_string(&ready).expect("read original readiness"),
            "127.0.0.1:12345"
        );
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[test]
    fn concurrent_readiness_publish_has_exactly_one_complete_winner() {
        let root = directory();
        let ready = root.join("node.ready");
        let barrier = Arc::new(Barrier::new(3));
        let (first, second) = std::thread::scope(|scope| {
            let first_barrier = Arc::clone(&barrier);
            let first_ready = &ready;
            let first = scope.spawn(move || {
                first_barrier.wait();
                write_ready_file(first_ready, "127.0.0.1:12345")
            });
            let second_barrier = Arc::clone(&barrier);
            let second_ready = &ready;
            let second = scope.spawn(move || {
                second_barrier.wait();
                write_ready_file(second_ready, "127.0.0.1:54321")
            });
            barrier.wait();
            (
                first.join().expect("join first publisher"),
                second.join().expect("join second publisher"),
            )
        });
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        let published = fs::read_to_string(&ready).expect("read readiness winner");
        assert!(matches!(
            published.as_str(),
            "127.0.0.1:12345" | "127.0.0.1:54321"
        ));
        assert!(!ready_staging_path(&ready).exists());
        fs::remove_dir_all(root).expect("remove path test directory");
    }

    #[cfg(unix)]
    #[test]
    fn hard_link_key_and_wal_alias_is_refused() {
        let root = directory();
        let key = root.join("candidate.seed");
        let wal = root.join("replica.wal");
        fs::write(&key, [11; 32]).expect("write key fixture");
        fs::hard_link(&key, &wal).expect("create hard-link alias");
        let error = require_keys_disjoint(&[key.as_path()], None, Some(&wal))
            .expect_err("hard-link alias must fail");
        assert_eq!(error.reason_code(), "PATH_ALIAS_REFUSED");
        fs::remove_dir_all(root).expect("remove path test directory");
    }
}
