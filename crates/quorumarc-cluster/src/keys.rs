use std::fs;
use std::path::Path;

use quorumarc_wire::{SigningKey, VerifyingKey};

use crate::path_guard::reject_symlink_components;
use crate::{ClusterError, err};

/// Loads an exact 32-byte Ed25519 seed from a regular, non-symlink `0600`
/// file. The seed is never inferred, embedded, or loaded by another role.
pub fn load_private_seed(path: &Path) -> Result<SigningKey, ClusterError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| err("KEY_READ_FAILED", format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(err(
            "KEY_FILE_INVALID",
            format!("{} is not a regular non-symlink file", path.display()),
        ));
    }
    ensure_private_permissions(path, &metadata)?;
    let bytes = fs::read(path)
        .map_err(|error| err("KEY_READ_FAILED", format!("{}: {error}", path.display())))?;
    let seed: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        err(
            "KEY_LENGTH_INVALID",
            format!("{} must contain exactly 32 raw bytes", path.display()),
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Loads an exact 32-byte Ed25519 public key from a regular, non-symlink file.
/// Candidate bootstrap uses this function for the witness and never creates a
/// witness [`SigningKey`].
pub fn load_public_key(path: &Path) -> Result<VerifyingKey, ClusterError> {
    reject_symlink_components(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| err("KEY_READ_FAILED", format!("{}: {error}", path.display())))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(err(
            "KEY_FILE_INVALID",
            format!("{} is not a regular non-symlink file", path.display()),
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| err("KEY_READ_FAILED", format!("{}: {error}", path.display())))?;
    let encoded: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        err(
            "KEY_LENGTH_INVALID",
            format!("{} must contain exactly 32 raw bytes", path.display()),
        )
    })?;
    VerifyingKey::from_bytes(&encoded).map_err(|error| {
        err(
            "KEY_ENCODING_INVALID",
            format!("{}: {error}", path.display()),
        )
    })
}

pub(crate) fn require_distinct_role_keys(
    keys: &[(&str, &VerifyingKey)],
) -> Result<(), ClusterError> {
    for (index, (first_role, first_key)) in keys.iter().enumerate() {
        for (second_role, second_key) in keys.iter().skip(index.saturating_add(1)) {
            if first_key.as_bytes() == second_key.as_bytes() {
                return Err(err(
                    "KEY_ROLE_ALIAS_REFUSED",
                    format!("{first_role} and {second_role} use the same public key"),
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_permissions(path: &Path, metadata: &fs::Metadata) -> Result<(), ClusterError> {
    use std::os::unix::fs::MetadataExt;

    let permissions = metadata.mode() & 0o777;
    if permissions != 0o600 {
        return Err(err(
            "KEY_PERMISSIONS_INVALID",
            format!(
                "{} has mode {permissions:03o}; exact 600 is required",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_private_permissions(path: &Path, _metadata: &fs::Metadata) -> Result<(), ClusterError> {
    Err(err(
        "KEY_PERMISSIONS_UNSUPPORTED",
        format!(
            "{} cannot be permission-validated outside the Ubuntu lab",
            path.display()
        ),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT: AtomicU64 = AtomicU64::new(1);

    fn directory() -> PathBuf {
        let value = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-cluster-key-{}-{value}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create test directory");
        path
    }

    #[cfg(unix)]
    #[test]
    fn private_seed_requires_exact_mode_0600() {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        let root = directory();
        let path = root.join("seed");
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .open(&path)
            .expect("open test seed");
        file.write_all(&[11; 32]).expect("write test seed");
        file.sync_all().expect("sync test seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("set insecure test permissions");
        let error = load_private_seed(&path).expect_err("mode must be refused");
        assert_eq!(error.reason_code(), "KEY_PERMISSIONS_INVALID");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        let root = directory();
        let path = root.join("public");
        fs::write(&path, [4; 31]).expect("write public fixture");
        let error = load_public_key(&path).expect_err("length must be refused");
        assert_eq!(error.reason_code(), "KEY_LENGTH_INVALID");
        fs::remove_dir_all(root).expect("remove test directory");
    }

    #[test]
    fn role_keys_must_be_distinct_by_value_not_only_path() {
        let first = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let same = SigningKey::from_bytes(&[7; 32]).verifying_key();
        let error = require_distinct_role_keys(&[("candidate", &first), ("witness", &same)])
            .expect_err("same key bytes across roles must fail");
        assert_eq!(error.reason_code(), "KEY_ROLE_ALIAS_REFUSED");
    }
}
