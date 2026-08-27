use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use quorumarc_store::{
    AuthoritySnapshot, DurableAuthorityStore, FileBackend, StateRoot, StoreError, StoreIdentity,
    StorePaths, StoreRole,
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> io::Result<Self> {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "quorumarc-store-identity-{label}-{}-{sequence}",
            std::process::id()
        ));
        match fs::remove_dir_all(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _cleanup_result = fs::remove_dir_all(&self.0);
    }
}

fn identity(
    cluster: &str,
    workload: &str,
    node: &str,
    role: StoreRole,
    store_id: [u8; 16],
) -> Result<StoreIdentity, Box<dyn Error>> {
    Ok(StoreIdentity::new(cluster, workload, node, role, store_id)?)
}

fn durable_source(directory: &Path) -> Result<(StoreIdentity, Vec<u8>), Box<dyn Error>> {
    let expected = identity(
        "cluster-a",
        "orders",
        "node-a",
        StoreRole::DataNode,
        [31; 16],
    )?;
    let paths = StorePaths::new(directory);
    let mut store = DurableAuthorityStore::open(paths.clone(), expected.clone(), FileBackend)?;
    store.allocate_incarnation(7)?;
    store.record_progress(41, StateRoot::new([9; 32]))?;
    drop(store);
    Ok((expected, fs::read(paths.committed())?))
}

#[test]
fn committed_frame_round_trips_identity_through_read_only_snapshot() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("snapshot")?;
    let paths = StorePaths::new(directory.path());
    let (expected, bytes) = durable_source(directory.path())?;
    fs::write(paths.temporary(), b"inspection-must-not-touch-staging")?;

    let snapshot = AuthoritySnapshot::decode(&bytes)?;
    assert_eq!(snapshot.identity(), &expected);
    assert_eq!(snapshot.generation(), 2);
    assert_eq!(snapshot.state().incarnation(), 7);
    assert_eq!(snapshot.state().commit_index(), 41);
    assert_eq!(
        fs::read(paths.temporary())?,
        b"inspection-must-not-touch-staging"
    );

    let recovered = DurableAuthorityStore::open(paths, expected.clone(), FileBackend)?;
    assert_eq!(recovered.identity(), &expected);
    assert_eq!(recovered.generation(), 2);
    Ok(())
}

#[test]
fn copied_store_is_refused_for_every_identity_dimension() -> Result<(), Box<dyn Error>> {
    let source = TestDirectory::new("copy-source")?;
    let (_durable_identity, bytes) = durable_source(source.path())?;
    let mismatches = [
        identity(
            "cluster-b",
            "orders",
            "node-a",
            StoreRole::DataNode,
            [31; 16],
        )?,
        identity(
            "cluster-a",
            "payments",
            "node-a",
            StoreRole::DataNode,
            [31; 16],
        )?,
        identity(
            "cluster-a",
            "orders",
            "node-b",
            StoreRole::DataNode,
            [31; 16],
        )?,
        identity(
            "cluster-a",
            "orders",
            "node-a",
            StoreRole::Witness,
            [31; 16],
        )?,
        identity(
            "cluster-a",
            "orders",
            "node-a",
            StoreRole::DataNode,
            [32; 16],
        )?,
    ];

    for (index, expected) in mismatches.into_iter().enumerate() {
        let target = TestDirectory::new(&format!("copy-target-{index}"))?;
        let paths = StorePaths::new(target.path());
        fs::write(paths.committed(), &bytes)?;
        let staging_marker = format!("preserve-before-refusal-{index}").into_bytes();
        fs::write(paths.temporary(), &staging_marker)?;

        let error = DurableAuthorityStore::open(paths.clone(), expected.clone(), FileBackend)
            .err()
            .ok_or("copied store unexpectedly opened under another identity")?;
        let StoreError::IdentityMismatch {
            expected: reported,
            durable,
        } = error
        else {
            return Err("copied store returned the wrong refusal type".into());
        };
        assert_eq!(*reported, expected);
        assert_eq!(durable.cluster_id(), "cluster-a");
        assert_eq!(durable.workload_id(), "orders");
        assert_eq!(durable.node_id(), "node-a");
        assert_eq!(durable.role(), StoreRole::DataNode);
        assert_eq!(durable.store_id(), &[31; 16]);
        assert_eq!(fs::read(paths.temporary())?, staging_marker);
    }
    Ok(())
}

#[test]
fn first_authority_transition_durably_binds_a_fresh_store() -> Result<(), Box<dyn Error>> {
    let directory = TestDirectory::new("first-bind")?;
    let paths = StorePaths::new(directory.path());
    let expected = identity(
        "cluster-a",
        "orders",
        "node-a",
        StoreRole::DataNode,
        [41; 16],
    )?;
    let mut store = DurableAuthorityStore::open(paths.clone(), expected.clone(), FileBackend)?;
    assert_eq!(store.generation(), 0);
    assert!(!paths.committed().exists());

    let receipt = store.allocate_incarnation(1)?;
    assert_eq!(receipt.generation(), 1);
    drop(store);

    let snapshot = AuthoritySnapshot::decode(&fs::read(paths.committed())?)?;
    assert_eq!(snapshot.identity(), &expected);
    let wrong_node = identity(
        "cluster-a",
        "orders",
        "node-b",
        StoreRole::DataNode,
        [41; 16],
    )?;
    assert!(matches!(
        DurableAuthorityStore::open(paths, wrong_node, FileBackend),
        Err(StoreError::IdentityMismatch { .. })
    ));
    Ok(())
}
