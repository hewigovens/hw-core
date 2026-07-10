use std::{
    env, fs, io,
    os::unix::fs::{PermissionsExt, symlink},
    path::Path,
    process::Command,
    sync::{Arc, Barrier},
};

use tempfile::tempdir;

use super::{
    CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION, FileStorage, HostSnapshot, StorageError, ThpStorage,
    unix::{
        atomic_write, atomic_write_in_parent, open_secure_parent, read_secure_file_from_parent,
    },
};
use crate::thp::types::KnownCredential;

#[tokio::test]
async fn roundtrip_snapshot_uses_owner_only_permissions() {
    let dir = tempdir().unwrap();
    let parent = dir.path().join("state");
    let path = parent.join("thp.json");
    let storage = FileStorage::new(&path);
    let snapshot = HostSnapshot {
        schema_version: CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION,
        static_key: Some(vec![1, 2, 3]),
        known_credentials: vec![KnownCredential {
            credential: "cred".into(),
            trezor_static_public_key: Some(vec![4; 32]),
            autoconnect: true,
        }],
    };

    storage.persist(&snapshot).await.unwrap();
    let loaded = storage.load().await.unwrap();

    assert_eq!(loaded.schema_version, CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION);
    assert_eq!(loaded.static_key, snapshot.static_key);
    assert_eq!(loaded.known_credentials.len(), 1);
    assert_eq!(
        loaded.known_credentials[0].trezor_static_public_key,
        snapshot.known_credentials[0].trezor_static_public_key
    );
    assert_eq!(
        fs::metadata(parent).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[tokio::test]
async fn load_missing_returns_default() {
    let dir = tempdir().unwrap();
    let storage = FileStorage::new(dir.path().join("missing.json"));

    let loaded = storage.load().await.unwrap();

    assert_eq!(loaded.schema_version, CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION);
    assert!(loaded.static_key.is_none());
    assert!(loaded.known_credentials.is_empty());
}

#[tokio::test]
async fn load_newer_schema_returns_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("future.json");
    fs::write(
        &path,
        format!(
            r#"{{
  "schema_version": {},
  "static_key": [],
  "known_credentials": []
}}"#,
            CURRENT_HOST_SNAPSHOT_SCHEMA_VERSION + 1
        ),
    )
    .unwrap();

    let err = FileStorage::new(path)
        .load()
        .await
        .expect_err("future schema should fail");

    assert!(matches!(err, StorageError::UnsupportedSchemaVersion { .. }));
}

#[tokio::test]
async fn legacy_permissions_are_repaired_or_rejected() {
    let dir = tempdir().unwrap();
    let readable_path = dir.path().join("readable.json");
    fs::write(
        &readable_path,
        serde_json::to_vec(&HostSnapshot::default()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&readable_path, fs::Permissions::from_mode(0o644)).unwrap();

    FileStorage::new(&readable_path).load().await.unwrap();
    assert_eq!(
        fs::metadata(readable_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    for mode in [0o666, 0o620, 0o602] {
        let path = dir.path().join(format!("writable-{mode:o}.json"));
        fs::write(&path, serde_json::to_vec(&HostSnapshot::default()).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();

        let err = FileStorage::new(path)
            .load()
            .await
            .expect_err("group- or world-writable storage should fail");
        assert!(
            matches!(err, StorageError::Io(ref io) if io.kind() == io::ErrorKind::PermissionDenied)
        );
    }
}

#[tokio::test]
async fn persist_rejects_writable_direct_parent() {
    let dir = tempdir().unwrap();
    let parent = dir.path().join("shared");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();

    let err = FileStorage::new(parent.join("thp.json"))
        .persist(&HostSnapshot::default())
        .await
        .expect_err("group-writable parent should fail");

    assert!(
        matches!(err, StorageError::Io(ref io) if io.kind() == io::ErrorKind::PermissionDenied)
    );
}

#[tokio::test]
async fn persist_allows_writable_ancestor_when_direct_parent_is_secure() {
    let dir = tempdir().unwrap();
    let shared = dir.path().join("shared");
    let parent = shared.join("private");
    fs::create_dir_all(&parent).unwrap();
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o770)).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let path = parent.join("thp.json");

    FileStorage::new(&path)
        .persist(&HostSnapshot::default())
        .await
        .unwrap();

    assert!(path.is_file());
}

#[tokio::test]
async fn symlink_and_hard_link_storage_paths_are_rejected() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target.json");
    let path = dir.path().join("thp.json");
    fs::write(
        &target,
        serde_json::to_vec(&HostSnapshot::default()).unwrap(),
    )
    .unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

    symlink(&target, &path).unwrap();
    assert!(matches!(
        FileStorage::new(&path).load().await,
        Err(StorageError::Io(_))
    ));

    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    let err = FileStorage::new(&path)
        .load()
        .await
        .expect_err("hard-linked storage should fail");
    assert!(
        matches!(err, StorageError::Io(ref io) if io.kind() == io::ErrorKind::PermissionDenied)
    );

    let real_parent = dir.path().join("real");
    let linked_parent = dir.path().join("linked");
    fs::create_dir(&real_parent).unwrap();
    fs::set_permissions(&real_parent, fs::Permissions::from_mode(0o700)).unwrap();
    symlink(&real_parent, &linked_parent).unwrap();
    assert!(matches!(
        FileStorage::new(linked_parent.join("thp.json"))
            .persist(&HostSnapshot::default())
            .await,
        Err(StorageError::Io(_))
    ));
    assert!(!real_parent.join("thp.json").exists());
}

#[test]
fn pinned_parent_descriptor_resists_path_replacement() {
    let dir = tempdir().unwrap();
    let trusted = dir.path().join("trusted");
    let moved = dir.path().join("moved");
    let replacement = dir.path().join("replacement");
    fs::create_dir(&trusted).unwrap();
    fs::create_dir(&replacement).unwrap();
    fs::set_permissions(&trusted, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&replacement, fs::Permissions::from_mode(0o700)).unwrap();
    let path = trusted.join("thp.json");
    atomic_write(&path, b"trusted").unwrap();
    let parent = open_secure_parent(&path).unwrap();

    fs::rename(&trusted, &moved).unwrap();
    symlink(&replacement, &trusted).unwrap();
    fs::write(replacement.join("thp.json"), b"replacement").unwrap();

    assert_eq!(
        read_secure_file_from_parent(&parent).unwrap(),
        Some(b"trusted".to_vec())
    );
    atomic_write_in_parent(&parent, b"updated").unwrap();
    assert_eq!(fs::read(moved.join("thp.json")).unwrap(), b"updated");
    assert_eq!(
        fs::read(replacement.join("thp.json")).unwrap(),
        b"replacement"
    );
}

#[test]
fn concurrent_atomic_writes_do_not_share_temporary_files() {
    let dir = tempdir().unwrap();
    let path = Arc::new(dir.path().join("thp.json"));
    let barrier = Arc::new(Barrier::new(2));
    let payloads = [vec![0x11; 1024 * 1024], vec![0x22; 1024 * 1024]];
    let handles: Vec<_> = payloads
        .iter()
        .cloned()
        .map(|payload| {
            let path = Arc::clone(&path);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                atomic_write(&path, &payload)
            })
        })
        .collect();

    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    let stored = fs::read(&*path).unwrap();
    assert!(stored == payloads[0] || stored == payloads[1]);
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn basename_storage_rejects_group_writable_cwd() {
    const CHILD_ENV: &str = "HW_CORE_TEST_INSECURE_BASENAME_CWD";
    if env::var_os(CHILD_ENV).is_some() {
        let err = atomic_write(Path::new("thp.json"), b"secret").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(!Path::new("thp.json").exists());
        return;
    }

    let dir = tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o770)).unwrap();
    let status = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "thp::storage::tests::basename_storage_rejects_group_writable_cwd",
            "--nocapture",
        ])
        .env(CHILD_ENV, "1")
        .current_dir(dir.path())
        .status()
        .unwrap();

    assert!(status.success());
    assert!(!dir.path().join("thp.json").exists());
}

#[test]
fn invalid_storage_path_is_rejected() {
    let err = atomic_write(Path::new("/"), b"secret").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
}
