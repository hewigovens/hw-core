use std::{fs, io, os::unix::fs::PermissionsExt, process::Command};

use tempfile::tempdir;

use super::{FileStorage, HostSnapshot, StorageError, ThpStorage, acl};

fn add_read_acl(path: &std::path::Path) {
    assert!(
        Command::new("chmod")
            .args(["+a", "everyone allow read"])
            .arg(path)
            .status()
            .unwrap()
            .success()
    );
}

#[tokio::test]
async fn extended_acls_are_rejected_without_mutation() {
    let dir = tempdir().unwrap();
    let parent = dir.path().join("state");
    let path = parent.join("thp.json");
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    add_read_acl(&parent);
    assert!(acl::has_entries(&fs::File::open(&parent).unwrap()).unwrap());

    let err = FileStorage::new(&path)
        .persist(&HostSnapshot::default())
        .await
        .expect_err("extended ACL storage parent should fail");
    assert!(
        matches!(err, StorageError::Io(ref io) if io.kind() == io::ErrorKind::PermissionDenied)
    );
    assert!(acl::has_entries(&fs::File::open(&parent).unwrap()).unwrap());
    assert!(!path.exists());

    let path = dir.path().join("existing.json");
    fs::write(&path, serde_json::to_vec(&HostSnapshot::default()).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    add_read_acl(&path);
    assert!(acl::has_entries(&fs::File::open(&path).unwrap()).unwrap());

    let err = FileStorage::new(path)
        .load()
        .await
        .expect_err("extended ACL storage file should fail");
    assert!(
        matches!(err, StorageError::Io(ref io) if io.kind() == io::ErrorKind::PermissionDenied)
    );
}
