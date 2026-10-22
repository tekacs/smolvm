use super::*;
use std::os::unix::{
    fs::{symlink, PermissionsExt},
    net::UnixListener,
};

fn exposed(guest: &str, host: Option<&Path>) -> PublishedSocketConfig {
    PublishedSocketConfig {
        direction: SocketDirection::Expose,
        guest_path: guest.into(),
        host_path: host.map(|p| p.to_str().unwrap().into()),
    }
}
fn allocate(root: &Path) -> Allocation {
    Allocation::prepare(root, &mut [exposed("/service.sock", None)])
        .unwrap()
        .unwrap()
}

#[test]
fn only_implicit_exposes_are_allocated_and_reopen_keeps_the_same_routes() {
    let root = tempfile::tempdir().unwrap();
    let caller = root.path().join("caller");
    let borrowed = root.path().join("borrowed");
    let explicit = UnixListener::bind(&caller).unwrap();
    let mounted = UnixListener::bind(&borrowed).unwrap();
    let mut sockets = vec![
        exposed("/service.sock", None),
        exposed("/control.sock", None),
        exposed("/caller.sock", Some(&caller)),
        PublishedSocketConfig {
            direction: SocketDirection::Mount,
            guest_path: "/reverse.sock".into(),
            host_path: Some(borrowed.to_str().unwrap().into()),
        },
    ];
    let prior = sockets.clone();
    let owned = Allocation::prepare(root.path(), &mut sockets)
        .unwrap()
        .unwrap();
    assert_eq!(&sockets[2..], &prior[2..]);
    assert_eq!(owned.routes().unwrap(), sockets[..2]);
    assert_eq!(
        std::fs::metadata(&owned.directory)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let persisted = serde_json::to_vec(&owned).unwrap();
    let reopened: Allocation = serde_json::from_slice(&persisted).unwrap();
    reopened.validate(root.path()).unwrap();
    assert_eq!(reopened.routes().unwrap(), owned.routes().unwrap());
    let other = allocate(root.path());
    assert_ne!(other.directory, owned.directory);
    other.remove().unwrap();
    // No listener was ever bound. Allocation identity still permits empty cleanup.
    reopened.remove().unwrap();
    reopened.remove().unwrap();
    assert!(caller.exists() && borrowed.exists());
    assert!(Allocation::prepare(root.path(), &mut sockets[2..])
        .unwrap()
        .is_none());
    drop((explicit, mounted));
}

#[test]
fn replacement_directories_and_symlinks_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let owned = allocate(root.path());
    let moved = root.path().join("moved");
    std::fs::rename(&owned.directory, &moved).unwrap();
    std::fs::create_dir(&owned.directory).unwrap();
    let replacement = UnixListener::bind(owned.endpoint(0)).unwrap();
    assert!(owned.routes().is_err());
    assert!(owned.remove().is_err());
    assert!(owned.endpoint(0).exists());
    drop(replacement);
    std::fs::remove_file(owned.endpoint(0)).unwrap();
    std::fs::remove_dir(&owned.directory).unwrap();
    symlink(&moved, &owned.directory).unwrap();
    assert!(owned.remove().is_err());
    assert!(std::fs::symlink_metadata(&owned.directory)
        .unwrap()
        .file_type()
        .is_symlink());
}

#[test]
fn cleanup_refuses_unknown_entries_and_validates_every_entry_before_deletion() {
    let root = tempfile::tempdir().unwrap();
    let owned = allocate(root.path());
    let listener = UnixListener::bind(owned.endpoint(0)).unwrap();
    std::fs::write(owned.directory.join("foreign"), b"keep").unwrap();
    assert!(owned.remove().is_err());
    assert!(owned.endpoint(0).exists());
    assert_eq!(
        std::fs::read(owned.directory.join("foreign")).unwrap(),
        b"keep"
    );
    std::fs::remove_file(owned.directory.join("foreign")).unwrap();
    drop(listener);
    std::fs::remove_file(owned.endpoint(0)).unwrap();
    std::fs::write(owned.endpoint(0), b"replacement").unwrap();
    assert!(owned.remove().is_err());
    assert_eq!(std::fs::read(owned.endpoint(0)).unwrap(), b"replacement");
    std::fs::remove_file(owned.endpoint(0)).unwrap();
    let listener = UnixListener::bind(owned.endpoint(0)).unwrap();
    drop(listener);
    owned.remove().unwrap();
    assert!(!owned.directory.exists());
}

#[test]
fn allocation_metadata_cannot_escape_its_execution_directory() {
    let root = tempfile::tempdir().unwrap();
    let owned = allocate(root.path());
    let other = tempfile::tempdir().unwrap();
    assert!(owned.validate(other.path()).is_err());
    let mut changed = owned.clone();
    changed.guests[0] = "relative".into();
    assert!(changed.validate(root.path()).is_err());
    owned.remove().unwrap();
}

#[test]
fn caller_owned_endpoints_block_recursive_deletion_even_through_parent_aliases() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("machine");
    std::fs::create_dir(&directory).unwrap();
    let alias = root.path().join("alias");
    symlink(&directory, &alias).unwrap();
    let listener = UnixListener::bind(directory.join("borrowed")).unwrap();
    let mut sockets = [PublishedSocketConfig {
        direction: SocketDirection::Mount,
        guest_path: "/host.sock".into(),
        host_path: Some(alias.join("borrowed").to_str().unwrap().into()),
    }];
    assert!(protect(&directory, &sockets).is_err());
    sockets[0].direction = SocketDirection::Expose;
    assert!(protect(&directory, &sockets).is_err());
    assert!(directory.join("borrowed").exists());
    drop(listener);
    std::fs::remove_file(directory.join("borrowed")).unwrap();
    protect(&directory, &sockets).unwrap();
}
