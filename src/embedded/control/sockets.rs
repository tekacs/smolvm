use super::*;
use crate::config::{PublishedSocketConfig, SocketDirection};

fn spec() -> MachineSpec {
    MachineSpec {
        name: "socket-service".into(),
        persistent: true,
        detached: true,
        init: vec!["install -d -m 0700 -o 1000 -g 1000 /workspace/service".into()],
        published_sockets: vec![
            PublishedSocketConfig {
                direction: SocketDirection::Expose,
                guest_path: "/private/service.sock".into(),
                host_path: Some("/tmp/service.sock".into()),
            },
            PublishedSocketConfig {
                direction: SocketDirection::Mount,
                guest_path: "/private/host.sock".into(),
                host_path: Some("/tmp/host.sock".into()),
            },
        ],
        ..Default::default()
    }
}

#[test]
fn both_socket_directions_survive_registry_reopen_and_launch_reconstruction() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("registry.sqlite");
    let requested = spec();
    {
        let db = SmolvmDb::open_at(&path).unwrap();
        create_vm(&db, &requested).unwrap();
    }
    let db = SmolvmDb::open_at(&path).unwrap();
    let record = get_record(&db, &requested.name).unwrap();
    assert_eq!(record.published_sockets, requested.published_sockets);
    assert_eq!(record.init, requested.init);
    assert!(!record.init_completed);
    let features = merge_record_launch_features(&record, LaunchFeatures::default());
    assert_eq!(features.published_sockets, requested.published_sockets);
    assert_eq!(features.watch_parent, Some(false));
    assert!(!record.vm_resources().network);
    // The registry remains independently readable with the selected fixed SQLite.
    assert_eq!(rusqlite::version(), "3.53.2");
}

#[test]
fn invalid_socket_spec_does_not_leave_a_registry_record() {
    let root = tempfile::tempdir().unwrap();
    let db = SmolvmDb::open_at(&root.path().join("registry.sqlite")).unwrap();
    let mut requested = spec();
    requested.published_sockets[1].guest_path = "relative".into();
    assert!(create_vm(&db, &requested).is_err());
    assert!(db.get_vm(&requested.name).unwrap().is_none());
}

#[test]
fn invalid_persisted_socket_is_refused_before_launch_preparation() {
    let mut record = spec().to_record();
    record.published_sockets[1].host_path = None;
    assert!(record_launch_features(&record, LaunchFeatures::default()).is_err());
}
