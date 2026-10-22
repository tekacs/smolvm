use super::*;
use std::process::{Command, Stdio};

fn fixture(root: &Path, boot: String) -> Execution {
    let group = root.join("group");
    std::fs::create_dir(&group).unwrap();
    Execution {
        path: root.join("agent.pid"),
        pid: std::process::id() as i32,
        start: super::super::process_start_time(std::process::id() as i32).unwrap(),
        boot,
        containment: Containment {
            group: Cgroup::capture(&group).unwrap(),
            exited: false,
            proof: None,
            endpoints: None,
        },
    }
}
fn save(record: &Execution) {
    publish(
        &record.path,
        record.pid,
        record.start,
        &record.boot,
        Some(&record.containment),
    )
    .unwrap();
}

#[test]
fn missing_legacy_corrupt_or_uncontained_records_do_not_prove_exit() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("agent.pid");
    assert!(Execution::load(&path).unwrap().is_none());
    std::fs::write(&path, "12\n34\n").unwrap();
    assert!(Execution::load(&path).unwrap().is_none());
    std::fs::write(&path, "12\n34\ninvalid\ncontainment-v1:{}\n").unwrap();
    assert!(Execution::load(&path).is_err());
    std::fs::write(&path, "x".repeat(16384)).unwrap();
    assert!(Execution::load(&path).is_err());
    let record = fixture(root.path(), boot_id().unwrap());
    save(&record);
    assert_eq!(Execution::load(&path).unwrap().unwrap(), record);
    assert!(
        record.exited().is_err(),
        "ordinary directory is not kernel containment"
    );
    assert!(super::record(&path, std::process::id() as i32, None, None).is_err());
}

#[test]
fn previous_boot_proves_exit_and_completion_survives_reopen() {
    let root = tempfile::tempdir().unwrap();
    let previous = "00000000-0000-0000-0000-000000000000".to_string();
    assert_ne!(previous, boot_id().unwrap());
    let record = fixture(root.path(), previous);
    save(&record);
    assert!(record.exited().unwrap());
    record
        .pin()
        .unwrap()
        .stop(Duration::ZERO, Duration::ZERO)
        .unwrap();
    let finished = Execution::load(&record.path).unwrap().unwrap();
    assert!(finished.containment.exited);
    std::fs::remove_dir(root.path().join("group")).unwrap();
    assert!(finished.exited().unwrap());
    assert_eq!(finished.pid(), record.pid());
    assert_eq!(finished.started(), record.started());
}

#[test]
fn stale_completion_cannot_replace_a_newer_incarnation() {
    let root = tempfile::tempdir().unwrap();
    let old = fixture(root.path(), boot_id().unwrap());
    save(&old);
    let mut newer = old.clone();
    newer.start += 1;
    save(&newer);
    let before = std::fs::read(&old.path).unwrap();
    assert!(old.complete().is_err());
    assert_eq!(std::fs::read(&old.path).unwrap(), before);
}

#[test]
fn removed_group_and_dead_process_persist_current_absence_without_deleting_evidence() {
    let root = tempfile::tempdir().unwrap();
    let mut record = fixture(root.path(), boot_id().unwrap());
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    record.pid = child.id() as i32;
    record.start = super::super::process_start_time(child.id() as i32).unwrap();
    save(&record);
    child.kill().unwrap(); child.wait().unwrap();
    std::fs::remove_dir(root.path().join("group")).unwrap();
    assert!(record.exited().unwrap());
    let reopened = Execution::load(&record.path).unwrap().unwrap();
    assert!(reopened.containment.exited);
    assert_eq!(reopened.containment.proof, Some(ExitProof::Absent));
    assert_eq!(reopened.pid, record.pid);
    assert_eq!(reopened.start, record.start);
    assert!(record.exited().unwrap(), "old handle accepts its durable completion");
    record.reclaim().unwrap();
    assert!(record.path.exists(), "reconciliation retains the original record");
}

#[test]
fn missing_group_with_live_process_or_replacement_never_becomes_absence_proof() {
    let root = tempfile::tempdir().unwrap();
    let record = fixture(root.path(), boot_id().unwrap()); save(&record);
    let before = std::fs::read(&record.path).unwrap();
    std::fs::remove_dir(root.path().join("group")).unwrap();
    assert!(record.exited().is_err());
    std::fs::create_dir(root.path().join("group")).unwrap();
    assert!(record.exited().is_err());
    assert_eq!(std::fs::read(&record.path).unwrap(), before);
}

#[test]
#[ignore = "requires an explicit disposable delegated SMOLVM_TEST_CGROUP root"]
fn removed_kernel_group_reconciles_exit_before_new_incarnation() {
    let base = PathBuf::from(std::env::var_os("SMOLVM_TEST_CGROUP").expect("explicit delegated root"));
    let leaf = base.join(format!("removed-proof-{}", std::process::id()));
    std::fs::create_dir(&leaf).unwrap();
    let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    if let Err(error) = std::fs::write(leaf.join("cgroup.procs"), child.id().to_string()) {
        let _ = child.kill(); let _ = child.wait(); let _ = std::fs::remove_dir(&leaf);
        panic!("cannot place synthetic child: {error}");
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("agent.pid");
    let identity = Cgroup::capture(&leaf).unwrap();
    let mut pinned = identity.open().unwrap();
    super::record(&path, child.id() as i32, Some(identity), None).unwrap();
    child.kill().unwrap(); child.wait().unwrap();
    std::fs::remove_dir(&leaf).unwrap();
    assert!(pinned.empty().unwrap(), "removed held group is empty on the real kernel");
    let prior = Execution::load(&path).unwrap().unwrap();
    assert!(prior.exited().unwrap());
    assert_eq!(Execution::load(&path).unwrap().unwrap().containment.proof, Some(ExitProof::Absent));
    prior.reclaim().unwrap();
    assert!(path.exists());
}

/// Explicit native test: no VM or helper image; only this test's two processes.
#[test]
#[ignore = "requires an explicit delegated SMOLVM_TEST_CGROUP root"]
fn whole_group_exit_outlives_parent_and_survives_controller_reopen() {
    use std::io::{BufRead, BufReader};
    let root = tempfile::tempdir().unwrap();
    let delegated = std::env::var_os("SMOLVM_TEST_CGROUP").expect("explicit test delegation");
    struct Owned {
        child: std::process::Child,
        group: Option<Cgroup>,
    }
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.child.kill();
            if let Some(group) = &self.group {
                if let Ok(mut pinned) = group.open() {
                    let _ = pinned.kill();
                    let _ = pinned.wait(Instant::now() + Duration::from_secs(3));
                }
            }
            let _ = self.child.wait();
        }
    }
    let mut owned = Owned {
        child: Command::new("/bin/sh")
            .args([
                "-c",
                "read ready; sleep 60 & printf 'DESCENDANT:%s\\n' \"$!\"; read exit",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap(),
        group: None,
    };
    let pid = owned.child.id() as i32;
    let group =
        super::super::cgroup::place(Path::new(&delegated), pid, 1, 128, false, false).unwrap();
    owned.group = Some(group.clone());
    let path = root.path().join("agent.pid");
    let mut sockets = vec![crate::config::PublishedSocketConfig {
        direction: crate::config::SocketDirection::Expose,
        guest_path: "/private/service.sock".into(),
        host_path: None,
    }];
    let endpoints = super::super::sockets::Allocation::prepare(root.path(), &mut sockets).unwrap();
    super::record(&path, pid, Some(group), endpoints).unwrap();
    let execution = Execution::load(&path).unwrap().unwrap();
    let guard = execution.pin().unwrap();
    owned
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"go\n")
        .unwrap();
    let mut ready = String::new();
    BufReader::new(owned.child.stdout.take().unwrap())
        .read_line(&mut ready)
        .unwrap();
    assert!(ready.starts_with("DESCENDANT:"));
    drop(owned.child.stdin.take());
    assert!(guard
        .process_exited(Instant::now() + Duration::from_secs(3))
        .unwrap());
    owned.child.wait().unwrap();
    assert!(
        !execution.exited().unwrap(),
        "VMM exit does not prove descendant exit"
    );
    assert!(
        execution.reclaim().is_err(),
        "live descendants retain even unbound socket allocation"
    );
    assert_eq!(execution.sockets().unwrap(), sockets);
    // Fresh lookup models a replacement controller with no in-memory process owner.
    let reopened = Execution::load(&path).unwrap().unwrap();
    reopened
        .pin()
        .unwrap()
        .stop(Duration::ZERO, Duration::from_secs(3))
        .unwrap();
    let complete = Execution::load(&path).unwrap().unwrap();
    assert!(complete.containment.exited);
    assert!(complete.exited().unwrap());
    assert!(!Path::new(sockets[0].host_path.as_ref().unwrap())
        .parent()
        .unwrap()
        .exists());
    let leaf = Path::new(&delegated).join(format!("vm-{pid}"));
    std::fs::remove_dir(&leaf).unwrap();
    assert!(Execution::load(&path).unwrap().unwrap().exited().unwrap());
}

#[test]
fn prebind_allocation_survives_record_reopen_and_stale_cleanup_is_refused() {
    let root = tempfile::tempdir().unwrap();
    let mut record = fixture(root.path(), "00000000-0000-0000-0000-000000000000".into());
    let mut sockets = vec![crate::config::PublishedSocketConfig {
        direction: crate::config::SocketDirection::Expose,
        guest_path: "/service.sock".into(),
        host_path: None,
    }];
    record.containment.endpoints =
        super::super::sockets::Allocation::prepare(root.path(), &mut sockets).unwrap();
    save(&record);
    let reopened = Execution::load(&record.path).unwrap().unwrap();
    assert_eq!(reopened.sockets().unwrap(), sockets);
    let endpoint = Path::new(sockets[0].host_path.as_ref().unwrap());
    assert!(!endpoint.exists());
    assert!(endpoint.parent().unwrap().exists());
    let mut successor = reopened.clone();
    successor.start += 1;
    save(&successor);
    assert!(reopened.reclaim().is_err());
    assert!(reopened.sockets().is_err());
    assert!(endpoint.parent().unwrap().exists());
    successor.reclaim().unwrap();
    assert!(!endpoint.parent().unwrap().exists());
}

#[test]
fn owned_allocation_cannot_be_published_without_containment() {
    let root = tempfile::tempdir().unwrap();
    let mut sockets = vec![crate::config::PublishedSocketConfig {
        direction: crate::config::SocketDirection::Expose,
        guest_path: "/service.sock".into(),
        host_path: None,
    }];
    let allocation = super::super::sockets::Allocation::prepare(root.path(), &mut sockets)
        .unwrap()
        .unwrap();
    let path = root.path().join("agent.pid");
    assert!(super::record(
        &path,
        std::process::id() as i32,
        None,
        Some(allocation.clone())
    )
    .is_err());
    assert!(!path.exists());
    allocation.remove().unwrap();
}

#[test]
fn pidfd_pins_exact_incarnation_and_mismatch_never_selects_the_process() {
    let mut child = Command::new("/bin/sh")
        .args(["-c", "read ignored"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    let pid = child.id() as i32;
    let start = super::super::process_start_time(pid).unwrap();
    let fd = process(pid, start).unwrap().unwrap();
    assert!(!wait(&fd, libc::POLLIN, Instant::now()).unwrap());
    assert!(process(pid, start + 1).unwrap().is_none());
    assert!(child.try_wait().unwrap().is_none());
    drop(child.stdin.take());
    assert!(wait(&fd, libc::POLLIN, Instant::now() + Duration::from_secs(3)).unwrap());
    child.wait().unwrap();
}
