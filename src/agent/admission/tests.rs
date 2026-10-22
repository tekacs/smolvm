use super::*;

fn child(root: &Path) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "agent::admission::tests::child_entry",
            "--ignored",
        ])
        .env("BOOT_TEST_ROOT", root)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    configure(&mut command);
    command.spawn().unwrap()
}

#[test]
#[ignore = "entrypoint launched explicitly by admission tests"]
fn child_entry() {
    let root = std::env::var_os("BOOT_TEST_ROOT").unwrap();
    if wait().is_ok() {
        assert_eq!(parent().unwrap(), unsafe { libc::getppid() });
        std::fs::write(Path::new(&root).join("admitted"), b"yes").unwrap();
    }
}

#[test]
fn closed_controller_pipe_never_admits_boot() {
    let root = tempfile::tempdir().unwrap();
    let mut boot = child(root.path());
    drop(boot.stdin.take());
    assert!(boot.wait().unwrap().success());
    assert!(!root.path().join("admitted").exists());
}

#[test]
fn failed_identity_publication_never_admits_boot() {
    let root = tempfile::tempdir().unwrap();
    let mut boot = child(root.path());
    let pid = boot.id() as i32;
    assert!(release(&mut boot, || record(
        &root.path().join("missing/agent.pid"),
        pid
    ))
    .is_err());
    assert!(!root.path().join("admitted").exists());
}

#[test]
fn failed_containment_never_admits_boot() {
    let root = tempfile::tempdir().unwrap();
    let mut boot = child(root.path());
    assert!(release(&mut boot, || Err(Error::agent(
        "contain child",
        "synthetic refusal"
    )))
    .is_err());
    assert!(boot.try_wait().unwrap().is_some());
    assert!(!root.path().join("admitted").exists());
}

#[test]
fn admitted_child_has_durable_exact_identity() {
    let root = tempfile::tempdir().unwrap();
    let mut boot = child(root.path());
    let pid = boot.id();
    let start = crate::process::process_start_time(pid as i32).unwrap();
    let identity = root.path().join("agent.pid");
    release(&mut boot, || record(&identity, pid as i32)).unwrap();
    assert!(boot.wait().unwrap().success());
    assert!(root.path().join("admitted").exists());
    let stored = std::fs::read_to_string(identity).unwrap();
    let mut lines = stored.lines();
    assert_eq!(lines.next().unwrap(), pid.to_string());
    assert_eq!(lines.next().unwrap(), start.to_string());
    #[cfg(target_os = "linux")]
    assert_eq!(
        lines.next().unwrap(),
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .unwrap()
            .trim()
    );
}
