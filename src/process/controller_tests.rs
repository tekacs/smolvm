//! Opt-in contained-process evidence; no VM, image or listener is required.
use super::*;
use std::process::{Child, Command, Stdio};

struct Controller {
    child: Child,
    record: PathBuf,
    delegated: PathBuf,
}
impl Drop for Controller {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Ok(Some(execution)) = Execution::load(&self.record) {
            if execution
                .pin()
                .and_then(|guard| guard.kill(Duration::from_secs(3)))
                .is_ok()
            {
                let _ = std::fs::remove_dir(self.delegated.join(format!("vm-{}", execution.pid())));
            }
        }
    }
}

#[test]
#[ignore = "requires an explicit delegated SMOLVM_TEST_CGROUP root"]
fn controller_death_before_bind_preserves_routes_and_defers_cleanup_until_exit() {
    let root = tempfile::tempdir().unwrap();
    let record = root.path().join("agent.pid");
    let delegated =
        PathBuf::from(std::env::var_os("SMOLVM_TEST_CGROUP").expect("explicit test delegation"));
    let mut controller = Controller {
        child: Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::execution::controllers::allocation_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SMOLVM_TEST_RECORD", &record)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
        record: record.clone(),
        delegated,
    };
    let mut ready = controller.child.stderr.take().unwrap();
    assert!(wait(
        &ready,
        libc::POLLIN,
        Instant::now() + Duration::from_secs(5)
    )
    .unwrap());
    let mut bytes = [0; 6];
    ready.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, b"READY\n");
    let before = Execution::load(&record).unwrap().unwrap();
    let routes = before.sockets().unwrap();
    let endpoint = Path::new(routes[0].host_path.as_ref().unwrap());
    assert!(!endpoint.exists(), "controller died before any bind");
    assert!(endpoint.parent().unwrap().exists());
    controller.child.kill().unwrap();
    assert!(!controller.child.wait().unwrap().success());
    let reopened = Execution::load(&record).unwrap().unwrap();
    assert_eq!(reopened, before);
    assert_eq!(reopened.sockets().unwrap(), routes);
    assert!(!reopened.exited().unwrap());
    assert!(reopened.reclaim().is_err());
    reopened
        .pin()
        .unwrap()
        .kill(Duration::from_secs(3))
        .unwrap();
    assert!(!endpoint.parent().unwrap().exists());
    let leaf = controller.delegated.join(format!("vm-{}", reopened.pid()));
    std::fs::remove_dir(&leaf).unwrap();
    assert!(Execution::load(&record).unwrap().unwrap().exited().unwrap());
}

#[test]
#[ignore = "private subprocess entrypoint for the contained controller-crash test"]
fn allocation_child() {
    let path = PathBuf::from(std::env::var_os("SMOLVM_TEST_RECORD").expect("explicit test record"));
    let delegated =
        PathBuf::from(std::env::var_os("SMOLVM_TEST_CGROUP").expect("explicit test delegation"));
    let mut sockets = vec![crate::config::PublishedSocketConfig {
        direction: crate::config::SocketDirection::Expose,
        guest_path: "/service.sock".into(),
        host_path: None,
    }];
    let endpoints =
        super::super::sockets::Allocation::prepare(path.parent().unwrap(), &mut sockets).unwrap();
    let mut child = Command::new("/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id() as i32;
    let result = (|| -> io::Result<()> {
        let group = super::super::cgroup::place(&delegated, pid, 1, 128, false, false)?;
        super::record(&path, pid, Some(group), endpoints)?;
        std::io::stderr().write_all(b"READY\n")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result.unwrap();
    // The parent test kills this controller while it waits, leaving the
    // contained child alive for the replacement controller to reconcile.
    child.wait().unwrap();
}
