//! Publish a boot process's identity before permitting it to enter the VM.

use crate::{Error, Result};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
};

const GATE: &str = "SMOLVM_BOOT_ADMISSION";

pub(super) fn configure(command: &mut Command) {
    command.env(GATE, "1").stdin(Stdio::piped());
}

/// Called by the matched helper before reading boot configuration or opening disks.
pub(crate) fn wait() -> Result<()> {
    if std::env::var_os(GATE).as_deref() == Some(std::ffi::OsStr::new("1")) {
        let mut byte = [0];
        std::io::stdin()
            .read_exact(&mut byte)
            .map_err(|_| Error::agent("admit boot", "controller closed before admission"))?;
        if byte != [1] {
            return Err(Error::agent("admit boot", "invalid admission byte"));
        }
    }
    Ok(())
}

/// A lost controller before this write leaves the helper blocked; EOF refuses boot.
pub(super) fn release(child: &mut Child, path: &Path) -> Result<()> {
    let admitted = (|| {
        record(path, child.id() as i32)?;
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| Error::agent("admit boot", "missing admission pipe"))?;
        pipe.write_all(&[1])?;
        Ok(())
    })();
    if admitted.is_err() {
        // This unreaped Child is ours; no lookup or reused PID can select another process.
        let _ = child.kill();
        let _ = child.wait();
    }
    admitted
}

pub(super) fn record(path: &Path, pid: i32) -> Result<()> {
    let start = crate::process::process_start_time(pid)
        .ok_or_else(|| Error::agent("record boot", "process incarnation is unavailable"))?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::agent("record boot", "missing identity directory"))?;
    let mut candidate = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(candidate, "{pid}\n{start}")?;
    #[cfg(target_os = "linux")]
    writeln!(
        candidate,
        "{}",
        std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim()
    )?;
    candidate.as_file().sync_all()?;
    candidate.persist(path).map_err(|error| error.error)?;
    #[cfg(unix)]
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
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
        assert!(release(&mut boot, &root.path().join("missing/agent.pid")).is_err());
        assert!(!root.path().join("admitted").exists());
    }

    #[test]
    fn admitted_child_has_durable_exact_identity() {
        let root = tempfile::tempdir().unwrap();
        let mut boot = child(root.path());
        let pid = boot.id();
        let start = crate::process::process_start_time(pid as i32).unwrap();
        let identity = root.path().join("agent.pid");
        release(&mut boot, &identity).unwrap();
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
}
