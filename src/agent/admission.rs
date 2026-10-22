//! Establish containment and publish identity before permitting guest disk access.
use super::boot_config::BootConfig;
use crate::{Error, Result};
use std::{
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
};

const GATE: &str = "SMOLVM_BOOT_ADMISSION";

pub(super) fn configure(command: &mut Command) {
    command
        .env(GATE, "1")
        .env("SMOLVM_BOOT_PARENT_ID", std::process::id().to_string())
        .stdin(Stdio::piped());
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

#[cfg(unix)]
pub(crate) fn parent() -> Result<i32> {
    std::env::var("SMOLVM_BOOT_PARENT_ID")
        .ok()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| Error::agent("watch boot parent", "missing launcher identity"))
}

/// The only release operation: containment, durable identity, then permission.
/// Any error kills/reaps this unreaped Child, never a looked-up numeric PID.
pub(super) fn admit<'a>(
    child: &mut Child,
    path: &Path,
    config: &BootConfig,
    name: Option<&'a str>,
    memfd: bool,
) -> Result<Option<&'a str>> {
    let pid = child.id() as i32;
    let mut scope = None;
    let result = release(child, || {
        #[cfg(target_os = "linux")]
        {
            let (group, adopted) = place(pid, config, name, memfd)?;
            scope = adopted;
            crate::process::execution::record(path, pid, group, config.endpoints.clone())?;
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (config, name, memfd, &mut scope);
            record(path, pid)?;
        }
        Ok(())
    });
    // The helper never ran guest code if admission failed. Do not stop a
    // same-name scope unless this operation actually adopted this child into it.
    #[cfg(target_os = "linux")]
    if result.is_err() && child.try_wait().ok().flatten().is_some() {
        if let Some(name) = scope {
            let _ = crate::systemd_scope::stop_scope(name);
        }
    }
    result.map(|()| scope)
}

fn release(child: &mut Child, prepare: impl FnOnce() -> Result<()>) -> Result<()> {
    let admitted = (|| {
        prepare()?;
        let mut pipe = child
            .stdin
            .take()
            .ok_or_else(|| Error::agent("admit boot", "missing admission pipe"))?;
        pipe.write_all(&[1])?;
        Ok(())
    })();
    if admitted.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    admitted
}

#[cfg(target_os = "linux")]
fn place<'a>(
    pid: i32,
    config: &BootConfig,
    name: Option<&'a str>,
    memfd: bool,
) -> Result<(Option<crate::process::cgroup::Cgroup>, Option<&'a str>)> {
    use crate::{
        embedded::bundle::boot_var,
        process::{cgroup, vmm_memory_budget},
    };
    let root = boot_var("SMOLVM_CGROUP_ROOT");
    let scoped = boot_var("SMOLVM_VM_USE_SCOPE").is_some();
    if root.is_some() && scoped {
        return Err(Error::agent(
            "place boot",
            "conflicting containment policies",
        ));
    }
    if let Some(root) = root {
        let group = cgroup::place(
            Path::new(&root),
            pid,
            config.resources.cpus,
            config.resources.memory_mib,
            config.cuda,
            memfd,
        )?;
        return Ok((Some(group), None));
    }
    if !scoped {
        return Ok((None, None));
    }
    let name = name.ok_or_else(|| Error::agent("place boot", "scope requires named machine"))?;
    let budget = vmm_memory_budget(config.resources.memory_mib, config.cuda, memfd);
    let caps = crate::systemd_scope::ScopeCaps {
        memory_max_bytes: Some(budget.max_bytes),
        memory_high_bytes: Some(budget.high_bytes),
        cpu_quota_usec_per_sec: Some(u64::from(config.resources.cpus.max(1)) * 1_000_000),
        tasks_max: Some(1024),
    };
    crate::systemd_scope::adopt_into_scope(name, pid, &caps)?;
    let group = cgroup::Cgroup::scope(name, pid)?;
    Ok((Some(group), Some(name)))
}

/// Legacy/uncontained failed-launch record. Never overwrite contained evidence.
pub(super) fn record(path: &Path, pid: i32) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        crate::process::execution::record(path, pid, None, None)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        let start = crate::process::process_start_time(pid)
            .ok_or_else(|| Error::agent("record boot", "process incarnation is unavailable"))?;
        let parent = path
            .parent()
            .ok_or_else(|| Error::agent("record boot", "missing identity directory"))?;
        let mut candidate = tempfile::NamedTempFile::new_in(parent)?;
        writeln!(candidate, "{pid}\n{start}")?;
        candidate.as_file().sync_all()?;
        candidate.persist(path).map_err(|error| error.error)?;
        #[cfg(unix)]
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "admission/tests.rs"]
mod tests;
