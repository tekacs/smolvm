//! Retained Linux execution evidence. Missing evidence is an error, not exit.
use super::cgroup::{Cgroup, Group};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::fs::OpenOptionsExt,
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const PREFIX: &str = "containment-v1:";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Containment {
    group: Cgroup,
    exited: bool,
    #[serde(default)]
    endpoints: Option<super::sockets::Allocation>,
}

/// Exact boot/process/cgroup identity retained in the existing agent.pid record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Execution {
    path: PathBuf,
    pid: i32,
    start: u64,
    boot: String,
    containment: Containment,
}

impl Execution {
    /// None means a legacy/uncontained record or no record, NEVER proven exit.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut text = String::new();
        file.take(16384).read_to_string(&mut text)?;
        if text.len() == 16384 {
            return Err(io::Error::other("execution record exceeds limit"));
        }
        Self::decode(path, &text)
    }

    fn decode(path: &Path, text: &str) -> io::Result<Option<Self>> {
        let mut lines = text.lines();
        let pid = lines.next();
        let start = lines.next();
        let boot = lines.next();
        let Some(tail) = lines.next() else {
            return Ok(None);
        };
        let invalid = || io::Error::other("invalid execution record");
        if lines.next().is_some() {
            return Err(invalid());
        }
        let pid = pid
            .and_then(|value| value.parse::<i32>().ok())
            .filter(|pid| *pid > 0)
            .ok_or_else(invalid)?;
        let start = start
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(invalid)?;
        let boot = boot
            .filter(|value| {
                value.len() == 36 && value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
            })
            .ok_or_else(invalid)?
            .to_owned();
        let containment: Containment =
            serde_json::from_str(tail.strip_prefix(PREFIX).ok_or_else(invalid)?)?;
        if let Some(endpoints) = &containment.endpoints {
            endpoints.validate(path.parent().ok_or_else(invalid)?)?;
        }
        Ok(Some(Self {
            path: path.into(),
            pid,
            start,
            boot,
            containment,
        }))
    }

    /// Numeric PID captured before boot admission; never sufficient alone to signal.
    pub fn pid(&self) -> i32 {
        self.pid
    }
    /// Kernel process start time captured alongside the PID before admission.
    pub fn started(&self) -> u64 {
        self.start
    }

    /// Return this execution's allocated endpoints without claiming listener readiness.
    /// Reopening the controller returns the same paths; stale handles cannot retarget them.
    pub fn sockets(&self) -> io::Result<Vec<crate::config::PublishedSocketConfig>> {
        let _lock = lock(&self.path)?;
        let current = self.current()?;
        current
            .containment
            .endpoints
            .as_ref()
            .map_or_else(|| Ok(Vec::new()), |endpoints| endpoints.routes())
    }

    /// Remove only this execution's owned sockets after whole-group exit.
    /// Caller-configured endpoints and borrowed mount listeners are never selected.
    pub fn reclaim(&self) -> io::Result<()> {
        let _lock = lock(&self.path)?;
        let current = self.current()?;
        if !current.exited()? {
            return Err(io::Error::other("execution has not fully exited"));
        }
        if let Some(endpoints) = &current.containment.endpoints {
            endpoints.remove()?;
        }
        Ok(())
    }

    fn current(&self) -> io::Result<Self> {
        let current = Self::load(&self.path)?
            .ok_or_else(|| io::Error::other("execution record disappeared"))?;
        let mut expected = self.clone();
        expected.containment.exited = current.containment.exited;
        if current != expected {
            return Err(io::Error::other("execution record changed"));
        }
        Ok(current)
    }

    /// Observe exact kernel identities, or the durable completion of those identities.
    pub fn exited(&self) -> io::Result<bool> {
        self.pin()?.exited()
    }

    pub(crate) fn pin(&self) -> io::Result<Guard> {
        if self.containment.exited || self.boot != boot_id()? {
            return Ok(Guard {
                record: self.clone(),
                process: None,
                group: None,
            });
        }
        let group = self.containment.group.open()?;
        let process = process(self.pid, self.start)?;
        if process.is_some() {
            self.containment.group.confirm(self.pid)?;
        }
        Ok(Guard {
            record: self.clone(),
            process,
            group: Some(group),
        })
    }

    fn complete(&self) -> io::Result<()> {
        let _lock = lock(&self.path)?;
        let current = self.current()?;
        if current.containment.exited {
            return Ok(());
        }
        let mut finished = self.containment.clone();
        finished.exited = true;
        publish(
            &self.path,
            self.pid,
            self.start,
            &self.boot,
            Some(&finished),
        )
    }
}

/// Publish only after containment and its process membership were verified.
pub(crate) fn record(
    path: &Path,
    pid: i32,
    group: Option<Cgroup>,
    endpoints: Option<super::sockets::Allocation>,
) -> io::Result<()> {
    if let Some(endpoints) = &endpoints {
        if group.is_none() {
            return Err(io::Error::other(
                "owned sockets require contained execution",
            ));
        }
        endpoints.validate(
            path.parent()
                .ok_or_else(|| io::Error::other("missing execution directory"))?,
        )?;
    }
    let _lock = lock(path)?;
    if let Some(prior) = Execution::load(path)? {
        if !prior.exited()? {
            return Err(io::Error::other("previous execution has not exited"));
        }
        if let Some(endpoints) = &prior.containment.endpoints {
            endpoints.retired()?;
        }
    }
    let start = super::process_start_time(pid)
        .ok_or_else(|| io::Error::other("process incarnation unavailable"))?;
    let boot = boot_id()?;
    if let Some(group) = &group {
        group.confirm(pid)?;
    }
    let containment = group.map(|group| Containment {
        group,
        exited: false,
        endpoints,
    });
    publish(path, pid, start, &boot, containment.as_ref())
}

fn publish(
    path: &Path,
    pid: i32,
    start: u64,
    boot: &str,
    containment: Option<&Containment>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("missing execution directory"))?;
    let mut candidate = tempfile::NamedTempFile::new_in(parent)?;
    writeln!(candidate, "{pid}\n{start}\n{boot}")?;
    if let Some(containment) = containment {
        writeln!(candidate, "{PREFIX}{}", serde_json::to_string(containment)?)?;
    }
    candidate.as_file().sync_all()?;
    candidate.persist(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}

fn lock(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path.with_extension("pid.lock"))?;
    // SAFETY: file is live. The short lock serializes identity publication/completion.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn boot_id() -> io::Result<String> {
    Ok(std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned())
}

pub(crate) struct Guard {
    record: Execution,
    process: Option<OwnedFd>,
    group: Option<Group>,
}
impl Guard {
    pub(crate) fn process_exited(&self, deadline: Instant) -> io::Result<bool> {
        match &self.process {
            Some(fd) => wait(fd, libc::POLLIN, deadline),
            None => Ok(true),
        }
    }

    pub(crate) fn exited(&mut self) -> io::Result<bool> {
        if !self.process_exited(Instant::now())? {
            return Ok(false);
        }
        match &mut self.group {
            Some(group) => group.empty(),
            None => Ok(true),
        }
    }

    fn wait(&mut self, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        if !self.process_exited(deadline)? {
            return Ok(false);
        }
        match &mut self.group {
            Some(group) => group.wait(deadline),
            None => Ok(true),
        }
    }

    pub(crate) fn stop(mut self, grace: Duration, force: Duration) -> io::Result<()> {
        if !self.exited()? {
            self.signal(libc::SIGTERM)?;
            if !self.wait(grace)? {
                return self.kill(force);
            }
        }
        self.reap();
        self.record.complete()?;
        self.record.reclaim()
    }

    pub(crate) fn kill(mut self, timeout: Duration) -> io::Result<()> {
        if !self.exited()? {
            if let Some(group) = &self.group {
                group.kill()?;
            }
            self.signal(libc::SIGKILL)?;
            if !self.wait(timeout)? {
                return Err(io::Error::other("execution has not fully exited"));
            }
        }
        self.reap();
        self.record.complete()?;
        self.record.reclaim()
    }

    fn reap(&self) {
        if let Some(fd) = &self.process {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::uninit();
            // SAFETY: PIDFD names exactly the exited process. ECHILD is fine
            // after controller replacement or another reaper; never reap by PID.
            unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    fd.as_raw_fd() as libc::id_t,
                    info.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG,
                );
            }
        }
    }

    fn signal(&self, signal: i32) -> io::Result<()> {
        let Some(fd) = &self.process else {
            return Ok(());
        };
        // SAFETY: fd is a pinned pidfd, no numeric-PID race; no signal info is supplied.
        if unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        } < 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error);
            }
        }
        Ok(())
    }
}

fn pidfd(pid: i32) -> io::Result<Option<OwnedFd>> {
    // SAFETY: pidfd_open returns a new fd or -1; it never signals the process.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0u32) };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    // SAFETY: successful pidfd_open returns an owned descriptor.
    Ok(Some(unsafe { OwnedFd::from_raw_fd(fd as i32) }))
}

pub(super) fn event(pid: i32, timeout: Duration) -> super::ExitEvent {
    let exited = pidfd(pid).and_then(|fd| match fd {
        None => Ok(true),
        Some(fd) => wait(&fd, libc::POLLIN, Instant::now() + timeout),
    });
    match exited {
        Ok(true) => super::ExitEvent::Exited,
        Ok(false) => super::ExitEvent::TimedOut,
        Err(_) => super::ExitEvent::Unavailable,
    }
}

fn process(pid: i32, start: u64) -> io::Result<Option<OwnedFd>> {
    let Some(fd) = pidfd(pid)? else {
        return Ok(None);
    };
    match super::process_start_time(pid) {
        Some(actual) if actual == start => Ok(Some(fd)),
        Some(_) => Ok(None), // Numeric PID reused: the old incarnation is gone.
        None if wait(&fd, libc::POLLIN, Instant::now())? => Ok(None),
        None => Err(io::Error::other("process incarnation cannot be verified")),
    }
}

pub(super) fn wait(fd: &impl AsRawFd, events: i16, deadline: Instant) -> io::Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let ms = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as i32;
        let mut event = libc::pollfd {
            fd: fd.as_raw_fd(),
            events,
            revents: 0,
        };
        // SAFETY: event is one initialized pollfd pointing to an owned live descriptor.
        let result = unsafe { libc::poll(&mut event, 1, ms) };
        if result > 0 {
            if event.revents & events != 0 {
                return Ok(true);
            }
            return Err(io::Error::other("unexpected execution event"));
        }
        if result == 0 && Instant::now() >= deadline {
            return Ok(false);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
        }
    }
}

#[cfg(test)]
#[path = "controller_tests.rs"]
mod controllers;
#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
