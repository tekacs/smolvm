//! Identity-bound Linux containment, independent of guest readiness.
use super::{cgroup_v2_process_dir, vmm_memory_budget, CGROUP_CPU_PERIOD_US, CGROUP_PIDS_MAX};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    time::Instant,
};

/// Exact device/inode identity of one Linux cgroup-v2 directory.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cgroup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Cgroup {
    pub(crate) fn capture(path: &Path) -> io::Result<Self> {
        let file = directory(path)?;
        let metadata = file.metadata()?;
        Ok(Self {
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    /// Read the kernel's current placement, never a predicted directory name.
    pub(crate) fn of(pid: i32) -> io::Result<Self> {
        let path = cgroup_v2_process_dir(pid)
            .ok_or_else(|| io::Error::other("process cgroup is unavailable"))?;
        let identity = Self::capture(&path)?;
        identity.open()?;
        Ok(identity)
    }

    pub(crate) fn scope(name: &str, pid: i32) -> io::Result<Self> {
        let identity = Self::of(pid)?;
        if identity.path.file_name()
            != Some(std::ffi::OsStr::new(&crate::systemd_scope::scope_name(
                name,
            )))
        {
            return Err(io::Error::other(
                "process was not adopted into its requested scope",
            ));
        }
        Ok(identity)
    }

    pub(crate) fn confirm(&self, pid: i32) -> io::Result<()> {
        if Self::of(pid)? != *self {
            return Err(io::Error::other("process cgroup identity changed"));
        }
        Ok(())
    }

    pub(crate) fn open(&self) -> io::Result<Group> {
        let directory = directory(&self.path)?;
        let metadata = directory.metadata()?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(io::Error::other("recorded cgroup identity changed"));
        }
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: directory is a live FD and statfs points to valid output storage.
        if unsafe { libc::fstatfs(directory.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful fstatfs initialized the output.
        if unsafe { filesystem.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err(io::Error::other(
                "recorded directory is not a cgroup v2 filesystem",
            ));
        }
        let events = member(&directory, c"cgroup.events", libc::O_RDONLY)?;
        Ok(Group { directory, events })
    }
}

/// A pinned directory and its kernel event file; later path replacement is irrelevant.
pub(crate) struct Group {
    directory: File,
    events: File,
}
impl Group {
    pub(crate) fn empty(&mut self) -> io::Result<bool> {
        // The kernel can remove a cgroup only when its subtree is empty. The
        // pinned directory (not a new pathname lookup) proves that removal.
        if self.directory.metadata()?.nlink() == 0 {
            return Ok(true);
        }
        self.events.seek(SeekFrom::Start(0))?;
        let mut value = String::new();
        (&mut self.events).take(4096).read_to_string(&mut value)?;
        populated(&value)
    }

    pub(crate) fn wait(&mut self, deadline: Instant) -> io::Result<bool> {
        loop {
            if self.empty()? {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            if !super::execution::wait(&self.events, libc::POLLPRI | libc::POLLERR, deadline)? {
                return Ok(false);
            }
        }
    }

    pub(crate) fn kill(&self) -> io::Result<()> {
        member(&self.directory, c"cgroup.kill", libc::O_WRONLY)?.write_all(b"1")
    }
}

fn populated(value: &str) -> io::Result<bool> {
    let mut rows = value
        .lines()
        .filter_map(|line| line.strip_prefix("populated "));
    let empty = match rows.next() {
        Some("0") => true,
        Some("1") => false,
        _ => {
            return Err(io::Error::other(
                "missing or invalid cgroup population evidence",
            ))
        }
    };
    if rows.next().is_some() {
        return Err(io::Error::other("duplicate cgroup population evidence"));
    }
    Ok(empty)
}

fn directory(path: &Path) -> io::Result<File> {
    if !path.is_absolute() {
        return Err(io::Error::other("cgroup path must be absolute"));
    }
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
}

fn member(directory: &File, name: &std::ffi::CStr, flags: i32) -> io::Result<File> {
    // SAFETY: directory and name are valid; CLOEXEC prevents leaking the new FD.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns a new owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Place a still-blocked child, applying and reading back limits before membership.
pub(crate) fn place(
    root: &Path,
    pid: i32,
    vcpus: u8,
    memory_mib: u32,
    cuda: bool,
    memfd: bool,
) -> io::Result<Cgroup> {
    if pid <= 0 {
        return Err(io::Error::other("invalid process identity"));
    }
    let vm = root.join(format!("vm-{pid}"));
    match std::fs::create_dir(&vm) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = std::fs::symlink_metadata(&vm)?;
            if !metadata.is_dir()
                || !populated(&std::fs::read_to_string(vm.join("cgroup.events"))?)?
            {
                return Err(io::Error::other("VM cgroup is not an empty directory"));
            }
        }
        Err(error) => return Err(error),
    }
    let pinned = directory(&vm)?;
    let identity = pinned.metadata()?;
    let quota = u64::from(vcpus.max(1)) * CGROUP_CPU_PERIOD_US;
    let budget = vmm_memory_budget(memory_mib, cuda, memfd);
    for (name, value) in [
        (c"cpu.max", format!("{quota} {CGROUP_CPU_PERIOD_US}")),
        (c"pids.max", CGROUP_PIDS_MAX.to_string()),
        (c"memory.high", budget.high_bytes.to_string()),
        (c"memory.max", budget.max_bytes.to_string()),
    ] {
        member(&pinned, name, libc::O_WRONLY)?.write_all(value.as_bytes())?;
        let mut observed = String::new();
        member(&pinned, name, libc::O_RDONLY)?.read_to_string(&mut observed)?;
        if observed.trim() != value {
            return Err(io::Error::other("VM cgroup limit readback mismatch"));
        }
    }
    member(&pinned, c"cgroup.procs", libc::O_WRONLY)?.write_all(pid.to_string().as_bytes())?;
    let mut members = String::new();
    member(&pinned, c"cgroup.procs", libc::O_RDONLY)?.read_to_string(&mut members)?;
    if !members
        .split_whitespace()
        .any(|value| value == pid.to_string())
    {
        return Err(io::Error::other("VM cgroup membership not established"));
    }
    Ok(Cgroup {
        path: vm,
        device: identity.dev(),
        inode: identity.ino(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn population_requires_one_exact_kernel_fact() {
        assert!(populated("populated 0\nfrozen 0\n").unwrap());
        assert!(!populated("populated 1\nfrozen 0\n").unwrap());
        for input in [
            "",
            "frozen 0\n",
            "populated 2\n",
            "populated 0\npopulated 1\n",
        ] {
            assert!(populated(input).is_err());
        }
    }
    #[test]
    fn regular_directory_or_replacement_never_proves_containment() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("group");
        std::fs::create_dir(&path).unwrap();
        let identity = Cgroup::capture(&path).unwrap();
        assert!(identity.open().is_err());
        std::fs::rename(&path, root.path().join("original")).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert_ne!(identity, Cgroup::capture(&path).unwrap());
        assert!(identity.open().is_err());
    }
}
