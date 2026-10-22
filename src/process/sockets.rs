//! Linux endpoints allocated by the engine, separate from caller-owned paths.
use crate::config::{PublishedSocketConfig, SocketDirection};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io,
    os::{
        fd::AsRawFd,
        unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

/// Private directory identity and mappings retained with one contained execution.
/// The allocation is not evidence that libkrun has bound a listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Allocation {
    directory: PathBuf,
    device: u64,
    inode: u64,
    guests: Vec<String>,
}

impl Allocation {
    pub(crate) fn prepare(
        parent: &Path,
        sockets: &mut [PublishedSocketConfig],
    ) -> io::Result<Option<Self>> {
        if !sockets
            .iter()
            .any(|s| s.direction == SocketDirection::Expose && s.host_path.is_none())
        {
            return Ok(None);
        }
        PublishedSocketConfig::validate(sockets).map_err(io::Error::other)?;
        let owner = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(parent)?
            .metadata()?;
        let temporary = tempfile::Builder::new()
            .prefix("s-")
            .rand_bytes(6)
            .tempdir_in(parent)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(temporary.path())?;
        // The privileged launcher may already have assigned the VM directory to
        // its workload UID. Match that identity without changing ancestor access.
        if directory.metadata()?.uid() != owner.uid() || directory.metadata()?.gid() != owner.gid()
        {
            // SAFETY: directory is an owned, open directory; IDs come from its trusted parent.
            if unsafe { libc::fchown(directory.as_raw_fd(), owner.uid(), owner.gid()) } != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        let metadata = directory.metadata()?;
        let mut allocation = Self {
            directory: temporary.path().into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            guests: Vec::new(),
        };
        let mut resolved = sockets.to_vec();
        for socket in &mut resolved {
            if socket.direction == SocketDirection::Expose && socket.host_path.is_none() {
                let path = allocation.endpoint(allocation.guests.len());
                socket2::SockAddr::unix(&path)?;
                socket.host_path = Some(
                    path.to_str()
                        .ok_or_else(|| io::Error::other("non-UTF8 socket path"))?
                        .into(),
                );
                allocation.guests.push(socket.guest_path.clone());
            }
        }
        allocation.validate(parent)?;
        directory.sync_all()?;
        File::open(parent)?.sync_all()?;
        // From here an interrupted launcher retains the allocation. Only the
        // execution record, once published, authorizes its automatic cleanup.
        let _ = temporary.keep();
        sockets.clone_from_slice(&resolved);
        Ok(Some(allocation))
    }

    pub(crate) fn validate(&self, parent: &Path) -> io::Result<()> {
        let name = self.directory.file_name().and_then(|n| n.to_str());
        if self.directory.parent() != Some(parent)
            || name.is_none_or(|n| {
                !n.starts_with("s-")
                    || n.len() != 8
                    || !n[2..].bytes().all(|b| b.is_ascii_alphanumeric())
            })
            || self.guests.is_empty()
        {
            return Err(io::Error::other("invalid socket allocation"));
        }
        PublishedSocketConfig::validate(&self.mappings()).map_err(io::Error::other)
    }

    fn endpoint(&self, slot: usize) -> PathBuf {
        self.directory.join(slot.to_string())
    }

    fn mappings(&self) -> Vec<PublishedSocketConfig> {
        self.guests
            .iter()
            .enumerate()
            .map(|(slot, guest)| PublishedSocketConfig {
                direction: SocketDirection::Expose,
                guest_path: guest.clone(),
                host_path: Some(self.endpoint(slot).to_string_lossy().into()),
            })
            .collect()
    }

    fn open(&self) -> io::Result<File> {
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&self.directory)?;
        let metadata = directory.metadata()?;
        if metadata.dev() != self.device || metadata.ino() != self.inode {
            return Err(io::Error::other("socket directory identity changed"));
        }
        Ok(directory)
    }

    pub(crate) fn routes(&self) -> io::Result<Vec<PublishedSocketConfig>> {
        self.open()?;
        Ok(self.mappings())
    }

    pub(crate) fn retired(&self) -> io::Result<()> {
        match self.open() {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other(
                "previous socket allocation has not been reclaimed",
            )),
        }
    }

    /// Call only under the execution publication lock after whole-group exit.
    pub(crate) fn remove(&self) -> io::Result<()> {
        let directory = match self.open() {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let pinned = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let mut entries = Vec::new();
        // Validate the complete set before deleting anything. Missing listeners
        // are normal when a helper died between admission and bind.
        for entry in std::fs::read_dir(&pinned)? {
            let entry = entry?;
            let name = entry.file_name();
            let slot = name.to_str().and_then(|n| n.parse::<usize>().ok());
            if slot
                .is_none_or(|slot| slot >= self.guests.len() || name != slot.to_string().as_str())
                || !entry.file_type()?.is_socket()
            {
                return Err(io::Error::other("unexpected socket allocation contents"));
            }
            entries.push(entry.path());
        }
        for path in entries {
            std::fs::remove_file(path)?;
        }
        directory.sync_all()?;
        self.open()?;
        std::fs::remove_dir(&self.directory)?;
        File::open(self.directory.parent().unwrap())?.sync_all()
    }
}

/// Recursive machine deletion must not consume caller-owned endpoints, even
/// when the caller placed one inside the engine's data directory.
pub(crate) fn protect(parent: &Path, sockets: &[PublishedSocketConfig]) -> io::Result<()> {
    let parent = match std::fs::canonicalize(parent) {
        Ok(parent) => parent,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for socket in sockets {
        let Some(path) = socket.host_path.as_deref().map(Path::new) else {
            continue;
        };
        match std::fs::symlink_metadata(path) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        let owner = std::fs::canonicalize(
            path.parent()
                .ok_or_else(|| io::Error::other("invalid endpoint path"))?,
        )?;
        if owner.starts_with(&parent) {
            return Err(io::Error::other(
                "caller-owned endpoint remains inside machine directory",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
