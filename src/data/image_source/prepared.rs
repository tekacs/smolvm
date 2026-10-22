//! Reuse a verified archive for a configured consumer lifetime.
//!
//! Call ordinary resolution/staging first, then publish source and cache files
//! read-only. Opening this handle verifies their bytes once. Every reference use
//! checks pinned descriptors and paths, including ctime; it performs no hash.
//! Missing/replaced/changed files refuse reuse rather than silently refreshing.
//!
//! This is an immutable-publication contract with a trusted publisher, not a
//! filesystem freeze. A descriptor cannot revoke an existing writer or prevent
//! a same-UID process from chmod/write. Publishers must not mutate artifacts
//! while in use. Checks precede reference use; they do not protect a later path
//! lookup from an adversarial concurrent writer. No cache eviction lease is
//! claimed: eviction is detected as a refusal on the next use.
use super::{archive_cache_base, archive_reference, hash_reader, max_archive_bytes, ARCHIVE_FILE};
use crate::{
    file_identity::Identity,
    progress::{Observer, Phase},
    Error, Result,
};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

/// Source and already-staged cache archive verified for one consumer lifetime.
/// Holds descriptors to prevent inode reuse from satisfying a stale proof.
pub struct Archive {
    source: Pin,
    staged: Pin,
    reference: String,
}
impl Archive {
    /// Verify a read-only regular source and its existing content-addressed cache.
    /// No image staging, VM launch or implicit repair occurs here.
    pub fn open(source: &Path, sha256: &str) -> Result<Self> {
        Self::open_observed(source, sha256, &Observer::default())
    }
    /// Prepare with actual hash observations; later reuse emits no hash events.
    pub fn open_observed(source: &Path, sha256: &str, observer: &Observer) -> Result<Self> {
        Self::at(source, sha256, &archive_cache_base()?, observer)
    }
    fn at(source: &Path, sha256: &str, cache: &Path, observer: &Observer) -> Result<Self> {
        let reference = archive_reference(sha256)?;
        let source = Pin::open(source)?;
        if source.file.metadata()?.len() > max_archive_bytes() {
            return Err(refused());
        }
        let staged = Pin::open(&cache.join(sha256).join(ARCHIVE_FILE))?;
        source.hash(sha256, observer)?;
        if !source.identity.same_inode(staged.identity) {
            staged.hash(sha256, observer)?;
        }
        let archive = Self {
            source,
            staged,
            reference,
        };
        archive.reference()?;
        Ok(archive)
    }
    /// Validate both pinned identities and both paths, then borrow the reference.
    /// Changed or missing artifacts require explicit preparation of a new handle.
    pub fn reference(&self) -> Result<&str> {
        self.reference_observed(&Observer::default())
    }
    /// Observe only the cheap identity check, not a fabricated archive hash.
    pub fn reference_observed(&self, observer: &Observer) -> Result<&str> {
        observer.around(Phase::ArchiveResolve, || {
            self.source.verify()?;
            self.staged.verify()?;
            Ok(self.reference.as_str())
        })
    }
}
struct Pin {
    file: File,
    path: PathBuf,
    identity: Identity,
}
impl Pin {
    fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.mode() & 0o222 != 0 {
            return Err(refused());
        }
        let pin = Self {
            identity: Identity::of(&file)?,
            file,
            path: path.to_path_buf(),
        };
        pin.verify()?;
        Ok(pin)
    }
    fn verify(&self) -> Result<()> {
        let path = fs::symlink_metadata(&self.path)?;
        if !path.is_file() || path.mode() & 0o222 != 0 {
            return Err(refused());
        }
        let current = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)?;
        if Identity::of(&self.file)? != self.identity || Identity::of(&current)? != self.identity {
            return Err(refused());
        }
        Ok(())
    }
    fn hash(&self, sha256: &str, observer: &Observer) -> Result<()> {
        self.verify()?;
        let actual = observer.around(Phase::ArchiveHash, || hash_reader(&self.file))?;
        self.verify()?;
        if actual != sha256 {
            return Err(refused());
        }
        Ok(())
    }
}
fn refused() -> Error {
    Error::config(
        "prepared archive",
        "read-only artifact identity or digest changed",
    )
}

#[cfg(test)]
mod tests;
