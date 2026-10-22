//! Identity shared by descriptor-pinned immutable artifact consumers.
use crate::{Error, Result};
use std::{fs::File, os::unix::fs::MetadataExt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    len: u64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
impl Identity {
    pub(crate) fn of(file: &File) -> Result<Self> {
        let metadata = file
            .metadata()
            .map_err(|error| Error::agent("inspect file identity", error.to_string()))?;
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mtime: (metadata.mtime(), metadata.mtime_nsec()),
            ctime: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    pub(crate) fn same_inode(self, other: Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }
}
