//! Logical sparseness checks for the differential copy test.
//!
//! Compare synchronized data extents, not compressed allocation counts. A file
//! sync can commit a ZFS intent log without settling its transaction group's
//! extent metadata, so Linux also synchronizes the filesystem before reading
//! either map. Block counts remain diagnostics, not the acceptance property.

use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) fn assert_subset(fast: &Path, reference: &Path, case: usize) {
    let fast = File::open(fast).expect("open fast copy");
    let reference = File::open(reference).expect("open reference copy");
    let size = fast.metadata().expect("fast metadata").len();
    let context = format!("seed 0x5EED case {case} size {size}");
    sync(&fast, &reference).unwrap_or_else(|error| panic!("{context}: sync copies: {error}"));
    let fast_map =
        extents(&fast).unwrap_or_else(|error| panic!("{context}: fast data extents: {error}"));
    let reference_map = extents(&reference)
        .unwrap_or_else(|error| panic!("{context}: reference data extents: {error}"));
    let fast_bytes = bytes(&fast_map);
    let reference_bytes = bytes(&reference_map);
    let fast_blocks = fast.metadata().expect("fast metadata").blocks();
    let reference_blocks = reference.metadata().expect("reference metadata").blocks();
    eprintln!(
        "{context}: fast {fast_bytes} data bytes {fast_map:?} ({fast_blocks} blocks); reference {reference_bytes} data bytes {reference_map:?} ({reference_blocks} blocks)"
    );
    assert!(
        covered(&fast_map, &reference_map),
        "{context}: fast data extents {fast_map:?} are not a subset of reference {reference_map:?}"
    );
    assert!(
        fast_bytes <= reference_bytes,
        "{context}: fast {fast_bytes} data bytes > reference {reference_bytes} data bytes"
    );
}

fn sync(fast: &File, reference: &File) -> io::Result<()> {
    fast.sync_all()?;
    reference.sync_all()?;
    #[cfg(target_os = "linux")]
    {
        // Both outputs belong to one TempDir. One filesystem sync settles both
        // maps; sleeping or syncing only the files is not a substitute.
        if fast.metadata()?.dev() != reference.metadata()?.dev() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "copy comparison requires the same filesystem",
            ));
        }
        // SAFETY: fast owns this live descriptor for the duration of the call.
        if unsafe { libc::syncfs(fast.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn extents(file: &File) -> io::Result<Vec<Range<u64>>> {
    walk(file.metadata()?.len(), |offset, whence| {
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "extent offset overflow"))?;
        // SAFETY: file owns a live descriptor; the checked offset fits off_t.
        let result = unsafe { libc::lseek(file.as_raw_fd(), offset, whence) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as u64)
        }
    })
}

fn walk(
    size: u64,
    mut seek: impl FnMut(u64, libc::c_int) -> io::Result<u64>,
) -> io::Result<Vec<Range<u64>>> {
    let mut ranges = Vec::new();
    let mut offset = 0;
    while offset < size {
        let start = match seek(offset, libc::SEEK_DATA) {
            Ok(start) => start,
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => break,
            Err(error) => return Err(error),
        };
        if start < offset || start >= size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid data offset",
            ));
        }
        let end = seek(start, libc::SEEK_HOLE)?.min(size);
        if end <= start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "non-advancing hole offset",
            ));
        }
        ranges.push(start..end);
        offset = end;
    }
    Ok(ranges)
}

fn bytes(ranges: &[Range<u64>]) -> u64 {
    ranges.iter().map(|range| range.end - range.start).sum()
}

/// Both maps are ordered, disjoint ranges. Adjacent reference ranges can
/// collectively cover one fast range, but no reference hole may be crossed.
fn covered(fast: &[Range<u64>], reference: &[Range<u64>]) -> bool {
    let mut remaining = reference.iter();
    let mut cover = remaining.next();
    for range in fast {
        let mut offset = range.start;
        while offset < range.end {
            match cover {
                Some(span) if span.end <= offset => cover = remaining.next(),
                Some(span) if span.start <= offset => offset = span.end.min(range.end),
                _ => return false,
            }
        }
    }
    true
}

#[test]
fn coverage_checks_positions_not_just_byte_totals() {
    let reference = [0..8, 12..16];
    assert!(covered(&[], &reference));
    assert!(covered(&[], &[]));
    assert!(covered(&reference, &reference));
    assert!(covered(&[1..3, 4..8, 12..15], &reference));
    let merged = 0..8;
    assert!(covered(std::slice::from_ref(&merged), &[0..4, 4..8]));
    let occupied = 0..1;
    assert!(!covered(std::slice::from_ref(&occupied), &[]));
    for extra in [8..9, 7..13, 15..17] {
        assert!(!covered(std::slice::from_ref(&extra), &reference));
    }
    // Fewer data bytes alone would wrongly accept data in a reference hole.
    let hole = 8..9;
    assert!(bytes(std::slice::from_ref(&hole)) < bytes(&reference));
    assert_eq!(bytes(&reference), 12);
}

#[test]
fn extent_walk_tracks_holes_and_eof() {
    let mut expected = [
        (0, libc::SEEK_DATA, 4),
        (4, libc::SEEK_HOLE, 8),
        (8, libc::SEEK_DATA, 12),
        (12, libc::SEEK_HOLE, 16),
    ]
    .into_iter();
    let ranges = walk(16, |offset, whence| {
        let (at, kind, result) = expected.next().expect("unexpected seek");
        assert_eq!((offset, whence), (at, kind));
        Ok(result)
    })
    .unwrap();
    assert_eq!(ranges, [4..8, 12..16]);
    assert!(expected.next().is_none());
    assert!(walk(0, |_, _| panic!("empty file must not seek"))
        .unwrap()
        .is_empty());
    assert!(walk(16, |_, _| Err(io::Error::from_raw_os_error(libc::ENXIO)))
        .unwrap()
        .is_empty());
}

#[test]
fn extent_walk_propagates_errors_instead_of_inventing_holes() {
    let unsupported = walk(16, |_, _| Err(io::Error::from_raw_os_error(libc::EINVAL)));
    assert_eq!(unsupported.unwrap_err().raw_os_error(), Some(libc::EINVAL));
    let hole_error = walk(16, |_, whence| {
        if whence == libc::SEEK_DATA {
            Ok(4)
        } else {
            Err(io::Error::from_raw_os_error(libc::ENXIO))
        }
    });
    assert_eq!(hole_error.unwrap_err().raw_os_error(), Some(libc::ENXIO));
    for replies in [vec![16], vec![4, 4], vec![0, 4, 2]] {
        let mut replies = replies.into_iter();
        let result = walk(16, |_, _| Ok(replies.next().expect("unexpected seek")));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }
}
