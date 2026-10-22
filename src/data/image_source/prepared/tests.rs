use super::*;
use crate::progress::Mark;
use sha2::{Digest, Sha256};
use std::{
    fs::Permissions,
    os::unix::fs::{symlink, PermissionsExt},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

struct Fixture {
    _root: tempfile::TempDir,
    source: PathBuf,
    staged: PathBuf,
    cache: PathBuf,
    digest: String,
}
impl Fixture {
    fn new(link: bool) -> Self {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("source.tar");
        let cache = root.path().join("cache");
        let bytes = b"synthetic archive payload";
        let digest = format!("{:x}", Sha256::digest(bytes));
        let staged = cache.join(&digest).join(ARCHIVE_FILE);
        fs::create_dir_all(staged.parent().unwrap()).unwrap();
        fs::write(&source, bytes).unwrap();
        fs::set_permissions(&source, Permissions::from_mode(0o400)).unwrap();
        if link {
            fs::hard_link(&source, &staged).unwrap();
        } else {
            fs::copy(&source, &staged).unwrap();
        }
        Self {
            _root: root,
            source,
            staged,
            cache,
            digest,
        }
    }
    fn open(&self, observer: &Observer) -> Result<Archive> {
        Archive::at(&self.source, &self.digest, &self.cache, observer)
    }
}
fn counter() -> (Observer, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0));
    let captured = count.clone();
    (
        Observer::new(move |e| {
            if e.phase == Phase::ArchiveHash && e.mark == Mark::Started {
                captured.fetch_add(1, Ordering::SeqCst);
            }
        }),
        count,
    )
}
fn rewrite(path: &Path) {
    let times = fs::metadata(path).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
    let bytes = vec![b'x'; times.len() as usize];
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
    File::open(path)
        .unwrap()
        .set_times(std::fs::FileTimes::new().set_modified(times.modified().unwrap()))
        .unwrap();
}
#[test]
fn repeated_reference_use_never_hashes_again() {
    for linked in [true, false] {
        let f = Fixture::new(linked);
        let (observer, count) = counter();
        let image = f.open(&observer).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), if linked { 1 } else { 2 });
        for _ in 0..64 {
            assert_eq!(
                image.reference_observed(&observer).unwrap(),
                format!("local:{}", f.digest)
            );
        }
        assert_eq!(count.load(Ordering::SeqCst), if linked { 1 } else { 2 });
    }
}
#[test]
fn same_length_corrupt_cache_is_not_trusted() {
    let f = Fixture::new(false);
    rewrite(&f.staged);
    assert!(f.open(&Observer::default()).is_err());
}
#[test]
fn source_and_cache_mutation_with_restored_mtime_refuse() {
    for staged in [false, true] {
        let f = Fixture::new(false);
        let image = f.open(&Observer::default()).unwrap();
        rewrite(if staged { &f.staged } else { &f.source });
        assert!(image.reference().is_err());
    }
}
#[test]
fn same_bytes_replacement_and_eviction_refuse_without_rehash() {
    for staged in [false, true] {
        let f = Fixture::new(false);
        let (observer, count) = counter();
        let image = f.open(&observer).unwrap();
        let path = if staged { &f.staged } else { &f.source };
        let replacement = path.with_extension("replacement");
        fs::copy(path, &replacement).unwrap();
        fs::rename(&replacement, path).unwrap();
        assert!(image.reference().is_err());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
    let f = Fixture::new(true);
    let image = f.open(&Observer::default()).unwrap();
    fs::remove_file(&f.staged).unwrap();
    assert!(image.reference().is_err());
}
#[test]
fn symlink_and_writable_publication_refuse() {
    for staged in [false, true] {
        let f = Fixture::new(false);
        let path = if staged { &f.staged } else { &f.source };
        fs::set_permissions(path, Permissions::from_mode(0o600)).unwrap();
        assert!(f.open(&Observer::default()).is_err());
        fs::set_permissions(path, Permissions::from_mode(0o400)).unwrap();
        let saved = path.with_extension("saved");
        fs::rename(path, &saved).unwrap();
        symlink(&saved, path).unwrap();
        assert!(f.open(&Observer::default()).is_err());
    }
}
#[test]
fn mutation_during_prepare_refuses_and_missing_cache_is_not_populated() {
    for staged in [false, true] {
        let f = Fixture::new(false);
        let path = if staged {
            f.staged.clone()
        } else {
            f.source.clone()
        };
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let observer = Observer::new(move |e| {
            if e.phase == Phase::ArchiveHash
                && e.mark == Mark::Completed
                && count.fetch_add(1, Ordering::SeqCst) == 0
            {
                rewrite(&path);
            }
        });
        assert!(f.open(&observer).is_err());
    }
    let f = Fixture::new(false);
    fs::remove_file(&f.staged).unwrap();
    assert!(f.open(&Observer::default()).is_err());
    assert!(!f.staged.exists());
}
#[test]
fn expected_digest_is_not_an_authority_to_skip_source_verification() {
    let f = Fixture::new(false);
    rewrite(&f.source);
    assert!(f.open(&Observer::default()).is_err());
    assert!(Archive::at(&f.source, "invalid", &f.cache, &Observer::default()).is_err());
}
