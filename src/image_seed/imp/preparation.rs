//! Explicit cache preparation and read-only inspection share lazy attachment's owner.
use super::*;

/// Preparation policy. Credentials are borrowed and deliberately not Debug/Serialize.
#[derive(Clone, Copy)]
pub struct SeedSpec<'a> {
    pub exe: &'a Path,
    pub image: &'a str,
    pub auth: &'a PullAuth,
    pub storage_gb: Option<u64>,
    pub digest_ttl: Option<u64>,
    pub proxy: Option<&'a str>,
    pub no_proxy: Option<&'a str>,
    pub trust_host_certs: bool,
}
impl<'a> SeedSpec<'a> {
    pub fn new(exe: &'a Path, image: &'a str, auth: &'a PullAuth) -> Self {
        Self { exe, image, auth, storage_gb:None, digest_ttl:None, proxy:None, no_proxy:None, trust_host_certs:false }
    }
}
/// Content/template/size identity. While held, the existing cache lease prevents eviction.
pub struct SeedId { pub(super) seed: EnsuredSeed }
impl SeedId {
    pub fn key(&self) -> &str { self.seed.key_dir.file_name().and_then(|name| name.to_str()).expect("seed key is ASCII") }
}
impl std::fmt::Debug for SeedId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.debug_tuple("SeedId").field(&self.key()).finish() }
}
/// Prepare the same seed lazy first-start uses, without attaching a machine disk.
/// Local archives use a temporary network-off, no-workload builder VM when absent.
pub fn prepare_image(spec: SeedSpec<'_>) -> Result<SeedId> {
    ensure_seed(spec.exe, spec.image, spec.auth, spec.digest_ttl, spec.proxy, spec.no_proxy, spec.trust_host_certs, small_seed_gb(spec.storage_gb)).map(|seed| SeedId { seed })
}
/// Inspect without creating directories, lock files, downloading, or booting a VM.
/// Mutable registry tags without a fresh cached resolution return None.
pub fn prepared(spec: SeedSpec<'_>) -> Result<Option<SeedId>> {
    let digest = if let Some(hash) = crate::data::image_source::local_archive_hash(spec.image) {
        hash.to_owned()
    } else if let Some((_, hash)) = spec.image.rsplit_once("@sha256:") {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) { return Ok(None); }
        format!("sha256:{hash}")
    } else {
        let Some(ttl) = spec.digest_ttl else { return Ok(None); };
        let Ok(bytes) = std::fs::read(digest_cache_path(spec.image, spec.auth)) else { return Ok(None); };
        let Some(digest) = fresh_cached_digest(&bytes, spec.image, ttl, crate::util::current_timestamp()) else { return Ok(None); };
        digest
    };
    let template = smolvm_pack::assets::existing_template("storage-template.ext4").and_then(|path| path.canonicalize().ok());
    let key = seed_key(spec.image, &digest, template.as_deref(), small_seed_gb(spec.storage_gb))?;
    cached(&seed_root(), &key)
}
fn cached(root: &Path, key: &str) -> Result<Option<SeedId>> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(root.join(".cache.lock")) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(Error::config("image seed lock", error.to_string())),
    };
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH) } != 0 { return Err(Error::config("image seed lock", std::io::Error::last_os_error().to_string())); }
    let cache = CacheLock { _lock: Lock(file) };
    let key_dir = root.join(key);
    Ok(seed_disk(&key_dir).map(|_| SeedId { seed: EnsuredSeed { root:root.into(), key_dir, cache, built:false } }))
}
/// The one locked cache-miss path used by explicit preparation and lazy attachment.
pub(super) fn ensure(root: PathBuf, key: &str, build: impl FnOnce(&Path) -> Result<()>) -> Result<EnsuredSeed> {
    std::fs::create_dir_all(&root).map_err(|e| Error::config("image seed", e.to_string()))?;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o711)).map_err(|e| Error::config("image seed", e.to_string()))?;
    let key_dir = root.join(key);
    let mut built = false;
    let mut cache = CacheLock::shared(&root)?;
    if seed_disk(&key_dir).is_none() {
        drop(cache);
        let _build = Lock::exclusive(&root.join(format!("{key}.lock")))?;
        if seed_disk(&key_dir).is_none() {
            build(&key_dir)?;
            if seed_disk(&key_dir).is_none() { return Err(Error::config("image seed", "builder did not publish a seed")); }
            built = true;
        }
        cache = CacheLock::shared(&root)?;
    }
    Ok(EnsuredSeed { root, key_dir, cache, built })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_preparation_and_lazy_attachment_share_one_build() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("cache");
        assert!(cached(&root, "synthetic").unwrap().is_none());
        assert!(!root.exists(), "inspection must not create cache state");
        let builds = std::cell::Cell::new(0);
        let build = |dir: &Path| {
            builds.set(builds.get()+1);
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("storage.raw"), b"synthetic image").unwrap();
            Ok(())
        };
        let seed = ensure(root.clone(), "synthetic", build).unwrap();
        assert!(seed.built); drop(seed);
        let inspected = cached(&root, "synthetic").unwrap().unwrap();
        assert_eq!(inspected.key(), "synthetic"); drop(inspected);
        let lazy = ensure(root.clone(), "synthetic", build).unwrap();
        assert!(!lazy.built); drop(lazy);
        assert_eq!(builds.get(), 1, "a prepared image must not unpack again");
        let unprepared = ensure(root, "other", build).unwrap();
        assert!(unprepared.built);
        assert_eq!(builds.get(), 2, "an unprepared image retains the lazy path");
    }
}
