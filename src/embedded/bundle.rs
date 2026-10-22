//! Paths an in-process embedder (the Python or Node SDK) bundles for the engine: the signed
//! `smol-vmm` boot helper, the directory holding libkrun and libkrunfw, and the guest agent
//! rootfs tarball. An embedder hands them over once with [`set_bundle`]; the engine consults
//! them before the `SMOLVM_BOOT_BINARY`, `SMOLVM_LIB_DIR` and `SMOLVM_AGENT_ROOTFS_TAR`
//! environment variables, which remain the CLI-facing overrides.
//!
//! Disk templates (`storage-template.ext4[.zst]`, `overlay-template.ext4[.zst]`) are found
//! beside the agent rootfs tarball: [`set_bundle`] registers that directory as a template root.
//!
//! They are kept out of the process environment on purpose. When an SDK exported them as
//! environment variables, every `smolvm` CLI the embedding program spawned inherited them, so a
//! branch made from a Python script booted with the SDK's helper, which arms a parent-death
//! watchdog and exits as soon as the CLI that spawned it returns. The machine died within
//! seconds, and the SDK's bundled libraries and agent rootfs shadowed the CLI's own.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// What an embedder bundles. Every field is optional: a missing one falls back to the
/// environment variable and then to the engine's own layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Bundle {
    /// A `_boot-vm`-capable helper to spawn instead of `current_exe`.
    pub boot_binary: Option<PathBuf>,
    /// Directory holding libkrun and libkrunfw.
    pub lib_dir: Option<PathBuf>,
    /// Guest agent rootfs as a tarball, extracted on first use.
    pub agent_rootfs_tar: Option<PathBuf>,
    /// Explicit helper environment. `None` inherits; `Some` clears ambient values.
    /// This is host process configuration, never persisted in the VM registry.
    pub boot_env: Option<BTreeMap<OsString, OsString>>,
}

impl Bundle {
    fn configure(&self, command: &mut Command) {
        if let Some(env) = &self.boot_env {
            command.env_clear().envs(env);
        }
    }

    fn variable(&self, name: &str) -> Option<OsString> {
        match &self.boot_env {
            Some(env) => env.get(std::ffi::OsStr::new(name)).cloned(),
            None => std::env::var_os(name),
        }
    }
}

/// Apply explicit environment policy before adding intentional per-launch values.
pub(crate) fn configure(command: &mut Command) {
    if let Some(bundle) = bundle() {
        bundle.configure(command);
    }
}

/// Read a boot setting without falling back to ambient values in explicit mode.
pub(crate) fn boot_var(name: &str) -> Option<OsString> {
    match bundle() {
        Some(bundle) => bundle.variable(name),
        None => std::env::var_os(name),
    }
}

static BUNDLE: OnceLock<Bundle> = OnceLock::new();

/// Record the embedder's bundle for this process. The first call wins; a later call with a
/// different bundle returns it as the error so the caller can report the conflict.
pub fn set_bundle(bundle: Bundle) -> Result<(), Bundle> {
    match BUNDLE.set(bundle.clone()) {
        Ok(()) => {
            // An SDK ships its disk templates beside the rootfs tarball.
            if let Some(dir) = bundle
                .agent_rootfs_tar
                .as_deref()
                .and_then(std::path::Path::parent)
            {
                smolvm_pack::assets::add_template_root(dir.to_path_buf());
            }
            Ok(())
        }
        Err(_) if BUNDLE.get() == Some(&bundle) => Ok(()),
        Err(rejected) => Err(rejected),
    }
}

/// The bundle an embedder registered, if any.
pub fn bundle() -> Option<&'static Bundle> {
    BUNDLE.get()
}

fn env_path(var: &str) -> Option<PathBuf> {
    boot_var(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

/// The boot helper to spawn: the embedder's, else `SMOLVM_BOOT_BINARY`, else none (spawn self).
pub fn boot_binary() -> Option<PathBuf> {
    bundle()
        .and_then(|b| b.boot_binary.clone())
        .or_else(|| env_path("SMOLVM_BOOT_BINARY"))
}

/// Where libkrun and libkrunfw live: the embedder's directory, else `SMOLVM_LIB_DIR`.
pub fn lib_dir() -> Option<PathBuf> {
    bundle()
        .and_then(|b| b.lib_dir.clone())
        .or_else(|| env_path(crate::data::consts::ENV_SMOLVM_LIB_DIR))
}

/// The guest agent rootfs tarball: the embedder's, else `SMOLVM_AGENT_ROOTFS_TAR`.
pub fn agent_rootfs_tar() -> Option<PathBuf> {
    bundle()
        .and_then(|b| b.agent_rootfs_tar.clone())
        .or_else(|| env_path("SMOLVM_AGENT_ROOTFS_TAR"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn explicit_boot_environment_clears_all_ambient_and_preexisting_values() {
        let explicit = Bundle {
            boot_env: Some(BTreeMap::from([("ONLY".into(), "allowed".into())])),
            ..Default::default()
        };
        let mut child = Command::new("/usr/bin/env");
        child.env("SYNTHETIC_SECRET", "must-not-cross");
        explicit.configure(&mut child);
        let output = child.output().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"ONLY=allowed\n");
        assert_eq!(explicit.variable("ONLY"), Some("allowed".into()));
        assert_eq!(explicit.variable("HOME"), None);
        assert_eq!(explicit.variable("LD_LIBRARY_PATH"), None);

        let empty = Bundle {
            boot_env: Some(BTreeMap::new()),
            ..Default::default()
        };
        let mut child = Command::new("/usr/bin/env");
        empty.configure(&mut child);
        assert!(child.output().unwrap().stdout.is_empty());
    }

    #[test]
    fn absent_environment_policy_preserves_explicit_command_values() {
        let mut child = Command::new("unused");
        child.env("SELECTED", "value");
        Bundle::default().configure(&mut child);
        assert!(child.get_envs().any(
            |(name, value)| name == "SELECTED" && value == Some(std::ffi::OsStr::new("value"))
        ));
    }

    #[test]
    fn a_second_identical_bundle_is_accepted_and_a_different_one_is_refused() {
        let b = Bundle {
            boot_binary: Some(PathBuf::from("/pkg/smol-vmm")),
            lib_dir: Some(PathBuf::from("/pkg")),
            agent_rootfs_tar: None,
            ..Default::default()
        };
        // Whatever another test registered first, registering the same thing twice must be fine
        // and registering something else must be refused rather than silently ignored.
        let first = set_bundle(b.clone());
        let again = set_bundle(b.clone());
        assert_eq!(first.is_ok(), again.is_ok());
        let other = Bundle {
            boot_binary: Some(PathBuf::from("/elsewhere")),
            ..Default::default()
        };
        assert!(set_bundle(other.clone()).is_err() || bundle() == Some(&other));
    }
}
