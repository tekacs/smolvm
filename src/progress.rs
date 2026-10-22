//! Explicit host phase observation without clocks, payloads or global registration.
use std::{fmt, sync::Arc};

/// Host operation whose boundaries the caller may stamp with its own clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Resolve an image source into a launchable reference.
    ArchiveResolve,
    /// Read and hash archive bytes; stdin hashing also stages those bytes.
    ArchiveHash,
    /// Reuse, link or copy the archive into its content-addressed cache.
    ArchiveStage,
    /// Existing best-effort seed selection, possible build and disk attachment.
    SeedAttempt,
    /// Open the machine's configured disks and resolve the agent rootfs.
    DiskOpen,
    /// Attempt host formatting of storage and root-overlay disks.
    DiskFormat,
    /// Spawn the host boot helper, before execution admission.
    HelperSpawn,
    /// Admit the spawned helper with its retained execution identity.
    ExecutionAdmission,
    /// Wait for the host manager's agent-readiness result.
    AgentReady,
    /// Pull the image and run recorded trusted initialization when needed.
    Initialization,
    /// Run the detached image-workload launch routine; it may skip an image with no command.
    WorkloadLaunch,
}

/// A boundary or staging result, never an error message or guest payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mark {
    /// The host is about to enter the phase.
    Started,
    /// The phase returned successfully; see the phase's documented scope.
    Completed,
    /// The phase returned a failure without exposing its details.
    Failed,
    /// Existing archive staging was reused by the owner's current cache check.
    Hit,
    /// Archive staging completed by creating a hardlink.
    Linked,
    /// Archive staging completed by copying or persisting streamed bytes.
    Copied,
}

/// One metadata-only host event; no time is assigned by the engine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event {
    /// The actual host operation being observed.
    pub phase: Phase,
    /// Its boundary or staging result.
    pub mark: Mark,
}

/// Per-operation observer. Callbacks must be brief and must not re-enter the
/// machine lifecycle. Cloning shares the callback, not a global registration.
#[derive(Clone, Default)]
pub struct Observer(Option<Arc<dyn Fn(Event) + Send + Sync>>);

impl Observer {
    /// Install a trusted callback; the caller owns timestamping and retention.
    pub fn new(callback: impl Fn(Event) + Send + Sync + 'static) -> Self {
        Self(Some(Arc::new(callback)))
    }

    pub(crate) fn emit(&self, phase: Phase, mark: Mark) {
        if let Some(callback) = &self.0 {
            callback(Event { phase, mark });
        }
    }

    pub(crate) fn around<T, E>(
        &self,
        phase: Phase,
        work: impl FnOnce() -> std::result::Result<T, E>,
    ) -> std::result::Result<T, E> {
        self.emit(phase, Mark::Started);
        let result = work();
        self.emit(
            phase,
            if result.is_ok() {
                Mark::Completed
            } else {
                Mark::Failed
            },
        );
        result
    }
}

impl fmt::Debug for Observer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Observer")
            .field("enabled", &self.0.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn observer_preserves_results_and_reports_only_actual_boundaries() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let observer = Observer::new(move |event| captured.lock().unwrap().push(event));
        assert_eq!(
            observer.around(Phase::ArchiveHash, || Ok::<_, &str>(7)),
            Ok(7)
        );
        assert_eq!(
            observer
                .clone()
                .around(Phase::DiskOpen, || Err::<(), _>("private failure")),
            Err("private failure")
        );
        assert_eq!(
            *events.lock().unwrap(),
            [
                Event {
                    phase: Phase::ArchiveHash,
                    mark: Mark::Started
                },
                Event {
                    phase: Phase::ArchiveHash,
                    mark: Mark::Completed
                },
                Event {
                    phase: Phase::DiskOpen,
                    mark: Mark::Started
                },
                Event {
                    phase: Phase::DiskOpen,
                    mark: Mark::Failed
                },
            ]
        );
        assert!(!format!("{observer:?}").contains("private"));
    }
}
