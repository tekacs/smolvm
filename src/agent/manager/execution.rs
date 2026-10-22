//! Contained executions never use a numeric-PID signal or an agent probe as exit proof.
use super::{AgentManager, AGENT_STOP_TIMEOUT};
use crate::{
    process::{self, execution::Execution},
    Error, Result,
};
use std::time::{Duration, Instant};

impl AgentManager {
    pub(super) fn reclaim_paths(&self) -> Result<()> {
        if let Some(execution) = self.execution()? {
            execution.reclaim()?;
            let config: crate::agent::boot_config::BootConfig = serde_json::from_reader(
                std::fs::File::open(self.boot_config_path())?,
            )
            .map_err(|_| Error::agent("reclaim paths", "invalid retained boot configuration"))?;
            let directory = self
                .pid_file
                .parent()
                .ok_or_else(|| Error::agent("reclaim paths", "missing VM directory"))?;
            process::sockets::protect(directory, &config.published_sockets)?;
        }
        Ok(())
    }

    pub(super) fn stop_execution(
        &self,
        execution: Execution,
        paused: bool,
        timeout: Option<Duration>,
    ) -> Result<()> {
        // Pin both identities BEFORE asking the guest to shut down: systemd can
        // remove an empty scope immediately after the process exits.
        let mut guard = execution.pin()?;
        if !guard.exited()? && !paused && !guard.process_exited(Instant::now())? {
            let shutdown = crate::agent::AgentClient::connect_with_short_timeout(
                &self.vsock_socket,
            )
            .and_then(|mut client| match timeout {
                Some(timeout) => client.shutdown_with_stop_timeout(timeout),
                None => client.shutdown(),
            });
            if shutdown.is_err() && !guard.process_exited(Instant::now() + AGENT_STOP_TIMEOUT)? {
                return Err(Error::agent(
                    "stop agent",
                    "guest synchronization unconfirmed; execution retained",
                ));
            }
        }
        guard.stop(AGENT_STOP_TIMEOUT, process::VM_SIGKILL_TIMEOUT)?;
        Ok(())
    }

    /// None selects legacy behavior. Malformed or changed evidence refuses cleanup.
    pub(super) fn kill_execution(&self, timeout: Duration) -> Option<Result<()>> {
        match self.execution() {
            Ok(Some(execution)) => Some((|| {
                if self.pid_and_start_time() != Some((execution.pid(), Some(execution.started()))) {
                    return Err(Error::agent(
                        "kill execution",
                        "cached incarnation does not match its record",
                    ));
                }
                execution.pin()?.kill(timeout)?;
                self.cleanup_marker_files();
                self.cleanup_dead_vm_runtime();
                Ok(())
            })()),
            Ok(None) => None,
            Err(error) => Some(Err(error)),
        }
    }
}
