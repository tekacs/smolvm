//! Trusted provisioning before workload launch, shared by CLI and embedding.
#[cfg(all(test, unix))]
mod tests;
use super::defaults::{self, Defaults};
use crate::{
    agent::{AgentClient, RunConfig},
    data::storage::HostMount,
    Error, Result,
};
use smolvm_protocol::ImageInfo;

/// Image, environment and persistent filesystem selected by the trusted caller.
pub struct Context<'a> {
    /// None runs commands on the bare guest instead of in an image container.
    pub image: Option<&'a str>,
    /// Pulled image metadata, when available.
    pub image_info: Option<&'a ImageInfo>,
    /// Explicit overrides, not inherited host environment.
    pub env: &'a [(String, String)],
    /// Explicit working directory, otherwise the image default.
    pub workdir: Option<&'a str>,
    /// Canonical recorded host-source/guest-target/read-only mount tuples.
    pub record_mounts: &'a [(String, String, bool)],
    /// Persistent image overlay identity, shared with subsequent workload execution.
    pub overlay_id: &'a str,
}

/// Trusted shell command wrapping; never populated from guest/model requests.
pub fn argv(command: &str) -> Vec<String> {
    vec!["sh".into(), "-c".into(), command.to_owned()]
}

/// Root provisioning request on the same overlay and mount identities as the workload.
pub fn image(
    image: &str,
    command: &str,
    defaults: &Defaults,
    mounts: &[(String, String, bool)],
    overlay: &str,
) -> RunConfig {
    let mounts = mounts
        .iter()
        .enumerate()
        .map(|(index, (source, target, readonly))| {
            let mount = HostMount::from_storage_tuple(source.clone(), target.clone(), *readonly);
            (mount.runtime_mount_tag(index), target.clone(), *readonly)
        })
        .collect();
    RunConfig::new(image, argv(command))
        .with_env(defaults.env.clone())
        .with_workdir(defaults.workdir.clone())
        .with_user(Some("0".into()))
        .with_mounts(mounts)
        .with_persistent_overlay(Some(overlay.into()))
}

/// Execute in order and stop at the first nonzero exit. `interactive` changes only
/// image-command IO: CLI streams through a TTY; embedding captures output
/// using the agent's existing noninteractive transport. The caller owns VM cleanup.
pub fn run(
    client: &mut AgentClient,
    commands: &[String],
    context: Context<'_>,
    interactive: bool,
) -> Result<()> {
    for (index, command) in commands.iter().enumerate() {
        let (code, stdout, stderr) = if let Some(reference) = context.image {
            let defaults =
                defaults::resolve(context.image_info, context.env, context.workdir, None);
            let config = image(
                reference,
                command,
                &defaults,
                context.record_mounts,
                context.overlay_id,
            );
            if interactive {
                (
                    client.run_interactive(config.with_tty(true))?,
                    Vec::new(),
                    Vec::new(),
                )
            } else {
                client.run_non_interactive(config)?
            }
        } else {
            client.vm_exec(
                argv(command),
                context.env.to_vec(),
                context.workdir.map(str::to_owned),
                None,
                None,
            )?
        };
        if code != 0 {
            return Err(Error::agent(
                "init",
                failure(
                    index,
                    code,
                    &String::from_utf8_lossy(&stdout),
                    &String::from_utf8_lossy(&stderr),
                ),
            ));
        }
    }
    Ok(())
}

/// A trusted operator diagnostic; callers must not return it to untrusted clients.
pub fn failure(index: usize, code: i32, stdout: &str, stderr: &str) -> String {
    let suffix = match (stdout.trim(), stderr.trim()) {
        ("", "") => String::new(),
        (out, "") => format!(": {out}"),
        ("", err) => format!(": {err}"),
        (out, err) => format!(": {err}; stdout: {out}"),
    };
    format!("init[{index}] failed (exit {code}){suffix}")
}
