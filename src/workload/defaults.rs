//! Shared image defaults for provisioning and workload construction.
use smolvm_protocol::ImageInfo;

/// Resolve effective env/workdir for image-backed execution.
///
/// Image metadata provides the baseline defaults. Explicit values from the
/// CLI/Smolfile/persisted machine config override those defaults by key, while
/// workdir uses the explicit value when present and otherwise falls back to the
/// image's `WorkingDir`. Image `User` flows through unchanged because there is
/// no CLI or persisted override for it today.
pub struct Defaults {
    /// Image environment with explicit per-key overrides.
    pub env: Vec<(String, String)>,
    /// Explicit working directory, otherwise the image default.
    pub workdir: Option<String>,
    /// Explicit account, otherwise the image default.
    pub user: Option<String>,
}

/// Resolve image defaults without consulting ambient host configuration.
pub fn resolve(
    image_info: Option<&ImageInfo>,
    env: &[(String, String)],
    explicit_workdir: Option<&str>,
    explicit_user: Option<&str>,
) -> Defaults {
    let mut resolved_env = Vec::new();

    if let Some(image_info) = image_info {
        for spec in &image_info.env {
            if let Some((key, value)) = crate::util::parse_env_spec(spec) {
                set(&mut resolved_env, key, value);
            }
        }
    }

    resolved_env = merge(&resolved_env, env);

    let workdir = explicit_workdir
        .map(str::to_string)
        .or_else(|| image_info.and_then(|info| info.workdir.clone()));

    // An explicit user wins over the image's USER, exactly as `docker run
    // --user` does; without one the image default applies, and without that
    // the agent runs the workload as root.
    let user = explicit_user
        .map(str::to_string)
        .or_else(|| image_info.and_then(|info| info.user.clone()));

    Defaults {
        env: resolved_env,
        workdir,
        user,
    }
}

/// Apply last-wins environment overrides by key.
pub fn merge(
    base_env: &[(String, String)],
    overrides: &[(String, String)],
) -> Vec<(String, String)> {
    let mut env = base_env.to_vec();
    for (key, value) in overrides {
        set(&mut env, key.clone(), value.clone());
    }
    env
}

fn set(env: &mut Vec<(String, String)>, key: String, value: String) {
    env.retain(|(existing, _)| existing != &key);
    env.push((key, value));
}
