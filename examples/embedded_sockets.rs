//! Explicit local artifact probe for embedded network-off socket lifecycles.
//! It never invokes CLI lifecycle commands. Use synthetic, nonsecret workload env.

#[cfg(target_os = "linux")]
mod linux {
    use serde::Deserialize;
    use serde_json::{json, Value};
    use smolvm::{
        config::PublishedSocketConfig,
        data::image_source::{self, ArchiveInput, ImageSource, ResolvedImage},
        embedded::{
            bundle::{self, Bundle},
            EmbeddedRuntime, MachineSpec,
        },
        VmResources,
    };
    use std::{
        collections::BTreeMap,
        ffi::OsString,
        io::{BufRead, Write},
        os::unix::fs::PermissionsExt,
        path::PathBuf,
    };

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Settings {
        root: PathBuf,
        helper: PathBuf,
        libraries: PathBuf,
        rootfs: PathBuf,
        templates: PathBuf,
        cgroup: PathBuf,
        path: String,
        image: PathBuf,
        name: String,
        sockets: Vec<PublishedSocketConfig>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        command: Vec<String>,
        #[serde(default)]
        init: Vec<String>,
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let config = std::env::args_os()
            .nth(1)
            .ok_or("explicit config path required")?;
        let settings: Settings = serde_json::from_slice(&std::fs::read(config)?)?;
        for path in [
            &settings.root,
            &settings.helper,
            &settings.libraries,
            &settings.rootfs,
            &settings.templates,
            &settings.cgroup,
            &settings.image,
        ] {
            if !path.is_absolute() || path.canonicalize()? != *path {
                return Err("artifact and state paths must be canonical absolute paths".into());
            }
        }
        if std::fs::metadata(&settings.root)?.permissions().mode() & 0o077 != 0 {
            return Err("state root must be private".into());
        }
        let mut env: BTreeMap<OsString, OsString> = BTreeMap::from([
            ("PATH".into(), settings.path.clone().into()),
            ("HOME".into(), settings.root.as_os_str().to_owned()),
            ("TMPDIR".into(), settings.root.join("tmp").into_os_string()),
            (
                "SMOLVM_AGENT_ROOTFS".into(),
                settings.rootfs.as_os_str().to_owned(),
            ),
            (
                "SMOLVM_LIB_DIR".into(),
                settings.libraries.as_os_str().to_owned(),
            ),
            (
                "SMOLVM_CGROUP_ROOT".into(),
                settings.cgroup.as_os_str().to_owned(),
            ),
            ("SMOLVM_SECCOMP".into(), "enforce".into()),
            ("SMOLVM_LANDLOCK".into(), "enforce".into()),
            (
                "DOCKER_CONFIG".into(),
                settings.root.join("docker").into_os_string(),
            ),
            ("LC_ALL".into(), "C".into()),
        ]);
        for (key, child) in [
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_RUNTIME_DIR", "runtime"),
        ] {
            env.insert(key.into(), settings.root.join(child).into_os_string());
        }
        for name in ["tmp", "docker", "cache", "data", "config", "runtime"] {
            std::fs::create_dir_all(settings.root.join(name))?;
            std::fs::set_permissions(
                settings.root.join(name),
                std::fs::Permissions::from_mode(0o700),
            )?;
        }
        // Single-threaded initialization, before creating the engine or any Tokio runtime.
        // Remove stale engine/proxy overrides, but leave synthetic sentinel credentials
        // in the controller so the helper's env_clear boundary can be measured.
        for (name, _) in std::env::vars_os().collect::<Vec<_>>() {
            if name.to_string_lossy().starts_with("SMOLVM_")
                || matches!(
                    name.to_str(),
                    Some(
                        "HTTP_PROXY"
                            | "HTTPS_PROXY"
                            | "ALL_PROXY"
                            | "http_proxy"
                            | "https_proxy"
                            | "all_proxy"
                    )
                )
            {
                std::env::remove_var(name);
            }
        }
        for (key, value) in &env {
            std::env::set_var(key, value);
        }
        bundle::set_bundle(Bundle {
            boot_binary: Some(settings.helper.clone()),
            lib_dir: Some(settings.libraries.clone()),
            boot_env: Some(env),
            ..Default::default()
        })
        .map_err(|_| "bundle already selected")?;
        smolvm_pack::assets::add_template_root(settings.templates.clone());
        let mut runtime = EmbeddedRuntime::new()?;
        println!("{}", json!({"ready":true,"sqlite":rusqlite::version()}));
        std::io::stdout().flush()?;
        for line in std::io::stdin().lock().lines() {
            let action = line?;
            if action == "quit" {
                break;
            }
            let result: Result<Value, Box<dyn std::error::Error>> = (|| {
                match action.as_str() {
                    "create" => {
                        let image = match image_source::resolve(ImageSource::Archive(
                            ArchiveInput::File(settings.image.clone()),
                        ))? {
                            ResolvedImage::Local { reference, .. } => reference,
                            _ => return Err("local archive required".into()),
                        };
                        runtime.create_machine_with_workload(
                            MachineSpec {
                                name: settings.name.clone(),
                                image: Some(image),
                                command: settings.command.clone(),
                                init: settings.init.clone(),
                                published_sockets: settings.sockets.clone(),
                                persistent: true,
                                detached: true,
                                resources: VmResources {
                                    cpus: 1,
                                    memory_mib: 512,
                                    network: false,
                                    storage_gib: Some(2),
                                    overlay_gib: Some(1),
                                    ..Default::default()
                                },
                                ..Default::default()
                            },
                            settings.env.clone(),
                            None,
                            Some("1000:1000".into()),
                        )?;
                    }
                    "start" => runtime.start_machine(&settings.name)?,
                    "attach" => runtime.connect_machine(&settings.name)?,
                    "drop" => {
                        runtime = EmbeddedRuntime::new()?;
                    }
                    "stop" => runtime.stop_machine(&settings.name)?,
                    "remove" => runtime.delete_machine(&settings.name)?,
                    "inspect" => {}
                    _ => return Err("unknown operation".into()),
                }
                Ok(match runtime.machine_record(&settings.name)? {
                    Some(record) => {
                        let execution = runtime.execution(&settings.name)?
                            .map(|identity| -> Result<Value, std::io::Error> {
                                Ok(json!({"pid":identity.pid(),"start":identity.started(),"exited":identity.exited()?}))
                            }).transpose()?;
                        json!({"present":true,"pid":record.pid,"start":record.pid_start_time,"network":record.network,"detached":record.detached,"directory":smolvm::agent::vm_data_dir(&settings.name),"execution":execution})
                    }
                    None => json!({"present":false}),
                })
            })();
            let response = match result {
                Ok(value) => json!({"operation":action,"ok":true,"record":value}),
                Err(_) => json!({"operation":action,"ok":false}),
            };
            println!("{response}");
            std::io::stdout().flush()?;
        }
        Ok(())
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    if linux::run().is_err() {
        eprintln!("embedded probe failed");
        std::process::exit(1);
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("this probe requires Linux");
        std::process::exit(1);
    }
}
