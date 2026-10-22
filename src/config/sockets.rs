//! Validation shared by CLI parsing and embedded machine creation.

use super::{PublishedSocketConfig, SocketDirection};
use crate::{Error, Result};
use std::collections::HashSet;
use std::path::{Component, Path};

impl PublishedSocketConfig {
    /// Validate durable bridge configuration without opening or deleting paths.
    /// The launcher separately checks host socket existence and file type.
    pub fn validate(sockets: &[Self]) -> Result<()> {
        if sockets.len() > smolvm_protocol::ports::PUBLISH_SOCKET_MAX {
            return Err(Error::config(
                "publish-socket",
                "too many published sockets",
            ));
        }
        let mut mounted = HashSet::new();
        let mut listeners = HashSet::new();
        for socket in sockets {
            let guest = &socket.guest_path;
            if !guest.starts_with('/')
                || guest.len() > 107
                || guest[1..]
                    .split('/')
                    .any(|part| matches!(part, "" | "." | ".."))
                || guest
                    .chars()
                    .any(|c| c.is_control() || c == ';' || c == '|')
            {
                return Err(Error::config(
                    "publish-socket",
                    "invalid absolute guest socket path",
                ));
            }
            if let Some(host) = &socket.host_path {
                validate_path(Path::new(host))?;
                socket2::SockAddr::unix(host)
                    .map_err(|_| Error::config("publish-socket", "invalid host socket address"))?;
                if socket.direction == SocketDirection::Expose
                    && !listeners
                        .insert(Path::new(host).components().collect::<std::path::PathBuf>())
                {
                    return Err(Error::config(
                        "expose-socket",
                        "duplicate host listener path",
                    ));
                }
            }
            if socket.direction == SocketDirection::Mount {
                if socket.host_path.is_none() {
                    return Err(Error::config(
                        "mount-socket",
                        "host socket path is required",
                    ));
                }
                if !mounted.insert(guest) {
                    return Err(Error::config(
                        "mount-socket",
                        "guest path is mounted more than once",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Resolve and check a host endpoint without deleting any existing file.
    /// A controller may remove an owned stale listener only after proving exit.
    pub(crate) fn resolve(&self, directory: Option<&Path>) -> Result<std::path::PathBuf> {
        let path = match &self.host_path {
            Some(path) => std::path::PathBuf::from(path),
            None if self.direction == SocketDirection::Expose => {
                let directory = directory
                    .ok_or_else(|| Error::config("publish-socket", "missing VM directory"))?;
                let name = Path::new(&self.guest_path)
                    .file_name()
                    .ok_or_else(|| Error::config("publish-socket", "missing socket basename"))?;
                directory.join(name)
            }
            None => return Err(Error::config("mount-socket", "missing host socket")),
        };
        validate_path(&path)?;
        socket2::SockAddr::unix(&path)
            .map_err(|_| Error::config("publish-socket", "host socket address is too long"))?;
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if self.direction == SocketDirection::Expose {
                    return Err(Error::config(
                        "expose-socket",
                        "host listener path already exists",
                    ));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::FileTypeExt;
                    if !metadata.file_type().is_socket() {
                        return Err(Error::config(
                            "mount-socket",
                            "host endpoint is not a Unix socket",
                        ));
                    }
                }
                #[cfg(not(unix))]
                let _ = metadata;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound
                    && self.direction == SocketDirection::Expose => {}
            Err(error) => return Err(error.into()),
        }
        Ok(path)
    }
}

fn validate_path(path: &Path) -> Result<()> {
    let value = path.to_string_lossy();
    if !path.is_absolute()
        || path.file_name().is_none()
        || value
            .chars()
            .any(|c| c.is_control() || c == ';' || c == '|')
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
        || value.split('/').any(|part| part == "." || part == "..")
    {
        return Err(Error::config("publish-socket", "invalid socket path"));
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn socket(
        direction: SocketDirection,
        guest: &str,
        host: Option<&str>,
    ) -> PublishedSocketConfig {
        PublishedSocketConfig {
            direction,
            guest_path: guest.into(),
            host_path: host.map(str::to_owned),
        }
    }

    #[test]
    fn both_directions_and_optional_expose_destination_are_valid() {
        let sockets = [
            socket(
                SocketDirection::Expose,
                "/private/service.sock",
                Some("/tmp/service.sock"),
            ),
            socket(
                SocketDirection::Mount,
                "/private/host.sock",
                Some("/tmp/host.sock"),
            ),
            socket(SocketDirection::Expose, "/private/other.sock", None),
        ];
        PublishedSocketConfig::validate(&sockets).unwrap();
    }

    #[test]
    fn host_resolution_never_deletes_files_or_adopts_non_socket_sources() {
        use std::os::unix::{fs::symlink, net::UnixListener};
        let root = tempfile::Builder::new()
            .prefix("skt")
            .tempdir_in("/tmp")
            .unwrap();
        let path = root.path().join("a");
        let expose = socket(
            SocketDirection::Expose,
            "/private/a",
            Some(path.to_str().unwrap()),
        );
        assert_eq!(expose.resolve(None).unwrap(), path);
        let mount = socket(
            SocketDirection::Mount,
            "/private/b",
            Some(path.to_str().unwrap()),
        );
        assert!(mount.resolve(None).is_err());
        std::fs::write(&path, b"keep").unwrap();
        assert!(expose.resolve(None).is_err());
        assert!(mount.resolve(None).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(mount.resolve(None).unwrap(), path);
        assert!(expose.resolve(None).is_err());
        let link = root.path().join("link");
        symlink(&path, &link).unwrap();
        assert!(socket(
            SocketDirection::Mount,
            "/private/c",
            Some(link.to_str().unwrap())
        )
        .resolve(None)
        .is_err());
        drop(listener);
        assert!(path.exists());
        assert!(
            expose.resolve(None).is_err(),
            "stale socket still requires proven-owner cleanup"
        );
    }

    #[test]
    fn rejects_malformed_paths_before_persistence() {
        for guest in [
            "", "relative", "/", "/a/../b", "/a/./b", "/a//b", "/a/", "/a;b", "/a|b", "/a\0b",
            "/a\nb",
        ] {
            assert!(
                PublishedSocketConfig::validate(&[socket(SocketDirection::Expose, guest, None)])
                    .is_err(),
                "{guest:?}"
            );
        }
        let long = format!("/{}", "x".repeat(107));
        assert!(
            PublishedSocketConfig::validate(&[socket(SocketDirection::Expose, &long, None)])
                .is_err()
        );
        for host in ["", "relative", "/", "/a/../b", "/a\0b", long.as_str()] {
            assert!(
                PublishedSocketConfig::validate(&[socket(
                    SocketDirection::Mount,
                    "/valid",
                    Some(host)
                )])
                .is_err(),
                "{host:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_sources_duplicate_destinations_and_excess() {
        let mount = socket(SocketDirection::Mount, "/guest.sock", Some("/host.sock"));
        let expose = socket(SocketDirection::Expose, "/guest.sock", Some("/host.sock"));
        assert!(PublishedSocketConfig::validate(&[socket(
            SocketDirection::Mount,
            "/guest.sock",
            None
        )])
        .is_err());
        assert!(PublishedSocketConfig::validate(&[mount.clone(), mount]).is_err());
        assert!(PublishedSocketConfig::validate(&[expose.clone(), expose]).is_err());
        let entries = vec![
            socket(SocketDirection::Expose, "/guest.sock", None);
            smolvm_protocol::ports::PUBLISH_SOCKET_MAX + 1
        ];
        assert!(PublishedSocketConfig::validate(&entries).is_err());
    }
}
