//! Choosing a backend for a Charter, and deriving the Spec it runs.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use runeward_charter::{Charter, Limits};

use crate::LABEL_PROFILE;
use crate::backend::Backend;
use crate::config::{BackendConfig, CONTAINER_RUNTIME_ENV, parse_size};
use crate::docker::Docker;
use crate::error::{BackendError, Result};
use crate::k8s::K8s;
use crate::pathutil::expand_home;
use crate::types::{Resources, Spec};

/// Opens a [`Backend`] for one `host.type`.
///
/// Drivers are how new isolation technologies plug in: a libkrun or
/// Firecracker microVM driver, or a Landlock/seccomp process supervisor,
/// registers under its own host type and returns a backend whose
/// [`Backend::isolation_tier`] reports what it delivers.
#[async_trait]
pub trait Driver: Send + Sync {
    /// Builds (and health-checks) a backend for `charter`.
    async fn open(&self, charter: &Charter, config: &BackendConfig) -> Result<Arc<dyn Backend>>;
}

/// Maps `host.type` values to [`Driver`]s.
#[derive(Clone, Default)]
pub struct Registry {
    drivers: HashMap<String, Arc<dyn Driver>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<_> = self.drivers.keys().collect();
        names.sort();
        f.debug_struct("Registry").field("drivers", &names).finish()
    }
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// The built-in drivers: `container` (also the empty host type) for
    /// Docker/Podman and `k8s` for Kubernetes.
    pub fn with_defaults() -> Self {
        let mut r = Self::new();
        r.register("container", Arc::new(ContainerDriver));
        r.register("", Arc::new(ContainerDriver));
        r.register("k8s", Arc::new(K8sDriver));
        r
    }

    /// Registers (or replaces) the driver for `host_type`.
    pub fn register(&mut self, host_type: &str, driver: Arc<dyn Driver>) {
        self.drivers.insert(host_type.to_owned(), driver);
    }

    /// Opens the backend for the Charter's `host.type`.
    pub async fn open(
        &self,
        charter: &Charter,
        config: &BackendConfig,
    ) -> Result<Arc<dyn Backend>> {
        let host_type = charter.host.host_type.as_str();
        match self.drivers.get(host_type) {
            Some(d) => d.open(charter, config).await,
            None => Err(BackendError::Unsupported(format!(
                "no backend for host.type {host_type:?}"
            ))),
        }
    }
}

/// Docker or Podman, chosen by [`select_container_runtime`].
#[derive(Debug, Clone, Copy, Default)]
pub struct ContainerDriver;

#[async_trait]
impl Driver for ContainerDriver {
    async fn open(&self, _: &Charter, config: &BackendConfig) -> Result<Arc<dyn Backend>> {
        let runtime = select_container_runtime(config, |n| look_path(n).is_some())?;
        Ok(Arc::new(
            Docker::with_runtime(&runtime, config.clone()).await?,
        ))
    }
}

/// The Kubernetes backend.
#[derive(Debug, Clone, Copy, Default)]
pub struct K8sDriver;

#[async_trait]
impl Driver for K8sDriver {
    async fn open(&self, _: &Charter, config: &BackendConfig) -> Result<Arc<dyn Backend>> {
        Ok(Arc::new(K8s::new(config.clone()).await?))
    }
}

/// Returns the backend implementing the Charter's execution host using the
/// built-in drivers and the process environment.
pub async fn for_charter(charter: &Charter) -> Result<Arc<dyn Backend>> {
    Registry::with_defaults()
        .open(charter, &BackendConfig::from_env())
        .await
}

/// Picks `docker` or `podman`: `RUNEWARD_CONTAINER_RUNTIME` when set,
/// otherwise docker, or podman when only podman is installed.
pub fn select_container_runtime(
    config: &BackendConfig,
    installed: impl Fn(&str) -> bool,
) -> Result<String> {
    let runtime = config.container_runtime();
    match runtime.as_str() {
        "" => {
            if !installed("docker") && installed("podman") {
                Ok("podman".into())
            } else {
                Ok("docker".into())
            }
        }
        "docker" | "podman" => Ok(runtime),
        other => Err(BackendError::Unsupported(format!(
            "unsupported {CONTAINER_RUNTIME_ENV} {other:?} (want docker or podman)"
        ))),
    }
}

/// Derives a backend-agnostic Spec from a resolved Charter. `env` must
/// already hold literal values.
pub fn spec_from_charter(c: &Charter, env: BTreeMap<String, String>) -> Spec {
    Spec {
        profile: c.name.clone(),
        image: c.host.image.clone(),
        workdir: c.host.workdir.clone(),
        user: c.host.user.clone(),
        command: c.host.command.clone(),
        env,
        labels: BTreeMap::from([(LABEL_PROFILE.to_owned(), c.name.clone())]),
        files: c.files.clone(),
        seed_dir: (!c.host.copy_from.is_empty()).then(|| expand_home(&c.host.copy_from)),
        network: c.network.clone(),
        resources: resources_from_limits(&c.limits),
        runtime_class: c.host.runtime_class.clone(),
        read_only: c.host.read_only,
        seccomp: c.host.seccomp.clone(),
        apparmor: c.host.apparmor.clone(),
        ide_port: if c.ide.enabled && c.ide.port > 0 {
            c.ide.port
        } else {
            0
        },
        // Set by the control plane, which owns secrets and approvals.
        id: String::new(),
        broker: None,
        supervisor: None,
    }
}

/// Maps the Charter's CPU/memory limits onto backend resource caps.
pub fn resources_from_limits(l: &Limits) -> Resources {
    Resources {
        memory_bytes: if l.memory.is_empty() {
            0
        } else {
            parse_size(&l.memory).unwrap_or(0)
        },
        nano_cpus: if l.cpus > 0.0 {
            (l.cpus * 1e9) as i64
        } else {
            0
        },
    }
}

/// Finds an executable on `PATH`, like Go's `exec.LookPath`.
pub fn look_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| is_executable(p))
}

#[cfg(unix)]
fn is_executable(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &std::path::Path) -> bool {
    p.is_file()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use runeward_charter::{Host, HostType, Ide};

    use super::*;

    #[test]
    fn spec_propagates_command_and_fields() {
        let c = Charter {
            name: "browser".into(),
            host: Host {
                image: "example/browser:1".into(),
                command: vec!["/bin/sh".into(), "-c".into(), "sleep infinity".into()],
                runtime_class: "runsc".into(),
                read_only: true,
                ..Host::default()
            },
            limits: Limits {
                memory: "512m".into(),
                cpus: 1.5,
                ..Limits::default()
            },
            ide: Ide {
                enabled: true,
                port: 8080,
                ..Ide::default()
            },
            ..Charter::default()
        };
        let spec = spec_from_charter(&c, BTreeMap::new());
        assert_eq!(spec.command, c.host.command);
        assert_eq!(spec.labels[LABEL_PROFILE], "browser");
        assert_eq!(spec.resources.memory_bytes, 512 << 20);
        assert_eq!(spec.resources.nano_cpus, 1_500_000_000);
        assert_eq!(spec.ide_port, 8080);
        assert!(spec.seed_dir.is_none());
        assert!(spec.read_only);
    }

    #[test]
    fn select_runtime() {
        let empty = BackendConfig::default();
        let only = |name: &'static str| move |n: &str| n == name;
        assert_eq!(
            select_container_runtime(&empty, only("docker")).expect("docker"),
            "docker"
        );
        assert_eq!(
            select_container_runtime(&empty, only("podman")).expect("podman"),
            "podman"
        );
        assert_eq!(
            select_container_runtime(&empty, |_| false).expect("default"),
            "docker"
        );
        let env = BackendConfig::from_pairs([(CONTAINER_RUNTIME_ENV, " Podman ")]);
        assert_eq!(
            select_container_runtime(&env, only("docker")).expect("override"),
            "podman"
        );
        let bad = BackendConfig::from_pairs([(CONTAINER_RUNTIME_ENV, "containerd")]);
        assert!(select_container_runtime(&bad, only("docker")).is_err());
    }

    #[derive(Default)]
    struct CountingDriver(AtomicUsize);

    #[async_trait]
    impl Driver for CountingDriver {
        async fn open(&self, _: &Charter, _: &BackendConfig) -> Result<Arc<dyn Backend>> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(BackendError::msg("counted"))
        }
    }

    #[tokio::test]
    async fn registry_dispatches_on_host_type() {
        let vm = Arc::new(CountingDriver::default());
        let mut r = Registry::new();
        r.register("microvm", vm.clone());
        let mut c = Charter::default();
        c.host.host_type = HostType::parse("microvm");
        let err = r
            .open(&c, &BackendConfig::default())
            .await
            .expect_err("driver error");
        assert_eq!(err.to_string(), "counted");
        assert_eq!(vm.0.load(Ordering::SeqCst), 1);

        c.host.host_type = HostType::parse("nope");
        let err = r
            .open(&c, &BackendConfig::default())
            .await
            .expect_err("unknown");
        assert_eq!(err.to_string(), "no backend for host.type \"nope\"");
        assert!(format!("{:?}", Registry::with_defaults()).contains("k8s"));
    }
}
