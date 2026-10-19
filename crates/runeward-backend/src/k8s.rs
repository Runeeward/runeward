//! The Kubernetes backend: one Pod plus a workspace PVC per sandbox, managed
//! directly (no controller), with exec/attach over the WebSocket API.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::pin::pin;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use k8s_openapi::api::core::v1::{
    AppArmorProfile, Capabilities, ConfigMap, ConfigMapVolumeSource, Container, ContainerPort,
    EmptyDirVolumeSource, EnvVar, Namespace, PersistentVolumeClaim, PersistentVolumeClaimSpec,
    PersistentVolumeClaimVolumeSource, Pod, PodSecurityContext, PodSpec, ResourceRequirements,
    SeccompProfile, SecurityContext, Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::api::networking::v1::{
    NetworkPolicy, NetworkPolicyEgressRule, NetworkPolicyIngressRule, NetworkPolicyPort,
    NetworkPolicySpec,
};
use k8s_openapi::api::node::v1::RuntimeClass;
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, Status};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::api::{Api, AttachParams, DeleteParams, ListParams, PostParams, TerminalSize};
use kube::config::KubeConfigOptions;
use kube::{Client, Config};
use runeward_charter::File;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::backend::{Backend, Reachable};
use crate::config::{BackendConfig, DEFAULT_IMAGE};
use crate::docker::{check_seed_dir, projected_data};
use crate::egress::{policy_json, proxy_env};
use crate::error::{BackendError, Result, is_status};
use crate::isolation::{IsolationTier, classify_runtime};
use crate::seed::{self, filtered_file_stream, join_producer, seed_tar_stream};
use crate::streams::{SharedWriter, drain, drain_shared, shared};
use crate::types::{
    BoxReader, BoxWriter, ExecRequest, ExecResult, PtyStream, Sandbox, SnapshotRef, Spec, TermSize,
    default_command, default_shell,
};
use crate::validate::{validate_env_name, validate_file_mode, validate_projection_path};
use crate::{LABEL_ID, LABEL_MANAGED, LABEL_PROFILE, container_name, random_hex, volume_name};

/// The fixed name of the sandbox container within each pod.
pub const K8S_CONTAINER: &str = "sandbox";

const DEFAULT_DENY_POLICY: &str = "runeward-default-deny";
const WAIT_RUNNING_TIMEOUT: Duration = Duration::from_secs(90);

/// The Kubernetes backend.
#[derive(Clone)]
pub struct K8s {
    client: Client,
    namespace: String,
    config: BackendConfig,
}

impl std::fmt::Debug for K8s {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K8s")
            .field("namespace", &self.namespace)
            .finish_non_exhaustive()
    }
}

impl K8s {
    /// Builds the backend from the ambient kubeconfig (or in-cluster
    /// config). `RUNEWARD_KUBE_CONTEXT` pins the context and
    /// `RUNEWARD_K8S_NAMESPACE` overrides the `runeward` namespace.
    pub async fn new(config: BackendConfig) -> Result<Self> {
        let kube_config = match config.kube_context() {
            Some(context) => Config::from_kubeconfig(&KubeConfigOptions {
                context: Some(context),
                ..KubeConfigOptions::default()
            })
            .await
            .map_err(|e| BackendError::msg(format!("load kubeconfig: {e}")))?,
            None => Config::infer()
                .await
                .map_err(|e| BackendError::msg(format!("load kubeconfig: {e}")))?,
        };
        let client = Client::try_from(kube_config)
            .map_err(|e| BackendError::kube("build kubernetes client", e))?;
        Ok(Self::with_client(client, config))
    }

    /// Builds the backend around an existing client.
    pub fn with_client(client: Client, config: BackendConfig) -> Self {
        Self {
            client,
            namespace: config.k8s_namespace(),
            config,
        }
    }

    /// The namespace sandboxes are created in.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn pvcs(&self) -> Api<PersistentVolumeClaim> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn config_maps(&self) -> Api<ConfigMap> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    fn network_policies(&self) -> Api<NetworkPolicy> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    /// Ensures the managed namespace exists with Pod Security Admission
    /// labels (patched best-effort onto an existing namespace).
    pub async fn ensure_namespace(&self) -> Result<()> {
        let api: Api<Namespace> = Api::all(self.client.clone());
        match api.get(&self.namespace).await {
            Ok(existing) => {
                self.apply_psa_labels(&api, existing).await;
                Ok(())
            }
            Err(e) if is_status(&e, 404) => {
                let ns = namespace_object(&self.namespace, self.config.psa_enforce_level());
                match api.create(&PostParams::default(), &ns).await {
                    Ok(_) => Ok(()),
                    Err(e) if is_status(&e, 409) => Ok(()),
                    Err(e) => Err(BackendError::kube("create namespace", e)),
                }
            }
            Err(e) => Err(BackendError::kube("check namespace", e)),
        }
    }

    async fn apply_psa_labels(&self, api: &Api<Namespace>, mut ns: Namespace) {
        let desired = psa_labels(self.config.psa_enforce_level());
        let labels = ns.metadata.labels.get_or_insert_with(BTreeMap::new);
        if desired.iter().all(|(k, v)| labels.get(k) == Some(v)) {
            return;
        }
        labels.extend(desired);
        if let Err(e) = api
            .replace(&self.namespace, &PostParams::default(), &ns)
            .await
        {
            tracing::warn!(
                target: "runeward_backend",
                "runeward: could not apply Pod Security Admission labels to namespace {:?} (non-fatal): {e}",
                self.namespace
            );
        }
    }

    /// Installs the default-deny NetworkPolicy when
    /// `RUNEWARD_K8S_NETWORK_POLICY` is truthy (off by default: it only
    /// works under an enforcing CNI and would surprise single-tenant users).
    pub async fn ensure_network_policy(&self) -> Result<()> {
        if !self.config.k8s_network_policy() {
            return Ok(());
        }
        match self
            .network_policies()
            .create(&PostParams::default(), &default_deny_policy())
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_status(&e, 409) => Ok(()),
            Err(e) => Err(BackendError::kube("create default-deny network policy", e)),
        }
    }

    /// Allows TCP ingress to the IDE port on one sandbox pod (needed when
    /// the default-deny policy is on; a no-op otherwise).
    async fn ensure_ide_ingress(&self, id: &str, port: i64) -> Result<()> {
        if !self.config.k8s_network_policy() || !(1..=65535).contains(&port) {
            return Ok(());
        }
        match self
            .network_policies()
            .create(&PostParams::default(), &ide_ingress_policy(id, port))
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if is_status(&e, 409) => Ok(()),
            Err(e) => Err(BackendError::kube("create ide ingress network policy", e)),
        }
    }

    async fn wait_running(&self, pod_name: &str, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let pod = self
                .pods()
                .get(pod_name)
                .await
                .map_err(|e| BackendError::kube("wait for pod", e))?;
            let status = pod.status.unwrap_or_default();
            let phase = status.phase.unwrap_or_default();
            if phase == "Running"
                && status
                    .container_statuses
                    .unwrap_or_default()
                    .iter()
                    .any(|cs| cs.name == K8S_CONTAINER && cs.ready)
            {
                return Ok(());
            }
            if phase == "Failed" {
                return Err(BackendError::msg(format!(
                    "pod {pod_name} entered Failed phase"
                )));
            }
            if Instant::now() > deadline {
                return Err(BackendError::Timeout(format!(
                    "timed out waiting for pod {pod_name} to become ready (phase={phase})"
                )));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn workdir(&self, id: &str) -> Result<String> {
        let pod = self
            .pods()
            .get(&container_name(id))
            .await
            .map_err(|e| BackendError::kube("get pod", e))?;
        let wd = pod
            .spec
            .and_then(|s| s.containers.into_iter().next())
            .and_then(|c| c.working_dir)
            .unwrap_or_default();
        Ok(if wd.is_empty() {
            "/workspace".to_owned()
        } else {
            wd
        })
    }

    /// Resolves the tier of a RuntimeClass from its handler, falling back to
    /// the class name when it cannot be read.
    async fn runtime_class_tier(&self, name: &str) -> IsolationTier {
        if name.is_empty() {
            return IsolationTier::Container;
        }
        let api: Api<RuntimeClass> = Api::all(self.client.clone());
        match api.get(name).await {
            Ok(rc) => classify_runtime(&rc.handler),
            Err(_) => classify_runtime(name),
        }
    }

    /// Executes `command` in the sandbox container, wiring the given I/O.
    /// Returns the exit code (0 on success).
    async fn stream(&self, pod: &str, command: Vec<String>, io: StreamIo<'_>) -> Result<i32> {
        let StreamIo {
            stdin,
            stdout,
            stderr,
            tty,
            resize,
        } = io;
        let params = AttachParams::default()
            .container(K8S_CONTAINER)
            .stdin(stdin.is_some())
            .stdout(true)
            .stderr(!tty)
            .tty(tty);
        let mut proc = self
            .pods()
            .exec(pod, command, &params)
            .await
            .map_err(|e| BackendError::kube("exec", e))?;
        let stdin_w = proc.stdin();
        let out_r = proc.stdout();
        let err_r = proc.stderr();
        let status = proc.take_status();
        let resize_task = match (proc.terminal_size(), resize) {
            (Some(mut tx), Some(mut rx)) => Some(tokio::spawn(async move {
                while let Some(TermSize { rows, cols }) = rx.recv().await {
                    let size = TerminalSize {
                        width: cols,
                        height: rows,
                    };
                    let ready = std::future::poll_fn(|cx| tx.poll_ready(cx)).await;
                    if ready.is_err() || tx.start_send(size).is_err() {
                        break;
                    }
                }
            })),
            _ => None,
        };

        let feed = async {
            if let (Some(input), Some(w)) = (stdin, stdin_w) {
                let _ = seed::pump(input, w).await;
            }
        };
        let outputs = async {
            match (stdout, stderr) {
                (Sink::Shared(o), err) => {
                    let e = match err {
                        Sink::Shared(e) => Some(e),
                        _ => None,
                    };
                    tokio::join!(drain_shared(out_r, Some(o)), drain_shared(err_r, e));
                }
                (o, e) => {
                    let (mut o, mut e) = (o, e);
                    tokio::join!(
                        drain(out_r, None, o.writer()),
                        drain(err_r, None, e.writer())
                    );
                }
            }
        };
        // Output ends when the remote process exits; stdin is abandoned then.
        {
            let mut feed = pin!(feed);
            let mut outputs = pin!(outputs);
            let mut fed = false;
            loop {
                tokio::select! {
                    () = &mut feed, if !fed => fed = true,
                    () = &mut outputs => break,
                }
            }
        }
        if let Some(t) = resize_task {
            t.abort();
        }
        let status = match status {
            Some(s) => s.await,
            None => None,
        };
        let joined = proc.join().await;
        match status {
            Some(st) => exit_code_from_status(&st),
            None => match joined {
                Ok(()) => Ok(0),
                Err(e) => Err(BackendError::msg(format!("exec stream: {e}"))),
            },
        }
    }

    /// Runs a command with optional stdin, collecting stderr; a non-zero exit
    /// is an error.
    async fn stream_checked(
        &self,
        pod: &str,
        command: Vec<String>,
        stdin: Option<BoxReader>,
        stdout: Option<&mut (dyn AsyncWrite + Send + Unpin)>,
    ) -> std::result::Result<(), String> {
        let mut errbuf: Vec<u8> = Vec::new();
        let res = {
            let mut sink = std::io::Cursor::new(&mut errbuf);
            let io = StreamIo {
                stdin,
                stdout: match stdout {
                    Some(w) => Sink::Borrowed(w),
                    None => Sink::Discard,
                },
                stderr: Sink::Borrowed(&mut sink),
                tty: false,
                resize: None,
            };
            self.stream(pod, command, io).await
        };
        let stderr = String::from_utf8_lossy(&errbuf).into_owned();
        match res {
            Ok(0) => Ok(()),
            Ok(code) => Err(format!(
                "command terminated with non-zero exit code {code}: {stderr}"
            )),
            Err(e) => Err(format!("{e}: {stderr}")),
        }
    }

    async fn seed_workspace(&self, id: &str, workdir: &str, src_dir: &Path) -> Result<()> {
        check_seed_dir(src_dir, &self.config)?;
        let (stream, producer) = seed_tar_stream(src_dir.to_path_buf());
        let cmd = tar_extract(workdir);
        let res = self
            .stream_checked(&container_name(id), cmd, Some(Box::new(stream)), None)
            .await;
        let produced = join_producer(producer).await;
        let src = src_dir.display().to_string();
        match (res, produced) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), _) => Err(BackendError::msg(format!(
                "seed workspace from {src:?}: {e}"
            ))),
            (_, Err(e)) => Err(BackendError::msg(format!(
                "seed workspace from {src:?}: {e}"
            ))),
        }
    }

    async fn tar_out(
        &self,
        id: &str,
        workdir: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> std::result::Result<(), String> {
        let cmd = ["tar", "-C", workdir, "-cf", "-", "."]
            .map(String::from)
            .to_vec();
        self.stream_checked(&container_name(id), cmd, None, Some(&mut *w))
            .await?;
        w.flush().await.map_err(|e| e.to_string())
    }

    async fn delete_pvc(&self, name: &str) {
        let _ = self.pvcs().delete(name, &DeleteParams::default()).await;
    }

    async fn delete_config_map(&self, name: &str) {
        let _ = self
            .config_maps()
            .delete(name, &DeleteParams::default())
            .await;
    }
}

/// Where a stream's output goes.
enum Sink<'a> {
    Discard,
    Borrowed(&'a mut (dyn AsyncWrite + Send + Unpin)),
    Shared(SharedWriter),
}

impl Sink<'_> {
    fn writer(&mut self) -> Option<&mut (dyn AsyncWrite + Send + Unpin)> {
        match self {
            Sink::Borrowed(w) => Some(&mut **w),
            _ => None,
        }
    }
}

struct StreamIo<'a> {
    stdin: Option<BoxReader>,
    stdout: Sink<'a>,
    stderr: Sink<'a>,
    tty: bool,
    resize: Option<mpsc::Receiver<TermSize>>,
}

/// Maps the exec status frame to an exit code; a failure without an exit
/// code is an error.
fn exit_code_from_status(st: &Status) -> Result<i32> {
    if st.status.as_deref() == Some("Success") {
        return Ok(0);
    }
    if st.reason.as_deref() == Some("NonZeroExitCode")
        && let Some(code) = st
            .details
            .as_ref()
            .and_then(|d| d.causes.as_ref())
            .and_then(|c| {
                c.iter()
                    .find(|c| c.reason.as_deref() == Some("ExitCode"))
                    .and_then(|c| c.message.as_deref())
            })
            .and_then(|m| m.trim().parse::<i32>().ok())
    {
        return Ok(code);
    }
    Err(BackendError::msg(
        st.message
            .clone()
            .unwrap_or_else(|| "exec failed".to_owned()),
    ))
}

fn tar_extract(workdir: &str) -> Vec<String> {
    ["tar", "-C", workdir, "-xf", "-"]
        .map(String::from)
        .to_vec()
}

#[async_trait]
impl Backend for K8s {
    fn name(&self) -> &str {
        "k8s"
    }

    fn isolation_tier(&self) -> IsolationTier {
        IsolationTier::Container
    }

    async fn create(&self, spec: Spec) -> Result<Sandbox> {
        self.ensure_namespace().await?;
        self.ensure_network_policy().await?;
        let id = random_hex();
        let pod_name = container_name(&id);
        let pvc_name = volume_name(&id);
        let labels = sandbox_labels(&id, &spec.profile);

        self.pvcs()
            .create(&PostParams::default(), &workspace_pvc(&pvc_name, &labels))
            .await
            .map_err(|e| BackendError::kube("create workspace pvc", e))?;

        if spec.network.deny_by_default() {
            let policy = match policy_json(&spec.network) {
                Ok(p) => p,
                Err(e) => {
                    self.delete_pvc(&pvc_name).await;
                    return Err(e);
                }
            };
            let cm = egress_config_map(&id, &labels, policy);
            if let Err(e) = self.config_maps().create(&PostParams::default(), &cm).await {
                self.delete_pvc(&pvc_name).await;
                return Err(BackendError::kube("create egress configmap", e));
            }
        }

        let pod = sandbox_pod(&id, &spec, &labels, &self.config);
        let image = pod
            .spec
            .as_ref()
            .and_then(|s| s.containers.first())
            .and_then(|c| c.image.clone())
            .unwrap_or_default();
        if let Err(e) = self.pods().create(&PostParams::default(), &pod).await {
            self.delete_pvc(&pvc_name).await;
            self.delete_config_map(&egress_config_map_name(&id)).await;
            return Err(BackendError::kube("create pod", e));
        }

        if let Err(e) = self.wait_running(&pod_name, WAIT_RUNNING_TIMEOUT).await {
            let _ = self.kill(&id).await;
            return Err(e);
        }
        if spec.ide_port > 0
            && let Err(e) = self.ensure_ide_ingress(&id, spec.ide_port).await
        {
            let _ = self.kill(&id).await;
            return Err(e);
        }
        let workdir = workdir_or_default(&spec.workdir);
        if let Some(src) = &spec.seed_dir
            && let Err(e) = self.seed_workspace(&id, &workdir, src).await
        {
            let _ = self.kill(&id).await;
            return Err(e);
        }
        if !spec.files.is_empty()
            && let Err(e) = self.copy_files(&id, &spec.files).await
        {
            let _ = self.kill(&id).await;
            return Err(e);
        }
        let isolation = self.runtime_class_tier(&spec.runtime_class).await;

        Ok(Sandbox {
            id,
            profile: spec.profile.clone(),
            backend: self.name().to_owned(),
            image,
            status: "running".into(),
            created_at: Utc::now(),
            endpoint: String::new(),
            isolation,
        })
    }

    async fn exec(&self, id: &str, req: ExecRequest) -> Result<ExecResult> {
        let ExecRequest {
            command,
            workdir,
            env,
            timeout,
            stdout: mut out_stream,
            stderr: mut err_stream,
            stream_only,
        } = req;
        let command = wrap_command(&workdir, &env, &command);
        let start = Instant::now();
        let mut out_buf = Vec::new();
        let mut err_buf = Vec::new();
        let res = {
            let mut out =
                TeeWriter::new((!stream_only).then_some(&mut out_buf), out_stream.as_mut());
            let mut err =
                TeeWriter::new((!stream_only).then_some(&mut err_buf), err_stream.as_mut());
            let io = StreamIo {
                stdin: None,
                stdout: Sink::Borrowed(&mut out),
                stderr: Sink::Borrowed(&mut err),
                tty: false,
                resize: None,
            };
            let pod = container_name(id);
            let run = self.stream(&pod, command, io);
            match timeout.filter(|t| !t.is_zero()) {
                Some(t) => tokio::time::timeout(t, run).await.unwrap_or_else(|_| {
                    Err(BackendError::Timeout("context deadline exceeded".into()))
                }),
                None => run.await,
            }
        };
        let mut result = ExecResult {
            exit_code: 0,
            stdout: String::from_utf8_lossy(&out_buf).into_owned(),
            stderr: String::from_utf8_lossy(&err_buf).into_owned(),
            duration: start.elapsed(),
        };
        match res {
            Ok(code) => {
                result.exit_code = code;
                Ok(result)
            }
            Err(e) => Err(BackendError::msg(format!("pod exec: {e}"))),
        }
    }

    async fn attach_pty(&self, id: &str, s: PtyStream) -> Result<()> {
        let PtyStream {
            stdin,
            stdout,
            stderr,
            tty,
            command,
            resize,
        } = s;
        let command = if command.is_empty() {
            default_shell()
        } else {
            command
        };
        // With a TTY, stdout and stderr are merged by the terminal.
        let (out, err) = match (stdout, stderr, tty) {
            (Some(o), _, true) => (Sink::Shared(shared(o)), Sink::Discard),
            (Some(o), Some(e), false) => (Sink::Shared(shared(o)), Sink::Shared(shared(e))),
            (Some(o), None, false) => {
                let o = shared(o);
                (Sink::Shared(o.clone()), Sink::Shared(o))
            }
            (None, Some(e), false) => (Sink::Discard, Sink::Shared(shared(e))),
            (None, _, _) => (Sink::Discard, Sink::Discard),
        };
        let io = StreamIo {
            stdin,
            stdout: out,
            stderr: err,
            tty,
            resize,
        };
        match self.stream(&container_name(id), command, io).await? {
            0 => Ok(()),
            code => Err(BackendError::msg(format!(
                "command terminated with non-zero exit code {code}"
            ))),
        }
    }

    async fn copy_files(&self, id: &str, files: &[File]) -> Result<()> {
        for f in files {
            validate_projection_path(&f.path, self.config.confine_files())?;
            validate_file_mode(&f.mode)?;
            let Some(data) = projected_data(f)? else {
                continue;
            };
            let mode = if f.mode.is_empty() { "0444" } else { &f.mode };
            let command = copy_file_command(mode, &f.path);
            let input: BoxReader = Box::new(std::io::Cursor::new(data));
            let pod = container_name(id);
            let run = self.stream_checked(&pod, command, Some(input), None);
            let res = tokio::time::timeout(Duration::from_secs(30), run)
                .await
                .unwrap_or_else(|_| Err("context deadline exceeded: ".to_owned()));
            if let Err(e) = res {
                return Err(BackendError::msg(format!("project file {:?}: {e}", f.path)));
            }
        }
        Ok(())
    }

    async fn export_workspace(
        &self,
        id: &str,
        w: &mut (dyn AsyncWrite + Send + Unpin),
    ) -> Result<()> {
        let workdir = self.workdir(id).await?;
        self.tar_out(id, &workdir, w)
            .await
            .map_err(|e| BackendError::msg(format!("export workspace: {e}")))
    }

    async fn snapshot(&self, id: &str, name: &str) -> Result<SnapshotRef> {
        let workdir = self.workdir(id).await?;
        let snap_id = random_hex();
        let dir = crate::pathutil::snapshot_dir();
        let _ = std::fs::create_dir_all(&dir);
        let loc = dir.join(format!("{snap_id}.tar"));
        let mut out = tokio::fs::File::create(&loc)
            .await
            .map_err(|e| BackendError::io("create snapshot", e))?;
        if let Err(e) = self.tar_out(id, &workdir, &mut out).await {
            drop(out);
            let _ = std::fs::remove_file(&loc);
            return Err(BackendError::msg(format!("snapshot tar: {e}")));
        }
        drop(out);
        let sum = match seed::hash_file(&loc) {
            Ok(s) => s,
            Err(e) => {
                let _ = std::fs::remove_file(&loc);
                return Err(BackendError::io("snapshot hash", e));
            }
        };
        Ok(SnapshotRef {
            id: snap_id,
            name: name.to_owned(),
            profile: String::new(),
            backend: self.name().to_owned(),
            location: loc.to_string_lossy().into_owned(),
            sha256: sum,
            created: Utc::now(),
        })
    }

    async fn restore(&self, snapshot: &SnapshotRef) -> Result<Sandbox> {
        let spec = Spec {
            profile: snapshot.profile.clone(),
            ..Spec::default()
        };
        self.restore_with_spec(snapshot, spec).await
    }

    async fn restore_with_spec(&self, snapshot: &SnapshotRef, mut spec: Spec) -> Result<Sandbox> {
        if spec.profile.is_empty() {
            spec.profile = snapshot.profile.clone();
        }
        let sb = self.create(spec).await?;
        let res = async {
            let workdir = self.workdir(&sb.id).await?;
            seed::verify_snapshot(snapshot)?;
            let loc = PathBuf::from(&snapshot.location);
            std::fs::metadata(&loc)
                .map_err(|e| BackendError::io(format!("open {}", loc.display()), e))?;
            // Sanitize the archive host-side to prevent tar-slip.
            let (stream, producer) = filtered_file_stream(loc);
            let res = self
                .stream_checked(
                    &container_name(&sb.id),
                    tar_extract(&workdir),
                    Some(Box::new(stream)),
                    None,
                )
                .await;
            let produced = join_producer(producer).await;
            match (res, produced) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(e), _) => Err(BackendError::msg(format!("restore untar: {e}"))),
                (_, Err(e)) => Err(BackendError::msg(format!("restore untar: {e}"))),
            }
        }
        .await;
        if let Err(e) = res {
            let _ = self.kill(&sb.id).await;
            return Err(e);
        }
        Ok(sb)
    }

    async fn kill(&self, id: &str) -> Result<()> {
        let pod_err = self
            .pods()
            .delete(
                &container_name(id),
                &DeleteParams::default().grace_period(0),
            )
            .await
            .err();
        self.delete_pvc(&volume_name(id)).await;
        self.delete_config_map(&egress_config_map_name(id)).await;
        let _ = self
            .network_policies()
            .delete(&ide_network_policy_name(id), &DeleteParams::default())
            .await;
        match pod_err {
            Some(e) if !is_status(&e, 404) => Err(BackendError::kube("delete pod", e)),
            _ => Ok(()),
        }
    }

    async fn list(&self) -> Result<Vec<Sandbox>> {
        let pods = self
            .pods()
            .list(&ListParams::default().labels(&format!("{LABEL_MANAGED}=true")))
            .await
            .map_err(|e| BackendError::kube("list pods", e))?;
        Ok(pods
            .items
            .into_iter()
            .map(|p| {
                let labels = p.metadata.labels.unwrap_or_default();
                let spec = p.spec.unwrap_or_default();
                Sandbox {
                    id: labels.get(LABEL_ID).cloned().unwrap_or_default(),
                    profile: labels.get(LABEL_PROFILE).cloned().unwrap_or_default(),
                    backend: "k8s".into(),
                    image: spec
                        .containers
                        .first()
                        .and_then(|c| c.image.clone())
                        .unwrap_or_default(),
                    status: p.status.and_then(|s| s.phase).unwrap_or_default(),
                    created_at: p
                        .metadata
                        .creation_timestamp
                        .map(|t| t.0)
                        .unwrap_or_else(crate::types::go_zero_time),
                    endpoint: String::new(),
                    isolation: classify_runtime(
                        spec.runtime_class_name.as_deref().unwrap_or_default(),
                    ),
                }
            })
            .collect())
    }

    async fn exists(&self, id: &str) -> bool {
        self.pods().get(&container_name(id)).await.is_ok()
    }

    fn reachable(&self) -> Option<&dyn Reachable> {
        Some(self)
    }
}

#[async_trait]
impl Reachable for K8s {
    async fn container_ip(&self, id: &str) -> Result<String> {
        let pod = self
            .pods()
            .get(&container_name(id))
            .await
            .map_err(|e| BackendError::kube("get pod IP", e))?;
        let ip = pod
            .status
            .and_then(|s| s.pod_ip)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if ip.is_empty() {
            return Err(BackendError::msg(format!(
                "pod {} has no IP yet",
                container_name(id)
            )));
        }
        Ok(ip)
    }
}

/// An [`AsyncWrite`] that captures into a buffer and forwards to a stream.
struct TeeWriter<'a> {
    capture: Option<&'a mut Vec<u8>>,
    stream: Option<&'a mut BoxWriter>,
}

impl<'a> TeeWriter<'a> {
    fn new(capture: Option<&'a mut Vec<u8>>, stream: Option<&'a mut BoxWriter>) -> Self {
        Self { capture, stream }
    }
}

impl AsyncWrite for TeeWriter<'_> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let this = &mut *self;
        let n = match this.stream.as_deref_mut() {
            Some(s) => match std::pin::Pin::new(s).poll_write(cx, buf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(_)) => {
                    // Keep capturing when the live stream goes away.
                    this.stream = None;
                    buf.len()
                }
                Poll::Pending => return Poll::Pending,
            },
            None => buf.len(),
        };
        if let Some(c) = this.capture.as_deref_mut() {
            c.extend_from_slice(&buf[..n]);
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.stream.as_deref_mut() {
            Some(s) => std::pin::Pin::new(s).poll_flush(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.stream.as_deref_mut() {
            Some(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            None => std::task::Poll::Ready(Ok(())),
        }
    }
}

fn workdir_or_default(w: &str) -> String {
    if w.is_empty() {
        "/workspace".to_owned()
    } else {
        w.to_owned()
    }
}

/// The labels on every object belonging to one sandbox.
pub(crate) fn sandbox_labels(id: &str, profile: &str) -> BTreeMap<String, String> {
    BTreeMap::from([
        (LABEL_MANAGED.to_owned(), "true".to_owned()),
        (LABEL_PROFILE.to_owned(), profile.to_owned()),
        (LABEL_ID.to_owned(), id.to_owned()),
    ])
}

/// The 2Gi ReadWriteOnce workspace claim.
pub(crate) fn workspace_pvc(
    name: &str,
    labels: &BTreeMap<String, String>,
) -> PersistentVolumeClaim {
    PersistentVolumeClaim {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            labels: Some(labels.clone()),
            ..ObjectMeta::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".into()]),
            resources: Some(VolumeResourceRequirements {
                requests: Some(BTreeMap::from([(
                    "storage".to_owned(),
                    Quantity("2Gi".into()),
                )])),
                ..VolumeResourceRequirements::default()
            }),
            ..PersistentVolumeClaimSpec::default()
        }),
        ..PersistentVolumeClaim::default()
    }
}

/// Names the per-sandbox ConfigMap holding the egress policy.
pub fn egress_config_map_name(id: &str) -> String {
    format!("runeward-egress-{id}")
}

/// Names the per-sandbox IDE ingress NetworkPolicy.
pub fn ide_network_policy_name(id: &str) -> String {
    format!("runeward-ide-{id}")
}

pub(crate) fn egress_config_map(
    id: &str,
    labels: &BTreeMap<String, String>,
    policy_json: String,
) -> ConfigMap {
    ConfigMap {
        metadata: ObjectMeta {
            name: Some(egress_config_map_name(id)),
            labels: Some(labels.clone()),
            ..ObjectMeta::default()
        },
        data: Some(BTreeMap::from([("policy.json".to_owned(), policy_json)])),
        ..ConfigMap::default()
    }
}

/// The sandbox Pod, including the egress sidecar (and, in strict mode, the
/// iptables init container) for deny-by-default Charters.
pub(crate) fn sandbox_pod(
    id: &str,
    spec: &Spec,
    labels: &BTreeMap<String, String>,
    cfg: &BackendConfig,
) -> Pod {
    let workdir = workdir_or_default(&spec.workdir);
    let image = if spec.image.is_empty() {
        DEFAULT_IMAGE.to_owned()
    } else {
        spec.image.clone()
    };
    let command = if spec.command.is_empty() {
        default_command()
    } else {
        spec.command.clone()
    };

    let mut env: Vec<EnvVar> = spec.env.iter().map(|(k, v)| env_var(k, v)).collect();

    let mut limits = BTreeMap::new();
    if spec.resources.memory_bytes > 0 {
        limits.insert(
            "memory".to_owned(),
            Quantity(quantity_binary_si(spec.resources.memory_bytes)),
        );
    }
    if spec.resources.nano_cpus > 0 {
        limits.insert(
            "cpu".to_owned(),
            Quantity(quantity_milli_decimal_si(
                spec.resources.nano_cpus / 1_000_000,
            )),
        );
    }

    let mut init_containers = Vec::new();
    let mut extra_containers = Vec::new();
    let mut extra_volumes = Vec::new();
    if spec.network.deny_by_default() {
        let img = cfg.egress_image();
        let pull = cfg.egress_pull_policy().to_owned();
        let policy_mount = VolumeMount {
            name: "egress-policy".into(),
            mount_path: "/etc/runeward".into(),
            read_only: Some(true),
            ..VolumeMount::default()
        };
        if spec.network.strict_egress() {
            let redirect = runeward_egress::STRICT_REDIRECT_PORT.to_string();
            let proxy_uid = i64::from(runeward_egress::STRICT_PROXY_UID);
            // Installs the iptables REDIRECT rules; needs NET_ADMIN.
            init_containers.push(Container {
                name: "egress-init".into(),
                image: Some(img.clone()),
                image_pull_policy: Some(pull.clone()),
                args: Some(
                    [
                        "--setup-iptables".to_owned(),
                        "--proxy-uid".to_owned(),
                        proxy_uid.to_string(),
                        "--redirect-port".to_owned(),
                        redirect.clone(),
                    ]
                    .to_vec(),
                ),
                security_context: Some(SecurityContext {
                    run_as_user: Some(0),
                    capabilities: Some(Capabilities {
                        add: Some(vec!["NET_ADMIN".into(), "NET_RAW".into()]),
                        drop: None,
                    }),
                    ..SecurityContext::default()
                }),
                ..Container::default()
            });
            // Runs as the exempt uid so its own upstream traffic is not
            // redirected back to itself.
            extra_containers.push(Container {
                name: "egress".into(),
                image: Some(img),
                image_pull_policy: Some(pull),
                args: Some(
                    [
                        "--transparent",
                        "--redirect-port",
                        &redirect,
                        "--policy",
                        "/etc/runeward/policy.json",
                    ]
                    .map(String::from)
                    .to_vec(),
                ),
                security_context: Some(SecurityContext {
                    run_as_user: Some(proxy_uid),
                    ..SecurityContext::default()
                }),
                volume_mounts: Some(vec![policy_mount]),
                ..Container::default()
            });
        } else {
            // Loopback bind: the sandbox shares the pod netns and reaches the
            // proxy on localhost:8888; nothing off-pod can.
            extra_containers.push(Container {
                name: "egress".into(),
                image: Some(img),
                image_pull_policy: Some(pull),
                args: Some(
                    [
                        "--addr",
                        "127.0.0.1:8888",
                        "--policy",
                        "/etc/runeward/policy.json",
                    ]
                    .map(String::from)
                    .to_vec(),
                ),
                volume_mounts: Some(vec![policy_mount]),
                ..Container::default()
            });
            env.extend(
                proxy_env("http://localhost:8888")
                    .iter()
                    .map(|(k, v)| env_var(k, v)),
            );
        }
        extra_volumes.push(Volume {
            name: "egress-policy".into(),
            config_map: Some(ConfigMapVolumeSource {
                name: egress_config_map_name(id),
                ..ConfigMapVolumeSource::default()
            }),
            ..Volume::default()
        });
    }

    let mut mounts = vec![VolumeMount {
        name: "workspace".into(),
        mount_path: workdir.clone(),
        ..VolumeMount::default()
    }];
    // The sandbox container is always hardened (the egress sidecar and init
    // need NET_ADMIN/NET_RAW). RunAsNonRoot stays unset: arbitrary images
    // may legitimately need root.
    let mut sec = SecurityContext {
        allow_privilege_escalation: Some(false),
        capabilities: Some(Capabilities {
            add: None,
            drop: Some(vec!["ALL".into()]),
        }),
        ..SecurityContext::default()
    };
    if spec.read_only {
        sec.read_only_root_filesystem = Some(true);
        mounts.push(VolumeMount {
            name: "tmp".into(),
            mount_path: "/tmp".into(),
            ..VolumeMount::default()
        });
        extra_volumes.push(Volume {
            name: "tmp".into(),
            empty_dir: Some(EmptyDirVolumeSource::default()),
            ..Volume::default()
        });
    }
    if !spec.apparmor.is_empty() {
        sec.app_armor_profile = Some(app_armor_profile(&spec.apparmor));
    }

    // Default to the runtime's seccomp profile rather than Unconfined.
    let seccomp = if spec.seccomp.is_empty() {
        SeccompProfile {
            type_: "RuntimeDefault".into(),
            localhost_profile: None,
        }
    } else {
        SeccompProfile {
            type_: "Localhost".into(),
            localhost_profile: Some(spec.seccomp.clone()),
        }
    };

    let mut containers = vec![Container {
        name: K8S_CONTAINER.into(),
        image: Some(image),
        command: Some(command),
        working_dir: Some(workdir),
        env: (!env.is_empty()).then_some(env),
        resources: Some(ResourceRequirements {
            limits: (!limits.is_empty()).then_some(limits),
            ..ResourceRequirements::default()
        }),
        security_context: Some(sec),
        volume_mounts: Some(mounts),
        ports: ide_container_ports(spec.ide_port),
        ..Container::default()
    }];
    containers.extend(extra_containers);
    let mut volumes = vec![Volume {
        name: "workspace".into(),
        persistent_volume_claim: Some(PersistentVolumeClaimVolumeSource {
            claim_name: volume_name(id),
            read_only: None,
        }),
        ..Volume::default()
    }];
    volumes.extend(extra_volumes);

    Pod {
        metadata: ObjectMeta {
            name: Some(container_name(id)),
            labels: Some(labels.clone()),
            ..ObjectMeta::default()
        },
        spec: Some(PodSpec {
            restart_policy: Some("Always".into()),
            runtime_class_name: (!spec.runtime_class.is_empty())
                .then(|| spec.runtime_class.clone()),
            enable_service_links: Some(false),
            security_context: Some(PodSecurityContext {
                seccomp_profile: Some(seccomp),
                ..PodSecurityContext::default()
            }),
            init_containers: (!init_containers.is_empty()).then_some(init_containers),
            containers,
            volumes: Some(volumes),
            ..PodSpec::default()
        }),
        ..Pod::default()
    }
}

fn env_var(name: &str, value: &str) -> EnvVar {
    EnvVar {
        name: name.to_owned(),
        value: Some(value.to_owned()),
        value_from: None,
    }
}

/// Advertises the optional in-cell IDE port on the sandbox container.
pub fn ide_container_ports(port: i64) -> Option<Vec<ContainerPort>> {
    if !(1..=65535).contains(&port) {
        return None;
    }
    Some(vec![ContainerPort {
        name: Some("ide".into()),
        container_port: port as i32,
        protocol: Some("TCP".into()),
        ..ContainerPort::default()
    }])
}

/// Maps a Charter `apparmor` value: `runtime/default` (or
/// `runtime-default`) selects the runtime default, `unconfined` disables
/// it, anything else names a Localhost profile.
pub fn app_armor_profile(name: &str) -> AppArmorProfile {
    match name {
        "runtime/default" | "runtime-default" => AppArmorProfile {
            type_: "RuntimeDefault".into(),
            localhost_profile: None,
        },
        "unconfined" => AppArmorProfile {
            type_: "Unconfined".into(),
            localhost_profile: None,
        },
        other => AppArmorProfile {
            type_: "Localhost".into(),
            localhost_profile: Some(other.to_owned()),
        },
    }
}

/// Pod Security Admission labels for the managed namespace: `enforce` is
/// configurable (default `privileged`, since strict egress needs NET_ADMIN);
/// warn/audit stay at `baseline` so violations are still surfaced.
pub fn psa_labels(enforce: &str) -> BTreeMap<String, String> {
    [
        ("pod-security.kubernetes.io/enforce", enforce),
        ("pod-security.kubernetes.io/enforce-version", "latest"),
        ("pod-security.kubernetes.io/warn", "baseline"),
        ("pod-security.kubernetes.io/warn-version", "latest"),
        ("pod-security.kubernetes.io/audit", "baseline"),
        ("pod-security.kubernetes.io/audit-version", "latest"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect()
}

pub(crate) fn namespace_object(name: &str, enforce: &str) -> Namespace {
    let mut labels = BTreeMap::from([(LABEL_MANAGED.to_owned(), "true".to_owned())]);
    labels.extend(psa_labels(enforce));
    Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_owned()),
            labels: Some(labels),
            ..ObjectMeta::default()
        },
        ..Namespace::default()
    }
}

/// Denies all ingress and allows egress only to DNS (UDP+TCP 53); real
/// egress allowlisting is done by the egress proxy.
pub(crate) fn default_deny_policy() -> NetworkPolicy {
    let dns = |proto: &str| NetworkPolicyPort {
        port: Some(IntOrString::Int(53)),
        protocol: Some(proto.into()),
        end_port: None,
    };
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(DEFAULT_DENY_POLICY.into()),
            labels: Some(BTreeMap::from([(
                LABEL_MANAGED.to_owned(),
                "true".to_owned(),
            )])),
            ..ObjectMeta::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector::default(),
            policy_types: Some(vec!["Ingress".into(), "Egress".into()]),
            ingress: Some(Vec::new()),
            egress: Some(vec![NetworkPolicyEgressRule {
                ports: Some(vec![dns("UDP"), dns("TCP")]),
                to: None,
            }]),
        }),
    }
}

pub(crate) fn ide_ingress_policy(id: &str, port: i64) -> NetworkPolicy {
    NetworkPolicy {
        metadata: ObjectMeta {
            name: Some(ide_network_policy_name(id)),
            labels: Some(BTreeMap::from([
                (LABEL_MANAGED.to_owned(), "true".to_owned()),
                (LABEL_ID.to_owned(), id.to_owned()),
            ])),
            ..ObjectMeta::default()
        },
        spec: Some(NetworkPolicySpec {
            pod_selector: LabelSelector {
                match_labels: Some(BTreeMap::from([(LABEL_ID.to_owned(), id.to_owned())])),
                match_expressions: None,
            },
            policy_types: Some(vec!["Ingress".into()]),
            // An empty `from` admits the control plane (and anything else
            // in-cluster that can route to the pod IP).
            ingress: Some(vec![NetworkPolicyIngressRule {
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::Int(port as i32)),
                    protocol: Some("TCP".into()),
                    end_port: None,
                }]),
                from: None,
            }]),
            egress: None,
        }),
    }
}

/// The argv that writes stdin to `path` with `mode`, owned root.
fn copy_file_command(mode: &str, path: &str) -> Vec<String> {
    let script = format!(
        r#"set -e; mkdir -p "$(dirname "$1")"; cat > "$1"; chmod {mode} "$1"; chown root:root "$1" 2>/dev/null || true"#
    );
    vec![
        "sh".into(),
        "-c".into(),
        script,
        "sh".into(),
        path.to_owned(),
    ]
}

/// Injects a working directory and environment into an argv with a small
/// `sh` wrapper (pod exec has no cwd/env fields). Names that are not
/// identifier-safe are skipped.
pub fn wrap_command(workdir: &str, env: &BTreeMap<String, String>, cmd: &[String]) -> Vec<String> {
    if workdir.is_empty() && env.is_empty() {
        return cmd.to_vec();
    }
    let mut script = String::new();
    if !workdir.is_empty() {
        script.push_str(r#"cd "$1" && shift; "#);
    }
    for (name, val) in env {
        if validate_env_name(name).is_err() {
            continue;
        }
        script.push_str(&format!("export {name}={}; ", shell_quote(val)));
    }
    script.push_str(r#"exec "$@""#);
    let mut out = vec!["sh".to_owned(), "-c".to_owned(), script, "sh".to_owned()];
    if !workdir.is_empty() {
        out.push(workdir.to_owned());
    }
    out.extend(cmd.iter().cloned());
    out
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// A byte count in Kubernetes' canonical BinarySI form (`512Mi`, `1500`).
pub fn quantity_binary_si(bytes: i64) -> String {
    if bytes.abs() < 1024 {
        return decimal_si(bytes);
    }
    const SUFFIX: [&str; 7] = ["", "Ki", "Mi", "Gi", "Ti", "Pi", "Ei"];
    let mut n = bytes;
    let mut exp = 0;
    while exp < 6 && n != 0 && n % 1024 == 0 {
        n /= 1024;
        exp += 1;
    }
    format!("{n}{}", SUFFIX[exp])
}

/// A milli-value in canonical DecimalSI form (`1500m`, `2`, `1k`).
pub fn quantity_milli_decimal_si(milli: i64) -> String {
    if milli % 1000 == 0 {
        decimal_si(milli / 1000)
    } else {
        format!("{milli}m")
    }
}

fn decimal_si(v: i64) -> String {
    const SUFFIX: [&str; 7] = ["", "k", "M", "G", "T", "P", "E"];
    let mut n = v;
    let mut exp = 0;
    while exp < 6 && n != 0 && n % 1000 == 0 {
        n /= 1000;
        exp += 1;
    }
    format!("{n}{}", SUFFIX[exp])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ide_container_ports_bounds() {
        for port in [-1, 0, 65536] {
            assert!(ide_container_ports(port).is_none(), "{port}");
        }
        let ports = ide_container_ports(8080).expect("port");
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].container_port, 8080);
    }

    #[test]
    fn psa_labels_default_and_override() {
        let l = psa_labels("privileged");
        assert_eq!(l["pod-security.kubernetes.io/enforce"], "privileged");
        assert_eq!(l["pod-security.kubernetes.io/warn"], "baseline");
        assert_eq!(l["pod-security.kubernetes.io/audit"], "baseline");
        let ns = namespace_object("runeward", "restricted");
        let labels = ns.metadata.labels.expect("labels");
        assert_eq!(labels[LABEL_MANAGED], "true");
        assert_eq!(labels["pod-security.kubernetes.io/enforce"], "restricted");
    }

    #[test]
    fn default_deny_policy_shape() {
        let np = default_deny_policy();
        let spec = np.spec.expect("spec");
        assert!(spec.ingress.as_ref().is_some_and(Vec::is_empty));
        let egress = spec.egress.expect("egress");
        assert_eq!(egress.len(), 1);
        let ports = egress[0].ports.as_ref().expect("ports");
        assert_eq!(ports.len(), 2);
        for p in ports {
            assert_eq!(p.port, Some(IntOrString::Int(53)));
        }
    }

    #[test]
    fn exit_codes_from_status() {
        let ok = Status {
            status: Some("Success".into()),
            ..Status::default()
        };
        assert_eq!(exit_code_from_status(&ok).expect("ok"), 0);
        let st: Status = serde_json::from_value(serde_json::json!({
            "status": "Failure",
            "reason": "NonZeroExitCode",
            "message": "command terminated with non-zero exit code: exit code 3",
            "details": {"causes": [{"reason": "ExitCode", "message": "3"}]}
        }))
        .expect("status");
        assert_eq!(exit_code_from_status(&st).expect("code"), 3);
        let bad = Status {
            status: Some("Failure".into()),
            message: Some("container not found".into()),
            ..Status::default()
        };
        assert!(exit_code_from_status(&bad).is_err());
    }

    #[test]
    fn copy_file_script() {
        let cmd = copy_file_command("0600", "/root/.gitconfig");
        assert_eq!(cmd[0], "sh");
        assert_eq!(
            cmd[2],
            r#"set -e; mkdir -p "$(dirname "$1")"; cat > "$1"; chmod 0600 "$1"; chown root:root "$1" 2>/dev/null || true"#
        );
        assert_eq!(cmd[4], "/root/.gitconfig");
    }
}
