//! Finding a sandbox's backend and copying its workspace to the host.

use std::path::Path;
use std::sync::Arc;

use tokio::runtime::Handle;

use crate::backend::Backend;
use crate::config::BackendConfig;
use crate::docker::Docker;
use crate::error::{BackendError, Result};
use crate::k8s::K8s;
use crate::seed::{SyncBridge, extract_tar};

/// Returns the backend hosting sandbox `id`, probing Docker then Kubernetes.
/// A backend that cannot be constructed (no engine, no kubeconfig) is
/// skipped rather than reported.
pub async fn detect(id: &str, config: &BackendConfig) -> Result<Arc<dyn Backend>> {
    if let Ok(d) = Docker::docker(config.clone()).await
        && d.exists(id).await
    {
        return Ok(Arc::new(d));
    }
    if let Ok(k) = K8s::new(config.clone()).await
        && k.exists(id).await
    {
        return Ok(Arc::new(k));
    }
    Err(BackendError::NotFound(format!(
        "sandbox {id:?} not found (looked in docker and kubernetes)"
    )))
}

/// Copies the workspace of sandbox `id` to `dest_dir` on the host. It is a
/// point-in-time copy; later host edits never flow back.
pub async fn export(id: &str, dest_dir: &Path) -> Result<()> {
    let be = detect(id, &BackendConfig::from_env()).await?;
    export_to_dir(be.as_ref(), id, dest_dir).await
}

/// Streams `be`'s workspace export for `id` into a root-confined extraction
/// at `dest_dir`.
pub async fn export_to_dir(be: &dyn Backend, id: &str, dest_dir: &Path) -> Result<()> {
    // Absolute so the containment checks are reliable.
    let dest = std::path::absolute(dest_dir).unwrap_or_else(|_| dest_dir.to_path_buf());
    std::fs::create_dir_all(&dest).map_err(|e| {
        BackendError::io(
            format!(
                "export: create destination {:?}",
                dest.display().to_string()
            ),
            e,
        )
    })?;
    let (mut w, r) = tokio::io::duplex(64 * 1024);
    let handle = Handle::current();
    let extract_dest = dest.clone();
    let extractor =
        tokio::task::spawn_blocking(move || extract_tar(SyncBridge::new(handle, r), &extract_dest));
    let exported = be.export_workspace(id, &mut w).await;
    drop(w);
    let extracted = extractor
        .await
        .unwrap_or_else(|e| Err(BackendError::msg(format!("export: extract: {e}"))));
    match (exported, extracted) {
        (Err(e), _) => Err(e),
        (Ok(()), res) => res,
    }
}
