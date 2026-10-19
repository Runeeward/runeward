//! Kubernetes commands: `up` (server-side apply of the embedded CRDs and
//! controller bundle), `controller` and `webhook`.

use std::collections::BTreeMap;

use anyhow::{Result, anyhow};
use kube::api::{Api, DynamicObject, Patch, PatchParams};
use kube::core::GroupVersionKind;
use kube::discovery::Scope;
use runeward_controlplane::Manager;
use runeward_k8s::controller::ControllerOptions;
use runeward_k8s::webhook::RunOptions;
use serde_json::Value;

use crate::common::{
    kube_client, kube_namespace, manager_config_dir, resolve_config_dir, shutdown_signal,
};
use crate::version::VERSION;

/// The server-side-apply owner for everything `up` applies.
pub const FIELD_MANAGER: &str = "runeward-up";

/// `runeward up [--image] [--crds-only]`.
pub async fn up(image: &str, crds_only: bool) -> Result<()> {
    let image = if image.is_empty() {
        std::env::var("RUNEWARD_IMAGE").unwrap_or_default()
    } else {
        image.to_owned()
    };
    let client = kube_client().await?;
    for m in runeward_k8s::manifests::crds() {
        apply_manifest(&client, m.content, "").await?;
    }
    if crds_only {
        println!("runeward: CRDs installed. Run the controller with `runeward controller`.");
        return Ok(());
    }
    for m in runeward_k8s::manifests::install() {
        apply_manifest(&client, m.content, &image).await?;
    }
    println!("runeward: installed. Add Charters with a ConfigMap named 'runeward-profiles', e.g.:");
    println!("  kubectl -n runeward create configmap runeward-profiles --from-file=examples/");
    Ok(())
}

/// Splits a manifest file into its YAML documents as JSON objects, dropping
/// empty documents and ones without a kind.
pub fn decode_documents(content: &str) -> Result<Vec<Value>> {
    let mut docs = Vec::new();
    for de in serde_yml::Deserializer::from_str(content) {
        let v = <Value as serde::Deserialize>::deserialize(de)
            .map_err(|e| anyhow!("decode manifest: {e}"))?;
        let has_kind = v
            .get("kind")
            .and_then(Value::as_str)
            .is_some_and(|k| !k.is_empty());
        if has_kind {
            docs.push(v);
        }
    }
    Ok(docs)
}

/// Server-side-applies every document of one manifest file.
async fn apply_manifest(client: &kube::Client, content: &str, image: &str) -> Result<()> {
    for mut doc in decode_documents(content)? {
        if !image.is_empty() {
            override_images(&mut doc, image);
        }
        apply_doc(client, doc).await?;
    }
    Ok(())
}

async fn apply_doc(client: &kube::Client, mut doc: Value) -> Result<()> {
    let str_at = |v: &Value, p: &str| {
        v.pointer(p)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let kind = str_at(&doc, "/kind");
    let name = str_at(&doc, "/metadata/name");
    let api_version = str_at(&doc, "/apiVersion");
    let (group, version) = match api_version.split_once('/') {
        Some((g, v)) => (g.to_owned(), v.to_owned()),
        None => (String::new(), api_version.clone()),
    };
    let gvk = GroupVersionKind::gvk(&group, &version, &kind);
    // Fresh discovery per document, so CRDs applied earlier are visible to
    // the custom resources that follow.
    let (resource, caps) = kube::discovery::pinned_kind(client, &gvk)
        .await
        .map_err(|e| anyhow!("map {api_version}, Kind={kind}: {e}"))?;
    let api: Api<DynamicObject> = if caps.scope == Scope::Namespaced {
        let mut ns = str_at(&doc, "/metadata/namespace");
        if ns.is_empty() {
            ns = kube_namespace();
            if let Some(meta) = doc.get_mut("metadata").and_then(Value::as_object_mut) {
                meta.insert("namespace".into(), Value::String(ns.clone()));
            }
        }
        Api::namespaced_with(client.clone(), &ns, &resource)
    } else {
        Api::all_with(client.clone(), &resource)
    };
    let params = PatchParams::apply(FIELD_MANAGER).force();
    match api.patch(&name, &params, &Patch::Apply(&doc)).await {
        Ok(_) => {}
        Err(kube::Error::Api(e)) if e.reason == "AlreadyExists" => {}
        Err(e) => return Err(anyhow!("apply {kind} {name}: {e}")),
    }
    println!("  applied {}/{name}", kind.to_lowercase());
    Ok(())
}

/// Sets every container and initContainer image of a workload to `image`.
pub fn override_images(doc: &mut Value, image: &str) {
    for key in ["containers", "initContainers"] {
        let path = format!("/spec/template/spec/{key}");
        if let Some(list) = doc.pointer_mut(&path).and_then(Value::as_array_mut) {
            for c in list.iter_mut().filter_map(Value::as_object_mut) {
                c.insert("image".into(), Value::String(image.to_owned()));
            }
        }
    }
}

/// `runeward controller [--workers] [--all-namespaces]`.
pub async fn controller(workers: usize, all_namespaces: bool, config_dir: &str) -> Result<()> {
    let client = kube_client().await?;
    let mgr = Manager::open(manager_config_dir(&resolve_config_dir(config_dir))).await?;
    runeward_obs::init_logging();
    let opts = ControllerOptions {
        workers,
        all_namespaces,
        namespace: kube_namespace(),
    };
    tracing::info!(
        service = "controller",
        "{}",
        runeward_obs::telemetry::notice()
    );
    let _ = runeward_obs::telemetry::report(VERSION, "controller_start", BTreeMap::new());
    let result = runeward_k8s::controller::run(client, mgr.clone(), opts, shutdown_signal()).await;
    let _ = mgr.close().await;
    Ok(result?)
}

/// `runeward webhook [--port] [--service] [--cert-secret]`.
pub async fn webhook(port: u16, service: &str, cert_secret: &str) -> Result<()> {
    let client = kube_client().await?;
    runeward_obs::init_logging();
    let opts = RunOptions {
        port,
        service: service.to_owned(),
        cert_secret: cert_secret.to_owned(),
        namespace: kube_namespace(),
    };
    runeward_k8s::webhook::run(client, opts, shutdown_signal()).await?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn every_embedded_document_decodes() {
        let mut kinds = Vec::new();
        for m in runeward_k8s::manifests::crds()
            .iter()
            .chain(runeward_k8s::manifests::install())
        {
            for d in decode_documents(m.content).unwrap() {
                kinds.push(d["kind"].as_str().unwrap().to_owned());
            }
        }
        assert_eq!(
            kinds
                .iter()
                .filter(|k| *k == "CustomResourceDefinition")
                .count(),
            5
        );
        // Multi-document files apply every document, not just the first.
        for k in [
            "Namespace",
            "ServiceAccount",
            "Role",
            "RoleBinding",
            "ClusterRole",
            "ClusterRoleBinding",
            "Deployment",
        ] {
            assert!(kinds.iter().any(|x| x == k), "missing {k}: {kinds:?}");
        }
    }

    #[test]
    fn images_are_overridden_in_pod_templates() {
        let mut d: Value = serde_json::json!({
            "kind": "Deployment",
            "spec": {"template": {"spec": {
                "containers": [{"name": "a", "image": "x"}],
                "initContainers": [{"name": "b", "image": "y"}]
            }}}
        });
        override_images(&mut d, "img:1");
        assert_eq!(
            d["spec"]["template"]["spec"]["containers"][0]["image"],
            "img:1"
        );
        assert_eq!(
            d["spec"]["template"]["spec"]["initContainers"][0]["image"],
            "img:1"
        );
        let mut ns = serde_json::json!({"kind": "Namespace"});
        override_images(&mut ns, "img:1");
        assert_eq!(ns, serde_json::json!({"kind": "Namespace"}));
    }
}
