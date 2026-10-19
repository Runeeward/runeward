//! Self-registration of the Validating/MutatingWebhookConfigurations.

use super::Error;
use super::certstore::is_status;
use k8s_openapi::ByteString;
use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhook, MutatingWebhookConfiguration, RuleWithOperations, ServiceReference,
    ValidatingWebhook, ValidatingWebhookConfiguration, WebhookClientConfig,
};
use kube::Resource;
use kube::api::{Api, ObjectMeta, PostParams};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::BTreeMap;
use std::fmt::Debug;

/// Shared name of the self-registered webhook configurations.
pub const CONFIG_NAME: &str = "runeward.dev";

/// Upserts the validating and mutating webhook configurations that route
/// Citadel/Cohort admission to the given Service. `ca_pem` is published as
/// each webhook's `caBundle` so the API server trusts the self-signed serving
/// certificate.
pub async fn register(
    client: kube::Client,
    ca_pem: &[u8],
    service: &str,
    namespace: &str,
) -> Result<(), Error> {
    upsert(
        Api::all(client.clone()),
        validating_configuration(ca_pem, service, namespace),
    )
    .await
    .map_err(|e| Error::Kube {
        context: "register validating webhook".to_owned(),
        error: Box::new(e),
    })?;
    upsert(
        Api::all(client),
        mutating_configuration(ca_pem, service, namespace),
    )
    .await
    .map_err(|e| Error::Kube {
        context: "register mutating webhook".to_owned(),
        error: Box::new(e),
    })
}

async fn upsert<K>(api: Api<K>, mut desired: K) -> Result<(), kube::Error>
where
    K: Resource + Clone + Debug + Serialize + DeserializeOwned,
{
    match api.get(CONFIG_NAME).await {
        Err(e) if is_status(&e, 404) => {
            api.create(&PostParams::default(), &desired).await?;
            Ok(())
        }
        Err(e) => Err(e),
        Ok(existing) => {
            desired.meta_mut().resource_version = existing.meta().resource_version.clone();
            api.replace(CONFIG_NAME, &PostParams::default(), &desired)
                .await?;
            Ok(())
        }
    }
}

fn metadata() -> ObjectMeta {
    ObjectMeta {
        name: Some(CONFIG_NAME.to_owned()),
        labels: Some(BTreeMap::from([(
            "app.kubernetes.io/managed-by".to_owned(),
            "runeward".to_owned(),
        )])),
        ..ObjectMeta::default()
    }
}

/// CREATE/UPDATE on the namespaced Citadel/Cohort and cluster-scoped
/// ClusterCitadel/ClusterCohort resources.
pub fn webhook_rules() -> Vec<RuleWithOperations> {
    let rule = |resources: [&str; 2], scope: &str| RuleWithOperations {
        operations: Some(vec!["CREATE".to_owned(), "UPDATE".to_owned()]),
        api_groups: Some(vec!["runeward.dev".to_owned()]),
        api_versions: Some(vec!["v1alpha1".to_owned()]),
        resources: Some(resources.map(str::to_owned).to_vec()),
        scope: Some(scope.to_owned()),
    };
    vec![
        rule(["citadels", "cohorts"], "Namespaced"),
        rule(["clustercitadels", "clustercohorts"], "Cluster"),
    ]
}

fn client_config(ca_pem: &[u8], service: &str, namespace: &str, path: &str) -> WebhookClientConfig {
    WebhookClientConfig {
        service: Some(ServiceReference {
            name: service.to_owned(),
            namespace: namespace.to_owned(),
            path: Some(path.to_owned()),
            port: None,
        }),
        ca_bundle: Some(ByteString(ca_pem.to_vec())),
        url: None,
    }
}

/// The desired ValidatingWebhookConfiguration. Fails closed: if the webhook is
/// unreachable, Citadel/Cohort admission is denied rather than letting an
/// ungoverned resource through. The rules only match runeward.dev CRDs, so a
/// webhook outage can't wedge core cluster objects.
pub fn validating_configuration(
    ca_pem: &[u8],
    service: &str,
    namespace: &str,
) -> ValidatingWebhookConfiguration {
    ValidatingWebhookConfiguration {
        metadata: metadata(),
        webhooks: Some(vec![ValidatingWebhook {
            name: "validate.runeward.dev".to_owned(),
            client_config: client_config(ca_pem, service, namespace, "/validate"),
            rules: Some(webhook_rules()),
            failure_policy: Some("Fail".to_owned()),
            side_effects: "None".to_owned(),
            admission_review_versions: vec!["v1".to_owned()],
            ..ValidatingWebhook::default()
        }]),
    }
}

/// The desired MutatingWebhookConfiguration. Fails open (`Ignore`): defaulting
/// is a convenience; rejection is the validating webhook's job.
pub fn mutating_configuration(
    ca_pem: &[u8],
    service: &str,
    namespace: &str,
) -> MutatingWebhookConfiguration {
    MutatingWebhookConfiguration {
        metadata: metadata(),
        webhooks: Some(vec![MutatingWebhook {
            name: "mutate.runeward.dev".to_owned(),
            client_config: client_config(ca_pem, service, namespace, "/mutate"),
            rules: Some(webhook_rules()),
            failure_policy: Some("Ignore".to_owned()),
            side_effects: "None".to_owned(),
            admission_review_versions: vec!["v1".to_owned()],
            reinvocation_policy: Some("Never".to_owned()),
            ..MutatingWebhook::default()
        }]),
    }
}
