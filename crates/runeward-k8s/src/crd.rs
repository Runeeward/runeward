//! Typed `runeward.dev/v1alpha1` custom resources.
//!
//! These mirror the CRD schemas shipped in `internal/manifests/crds` (and the
//! `deploy/crds` copies). The shipped YAML stays the source of truth: it is
//! what gets installed (see [`crate::manifests`]); the `CustomResource`
//! derives here exist for typed clients, and a test checks that the derived
//! CRDs agree with the YAML on group, versions, names, scope, subresources,
//! printer columns and the spec/status field shapes.

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// API group of every runeward custom resource.
pub const GROUP: &str = "runeward.dev";
/// The only served (and storage) version.
pub const VERSION: &str = "v1alpha1";

/// Desired state of a [`Citadel`]: one governed runeward execution cell.
#[derive(
    CustomResource, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[kube(
    group = "runeward.dev",
    version = "v1alpha1",
    kind = "Citadel",
    plural = "citadels",
    singular = "citadel",
    shortname = "ctd",
    namespaced,
    status = "CitadelStatus",
    doc = "Citadel is a declarative request for one governed runeward execution cell.",
    printcolumn = r#"{"name":"Profile","type":"string","jsonPath":".spec.profile"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Citadel","type":"string","jsonPath":".status.citadelId"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CitadelSpec {
    /// Name of the runeward profile to provision from.
    pub profile: String,
}

/// Desired state of a [`ClusterCitadel`]: a cluster-scoped [`Citadel`] whose
/// backing Pod/PVC lives in the controller namespace.
#[derive(
    CustomResource, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[kube(
    group = "runeward.dev",
    version = "v1alpha1",
    kind = "ClusterCitadel",
    plural = "clustercitadels",
    singular = "clustercitadel",
    shortname = "cctd",
    status = "CitadelStatus",
    doc = "ClusterCitadel is a cluster-scoped declarative request for one governed runeward execution cell.",
    printcolumn = r#"{"name":"Profile","type":"string","jsonPath":".spec.profile"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Citadel","type":"string","jsonPath":".status.citadelId"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCitadelSpec {
    /// Name of the runeward profile to provision from.
    pub profile: String,
}

/// Observed state shared by [`Citadel`] and [`ClusterCitadel`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CitadelStatus {
    /// One of Pending, Running, Failed, Terminating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// The runeward citadel id backing this resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citadel_id: Option<String>,
    /// Backend the citadel runs on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    /// Image the citadel runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// Isolation tier the citadel runs behind (`process`, `container`,
    /// `kernel` or `vm`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub isolation: Option<String>,
    /// Human-readable status detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Generation last reconciled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Desired state of a [`Cohort`]: N governed citadels sharing one atomic task
/// board.
#[derive(
    CustomResource, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[kube(
    group = "runeward.dev",
    version = "v1alpha1",
    kind = "Cohort",
    plural = "cohorts",
    singular = "cohort",
    shortname = "coh",
    namespaced,
    status = "CohortStatus",
    doc = "Cohort is a declarative request for N governed runeward citadels that share a single atomic task board.",
    printcolumn = r#"{"name":"Profile","type":"string","jsonPath":".spec.profile"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Cohort","type":"string","jsonPath":".status.cohortId"}"#,
    printcolumn = r#"{"name":"Done","type":"integer","jsonPath":".status.tasksDone"}"#,
    printcolumn = r#"{"name":"Total","type":"integer","jsonPath":".status.tasksTotal"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct CohortSpec {
    /// Name of the runeward profile (with a `[fleet]` block).
    pub profile: String,
}

/// Desired state of a [`ClusterCohort`]: a cluster-scoped [`Cohort`].
#[derive(
    CustomResource, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[kube(
    group = "runeward.dev",
    version = "v1alpha1",
    kind = "ClusterCohort",
    plural = "clustercohorts",
    singular = "clustercohort",
    shortname = "ccoh",
    status = "CohortStatus",
    doc = "ClusterCohort is a cluster-scoped declarative request for N governed runeward citadels that share a single atomic task board.",
    printcolumn = r#"{"name":"Profile","type":"string","jsonPath":".spec.profile"}"#,
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Cohort","type":"string","jsonPath":".status.cohortId"}"#,
    printcolumn = r#"{"name":"Done","type":"integer","jsonPath":".status.tasksDone"}"#,
    printcolumn = r#"{"name":"Total","type":"integer","jsonPath":".status.tasksTotal"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterCohortSpec {
    /// Name of the runeward profile (with a `[fleet]` block).
    pub profile: String,
}

/// Observed state shared by [`Cohort`] and [`ClusterCohort`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct CohortStatus {
    /// One of Pending, Running, Failed, Terminating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    /// The runeward cohort id backing this resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cohort_id: Option<String>,
    /// Ids of the member citadels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub citadels: Option<Vec<String>>,
    /// Total tasks on the board.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks_total: Option<i64>,
    /// Tasks not yet claimed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks_pending: Option<i64>,
    /// Tasks claimed by a citadel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks_claimed: Option<i64>,
    /// Tasks completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks_done: Option<i64>,
    /// Tasks failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tasks_failed: Option<i64>,
    /// Human-readable status detail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Generation last reconciled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Org-wide defaults and guardrails for Citadel and Cohort resources, enforced
/// by the admission webhook (see [`crate::webhook`]).
#[derive(
    CustomResource, Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema,
)]
#[kube(
    group = "runeward.dev",
    version = "v1alpha1",
    kind = "ClusterPolicy",
    plural = "clusterpolicies",
    singular = "clusterpolicy",
    shortname = "cpol",
    status = "ClusterPolicyStatus",
    doc = "ClusterPolicy declares org-wide defaults and guardrails for runeward Citadel and Cohort resources.",
    printcolumn = r#"{"name":"Default","type":"string","jsonPath":".spec.defaultProfile"}"#,
    printcolumn = r#"{"name":"Observed","type":"integer","jsonPath":".status.observedResources"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPolicySpec {
    /// Glob patterns; if non-empty, `spec.profile` must match at least one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_profiles: Option<Vec<String>>,
    /// Glob patterns; if any matches `spec.profile` the request is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denied_profiles: Option<Vec<String>>,
    /// Mutating default applied when `spec.profile` is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_profile: Option<String>,
    /// Glob patterns; if non-empty, the resource's namespace must match one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_namespaces: Option<Vec<String>>,
    /// Label keys that must be present on the resource metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_labels: Option<Vec<String>>,
}

/// Observed state of a [`ClusterPolicy`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ClusterPolicyStatus {
    /// Number of resources evaluated against this policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_resources: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifests;
    use k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::{
        CustomResourceDefinition, JSONSchemaProps,
    };
    use kube::CustomResourceExt;
    use std::collections::{BTreeMap, BTreeSet};

    fn shipped(name: &str) -> CustomResourceDefinition {
        let m = manifests::crds()
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("no shipped CRD {name}"));
        serde_yml::from_str(m.content).unwrap_or_else(|e| panic!("parse {name}: {e}"))
    }

    fn props(s: &JSONSchemaProps) -> BTreeMap<String, JSONSchemaProps> {
        s.properties.clone().unwrap_or_default()
    }

    fn required(s: &JSONSchemaProps) -> BTreeSet<String> {
        s.required.clone().unwrap_or_default().into_iter().collect()
    }

    /// Compares one object level (spec or status): same field names, same
    /// required set, and same `type`/`format`/item type for each field.
    fn assert_level(ctx: &str, derived: &JSONSchemaProps, shipped: &JSONSchemaProps) {
        assert_eq!(
            required(derived),
            required(shipped),
            "{ctx}: required fields"
        );
        let (d, s) = (props(derived), props(shipped));
        assert_eq!(
            d.keys().collect::<Vec<_>>(),
            s.keys().collect::<Vec<_>>(),
            "{ctx}: property names"
        );
        for (name, sp) in &s {
            let dp = &d[name];
            assert_eq!(dp.type_, sp.type_, "{ctx}.{name}: type");
            if sp.format.is_some() {
                assert_eq!(dp.format, sp.format, "{ctx}.{name}: format");
            }
            let item_type = |p: &JSONSchemaProps| {
                match &p.items {
                Some(k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::JSONSchemaPropsOrArray::Schema(s)) => s.type_.clone(),
                Some(_) => Some("<array>".to_owned()),
                None => None,
            }
            };
            assert_eq!(item_type(dp), item_type(sp), "{ctx}.{name}: item type");
        }
    }

    fn assert_compatible(file: &str, derived: CustomResourceDefinition) {
        let shipped = shipped(file);
        assert_eq!(derived.metadata.name, shipped.metadata.name, "{file}: name");
        let (d, s) = (&derived.spec, &shipped.spec);
        assert_eq!(d.group, s.group, "{file}: group");
        assert_eq!(d.scope, s.scope, "{file}: scope");
        assert_eq!(d.names.kind, s.names.kind, "{file}: kind");
        assert_eq!(d.names.plural, s.names.plural, "{file}: plural");
        assert_eq!(d.names.singular, s.names.singular, "{file}: singular");
        assert_eq!(
            d.names.short_names, s.names.short_names,
            "{file}: shortNames"
        );
        assert_eq!(
            d.names
                .list_kind
                .as_deref()
                .unwrap_or(&format!("{}List", d.names.kind)),
            s.names.list_kind.as_deref().unwrap_or_default(),
            "{file}: listKind"
        );
        assert_eq!(d.versions.len(), s.versions.len(), "{file}: version count");
        for (dv, sv) in d.versions.iter().zip(&s.versions) {
            let ctx = format!("{file} {}", sv.name);
            assert_eq!(dv.name, sv.name, "{ctx}: version name");
            assert_eq!(dv.served, sv.served, "{ctx}: served");
            assert_eq!(dv.storage, sv.storage, "{ctx}: storage");
            assert_eq!(
                dv.subresources.as_ref().map(|r| r.status.is_some()),
                sv.subresources.as_ref().map(|r| r.status.is_some()),
                "{ctx}: status subresource"
            );
            let cols = |v: &k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinitionVersion| {
                v.additional_printer_columns
                    .clone()
                    .unwrap_or_default()
                    .into_iter()
                    .map(|c| (c.name, c.type_, c.json_path))
                    .collect::<Vec<_>>()
            };
            assert_eq!(cols(dv), cols(sv), "{ctx}: printer columns");

            let schema = |v: &k8s_openapi::apiextensions_apiserver::pkg::apis::apiextensions::v1::CustomResourceDefinitionVersion| {
                v.schema
                    .as_ref()
                    .and_then(|s| s.open_api_v3_schema.clone())
                    .expect("openAPIV3Schema")
            };
            let (droot, sroot) = (schema(dv), schema(sv));
            let (dprops, sprops) = (props(&droot), props(&sroot));
            for level in ["spec", "status"] {
                let sl = sprops
                    .get(level)
                    .unwrap_or_else(|| panic!("{ctx}: shipped {level}"));
                let dl = dprops
                    .get(level)
                    .unwrap_or_else(|| panic!("{ctx}: derived {level}"));
                assert_eq!(dl.type_, sl.type_, "{ctx}.{level}: type");
                assert_level(&format!("{ctx}.{level}"), dl, sl);
            }
            // spec is required in the derived CRD only when it has required
            // fields; the shipped CRDs never require spec itself, so the
            // derived root may differ there. Status is never required.
            assert!(
                !required(&droot).contains("status"),
                "{ctx}: status required"
            );
        }
    }

    #[test]
    fn derived_crds_match_shipped_yaml() {
        assert_compatible("runeward.dev_citadels.yaml", Citadel::crd());
        assert_compatible("runeward.dev_clustercitadels.yaml", ClusterCitadel::crd());
        assert_compatible("runeward.dev_cohorts.yaml", Cohort::crd());
        assert_compatible("runeward.dev_clustercohorts.yaml", ClusterCohort::crd());
        assert_compatible("runeward.dev_clusterpolicies.yaml", ClusterPolicy::crd());
    }

    #[test]
    fn every_shipped_crd_has_a_rust_type() {
        let derived: BTreeSet<String> = [
            Citadel::crd_name(),
            ClusterCitadel::crd_name(),
            Cohort::crd_name(),
            ClusterCohort::crd_name(),
            ClusterPolicy::crd_name(),
        ]
        .into_iter()
        .map(str::to_owned)
        .collect();
        let shipped: BTreeSet<String> = manifests::crds()
            .iter()
            .map(|m| shipped(m.name).metadata.name.unwrap_or_default())
            .collect();
        assert_eq!(derived, shipped);
    }

    #[test]
    fn typed_round_trip() {
        let raw = serde_json::json!({
            "apiVersion": "runeward.dev/v1alpha1",
            "kind": "Cohort",
            "metadata": {"name": "c", "namespace": "apps"},
            "spec": {"profile": "fleet"},
            "status": {"phase": "Running", "cohortId": "coh-1", "citadels": ["a", "b"], "tasksDone": 2, "tasksTotal": 5, "observedGeneration": 3}
        });
        let c: Cohort = serde_json::from_value(raw.clone()).expect("decode");
        assert_eq!(c.spec.profile, "fleet");
        let st = c.status.as_ref().expect("status");
        assert_eq!(st.cohort_id.as_deref(), Some("coh-1"));
        assert_eq!(st.tasks_done, Some(2));
        assert_eq!(serde_json::to_value(&c).expect("encode"), raw);

        let p: ClusterPolicy = serde_json::from_value(serde_json::json!({
            "apiVersion": "runeward.dev/v1alpha1",
            "kind": "ClusterPolicy",
            "metadata": {"name": "p"},
            "spec": {"defaultProfile": "baseline", "deniedProfiles": ["*-root"]}
        }))
        .expect("decode policy");
        assert_eq!(p.spec.default_profile.as_deref(), Some("baseline"));
        assert_eq!(p.spec.denied_profiles, Some(vec!["*-root".to_owned()]));
        assert!(p.spec.allowed_profiles.is_none());
    }
}
