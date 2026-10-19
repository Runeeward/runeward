//! Kubernetes integration for Rune Box.
//!
//! - [`manifests`]: the embedded `runeward.dev` CRDs and controller install
//!   bundle applied by `runeward up` (the shipped YAML is canonical).
//! - [`crd`]: typed `runeward.dev/v1alpha1` resources (Citadel,
//!   ClusterCitadel, Cohort, ClusterCohort, ClusterPolicy).
//! - [`controller`]: reconciles Citadel/Cohort resources onto the
//!   control-plane Manager running in the same process.
//! - [`webhook`]: the validating/mutating admission webhook enforcing
//!   ClusterPolicy on Citadel and Cohort resources.

pub mod controller;
pub mod crd;
pub mod manifests;
pub mod webhook;

#[cfg(test)]
mod testutil;
