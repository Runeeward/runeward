//! Kubernetes integration for Rune Box.
//!
//! - [`manifests`]: the embedded `runeward.dev` CRDs and controller install
//!   bundle applied by `runeward up` (the shipped YAML is canonical).
//! - [`crd`]: typed `runeward.dev/v1alpha1` resources (Citadel,
//!   ClusterCitadel, Cohort, ClusterCohort, ClusterPolicy).
//! - [`webhook`]: the validating/mutating admission webhook enforcing
//!   ClusterPolicy on Citadel and Cohort resources.
//!
//! The controller that reconciles Citadel/Cohort resources onto Pods and
//! PVCs is not ported yet: it drives the runeward control plane, which has no
//! Rust port so far. It will land here as a `controller` module once it does.

pub mod manifests;
