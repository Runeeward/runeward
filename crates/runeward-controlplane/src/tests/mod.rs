//! In-crate tests. They reach private state the way the Go tests did, and
//! never need Docker or Kubernetes: sandboxes come from [`support::FakeBackend`].

mod agents;
mod citadels;
mod compat;
mod context;
mod fleets;
mod govern;
mod governance;
mod support;
mod workspaces;
