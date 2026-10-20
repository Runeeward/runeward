//! Runeward's observability wiring: structured logging through `tracing`,
//! Prometheus metrics, and opt-in anonymous [`telemetry`].
//!
//! The crate has no dependency on the control plane, so any crate can record
//! metrics without creating a dependency cycle.

mod logging;
mod metrics;
pub mod telemetry;

pub use logging::{
    ENV_LOG_FORMAT, ENV_LOG_LEVEL, LogFormat, dispatch, dispatch_from_lookup, init_logging,
    parse_format, parse_level,
};
pub use metrics::{inc_sandbox_created, metrics_handler, record_action, registry, set_build_info};
