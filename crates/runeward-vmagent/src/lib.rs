//! The Rune Box microVM guest agent and its host protocol.
//!
//! `runeward-vmagent` is the guest's PID 1 (the Firecracker initramfs
//! `/init`, or libkrun's `/init.krun`). It builds the sandbox root from the
//! read-only image disk and the workspace disk, then serves the host over
//! vsock: commands with streamed stdin/stdout/stderr, a TTY, signals and
//! exit status; file read/write/stat/list and workspace tar streams; the
//! isolation probe; and shutdown. The guest has no network interface: the
//! agent forwards the sandbox's proxy connections to the host over vsock,
//! where the Charter's egress policy is enforced.
//!
//! - [`proto`]: frames and messages (shared with the host backend);
//! - [`server`]: request handling (portable Unix, testable on a host);
//! - [`helper`] and [`fileops`]: what runs after the identity switch;
//! - [`probe`]: the isolation evidence;
//! - `guest` (Linux): PID 1 boot, mounts, vsock.

pub mod proto;

#[cfg(unix)]
pub mod fileops;
#[cfg(target_os = "linux")]
pub mod guest;
#[cfg(unix)]
pub mod helper;
pub mod probe;
#[cfg(unix)]
pub mod server;
#[cfg(unix)]
pub mod users;
