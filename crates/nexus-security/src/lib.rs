//! Nexus Desktop security core.
//!
//! Every remote or workspace-mutating operation in Nexus Desktop must obtain a
//! [`policy::Grant`] from [`policy::PolicyEngine::authorize`]. The Debian server is
//! permanently read-only: its policy is a compile-time constant that settings
//! cannot loosen. See `docs/SECURITY-MODEL.md`.

pub mod audit;
pub mod catalog;
pub mod gateway;
pub mod hostkeys;
pub mod otp;
pub mod paths;
pub mod policy;
pub mod ro;
pub mod sensitive;
pub mod shell;

pub use policy::{Capability, Denial, Grant, Operation, Origin, PolicyEngine, Target};
