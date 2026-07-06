//! MPC Signing Service library crate.
//!
//! Threshold (t-of-n) signing across distributed nodes — no single key.
//!
//! Stage 1 establishes the workspace skeleton: module layout, dependency
//! baseline, and feature flags. Each module here is a stub that later stages
//! flesh out. Keeping the surface stable lets every subsequent stage compile
//! against a single foundation.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod audit;
pub mod config;
pub mod engine;
pub mod node;
pub mod policy;
pub mod proto;
pub mod provider;
pub mod wallet;

/// Crate-level error alias used by stub handlers.
pub type Result<T> = std::result::Result<T, Error>;

/// Crate-level error type. Later stages add richer variants; for now this is a
/// thin wrapper so the skeleton compiles end-to-end.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A stub was called before its implementing stage landed.
    #[error("not yet implemented (see PROJECT_PLAN.md stage notes): {0}")]
    Unimplemented(&'static str),
}

/// Smoke-test helper: returns the service's identity string. Used by the binary
/// and by `cargo test`'s Stage 1 smoke test so there is always at least one
/// passing test (acceptance criterion: "cargo test passes with a single smoke
/// test").
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stage 1 acceptance smoke test — the only test required at this stage.
    /// Confirms the library links, the version string is populated, and the
    /// module tree is publicly addressable.
    #[test]
    fn smoke_service_skeleton_loads() {
        assert!(!version().is_empty());
        let err = Error::Unimplemented("stage-1 skeleton");
        assert_eq!(
            err.to_string(),
            "not yet implemented (see PROJECT_PLAN.md stage notes): stage-1 skeleton"
        );
    }
}
