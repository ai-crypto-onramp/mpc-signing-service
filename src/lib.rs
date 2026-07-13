//! MPC Signing Service — threshold t-of-n signing behind a custody-provider
//! boundary (v1) with policy gating, Wallet Management integration, and
//! signed audit emission.
//!
//! Module map (mirrors PROJECT_PLAN Stage 1):
//! - [`config`]  — 12-factor env configuration
//! - [`domain`]  — key/session/audit domain types
//! - [`store`]   — signing-session and used-token stores
//! - [`policy`]  — policy decision token verification (Stage 3)
//! - [`wallet`]  — Wallet Management client (Stage 4)
//! - [`engine`]  — `SigningEngine` trait, factory, and backends (Stages 5–7)
//! - [`audit`]   — signed audit records + async emitter (Stage 9)
//! - [`grpc`]    — tonic server wiring and the generated proto types

pub mod audit;
pub mod config;
pub mod domain;
pub mod enclave;
pub mod engine;
pub mod grpc;
pub mod mtls;
pub mod policy;
pub mod store;
pub mod wallet;

/// Generated protobuf/tonic types for `proto/mpc_signing.proto`.
pub mod pb {
    tonic::include_proto!("mpc.v1");
}
