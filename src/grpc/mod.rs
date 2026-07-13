//! tonic server wiring (Stage 2) and the JSON codec used to interoperate
//! with wallet-management's JSON-codec gRPC server.

pub mod json_codec;
pub mod service;

pub use service::{serve, MpcService};
