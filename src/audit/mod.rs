//! Signing audit records — tamper-evident, append-only, emitted per signing
//! attempt (success or denial) to the Audit / Event Log.
//!
//! Stub. Stage 7 implements the signed-record shape and async stream.

#![allow(dead_code)]

use crate::Error;
use crate::Result;

/// Audit recorder trait. Stage 7 wires the real emitter to the Audit / Event
/// Log; the in-mem impl is used by tests now.
pub trait AuditRecorder: Send + Sync {
    /// Record a signing attempt (success or denial).
    fn record(&self, session_id: &str, result: AuditResult) -> Result<()> {
        let _ = (session_id, result);
        Err(Error::Unimplemented("AuditRecorder::record (Stage 7)"))
    }
}

/// Result of a signing attempt, captured in the audit record.
#[derive(Debug, Clone)]
pub enum AuditResult {
    /// Signature produced; carries the signature bytes.
    Signed(Vec<u8>),
    /// Signing denied; carries the denial reason.
    Denied(String),
}
