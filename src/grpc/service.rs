//! `MpcSigningService` implementation: the SignTx pipeline is
//! verify policy token → resolve wallet binding → dispatch to the
//! `SigningEngine` → emit a signed audit record. Control-plane RPCs (DKG,
//! rotation, metadata, restore) dispatch to the engine directly.

use std::sync::Arc;

use tonic::{Request, Response, Status};

use crate::audit::{AuditEmitter, AuditResult, AuditSigner};
use crate::domain::{
    sha256_hex, unix_now, Chain, KeyId, SessionStatus, SigningSession, SigningSessionId,
};
use crate::engine::{DkgParams, EngineSignRequest, RestoreParams, SigningEngine};
use crate::pb::mpc_signing_service_server::{MpcSigningService, MpcSigningServiceServer};
use crate::pb::{
    DkgRequest, DkgResponse, GetKeyMetadataRequest, GetKeyMetadataResponse, RestoreShareRequest,
    RestoreShareResponse, RotateKeyRequest, RotateKeyResponse, SignTxRequest, SignTxResponse,
};
use crate::policy::PolicyTokenVerifier;
use crate::store::SigningSessionStore;
use crate::wallet::{WalletError, WalletManagementClient};

/// Assembled service dependencies.
pub struct MpcService {
    pub verifier: Option<Arc<dyn PolicyTokenVerifier>>,
    pub wallet: Option<Arc<dyn WalletManagementClient>>,
    pub engine: Arc<dyn SigningEngine>,
    pub sessions: Arc<dyn SigningSessionStore>,
    pub audit_signer: Arc<AuditSigner>,
    pub audit: AuditEmitter,
    /// DEV ONLY escape hatches; both default to fail-closed.
    pub skip_policy: bool,
    pub skip_wallet_check: bool,
}

impl MpcService {
    fn deny(&self, session: &SigningSession, reason: &str, code: tonic::Code) -> Status {
        self.sessions
            .update_status(&session.id, SessionStatus::Denied, Some(reason.to_string()));
        self.audit.emit(self.audit_signer.record(
            &session.id,
            &session.key_id,
            session.chain,
            &session.request_hash,
            AuditResult::Denied,
            Some(reason.to_string()),
            None,
        ));
        Status::new(code, reason.to_string())
    }
}

#[tonic::async_trait]
impl MpcSigningService for MpcService {
    async fn sign_tx(
        &self,
        request: Request<SignTxRequest>,
    ) -> Result<Response<SignTxResponse>, Status> {
        let req = request.into_inner();
        let chain = Chain::from_proto(req.chain)
            .ok_or_else(|| Status::invalid_argument("unknown or unspecified chain"))?;
        if req.key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        if req.tx_payload.is_empty() {
            return Err(Status::invalid_argument("tx_payload is required"));
        }

        let session = SigningSession {
            id: SigningSessionId::new(),
            key_id: KeyId(req.key_id.clone()),
            chain,
            request_hash: sha256_hex(&req.tx_payload),
            status: SessionStatus::Pending,
            denial_reason: None,
            created_at_unix: unix_now(),
        };
        self.sessions.insert(session.clone());

        // 1. Policy decision token — refuse to sign without approval.
        if self.skip_policy {
            tracing::warn!("INSECURE_SKIP_POLICY is set; skipping policy token verification");
        } else {
            let Some(verifier) = &self.verifier else {
                return Err(self.deny(
                    &session,
                    "policy_verifier_not_configured",
                    tonic::Code::FailedPrecondition,
                ));
            };
            if let Err(reason) = verifier.verify(
                &req.policy_decision_token,
                &req.tx_payload,
                &req.key_id,
                chain,
            ) {
                return Err(self.deny(
                    &session,
                    &reason.to_string(),
                    tonic::Code::FailedPrecondition,
                ));
            }
        }

        // 2. Wallet Management key binding — fail closed on any error.
        if self.skip_wallet_check {
            tracing::warn!("INSECURE_SKIP_WALLET_CHECK is set; skipping wallet binding check");
        } else {
            let Some(wallet) = &self.wallet else {
                return Err(self.deny(
                    &session,
                    "wallet_management_not_configured",
                    tonic::Code::FailedPrecondition,
                ));
            };
            if let Err(err) = wallet.check_key_binding(&req.wallet_id, &req.key_id).await {
                let (reason, code) = match err {
                    WalletError::Unavailable(_) => {
                        ("wallet_management_unavailable", tonic::Code::Unavailable)
                    }
                    WalletError::NotFound => ("wallet_not_found", tonic::Code::FailedPrecondition),
                    WalletError::KeyMismatch => {
                        ("wallet_key_mismatch", tonic::Code::FailedPrecondition)
                    }
                };
                return Err(self.deny(&session, reason, code));
            }
        }

        // 3. Dispatch to the signing engine.
        self.sessions
            .update_status(&session.id, SessionStatus::Signing, None);
        let engine_req = EngineSignRequest {
            key_id: session.key_id.clone(),
            chain,
            payload: req.tx_payload.clone(),
        };
        match self.engine.sign(&engine_req).await {
            Ok(sig) => {
                self.sessions
                    .update_status(&session.id, SessionStatus::Signed, None);
                self.audit.emit(self.audit_signer.record(
                    &session.id,
                    &session.key_id,
                    chain,
                    &session.request_hash,
                    AuditResult::Signed,
                    None,
                    Some(hex::encode(&sig.signature)),
                ));
                Ok(Response::new(SignTxResponse {
                    signing_session_id: session.id.0,
                    signature: sig.signature,
                    public_key: sig.public_key,
                    // Address resolution lands with the Wallet Management
                    // metadata RPC extension; empty until then.
                    address: String::new(),
                }))
            }
            Err(err) => {
                let msg = err.to_string();
                self.sessions
                    .update_status(&session.id, SessionStatus::Failed, Some(msg.clone()));
                self.audit.emit(self.audit_signer.record(
                    &session.id,
                    &session.key_id,
                    chain,
                    &session.request_hash,
                    AuditResult::Failed,
                    Some(msg),
                    None,
                ));
                Err(err.into())
            }
        }
    }

    async fn dkg(&self, request: Request<DkgRequest>) -> Result<Response<DkgResponse>, Status> {
        let req = request.into_inner();
        let chain = Chain::from_proto(req.chain)
            .ok_or_else(|| Status::invalid_argument("unknown or unspecified chain"))?;
        let out = self
            .engine
            .dkg(&DkgParams {
                chain,
                threshold: req.threshold,
                parties: req.parties,
            })
            .await
            .map_err(Status::from)?;
        tracing::info!(key_id = %out.key_id.0, chain = chain.as_str(), "dkg completed");
        Ok(Response::new(DkgResponse {
            key_id: out.key_id.0,
            public_key: out.public_key,
        }))
    }

    async fn rotate_key(
        &self,
        request: Request<RotateKeyRequest>,
    ) -> Result<Response<RotateKeyResponse>, Status> {
        let req = request.into_inner();
        if req.key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        let out = self
            .engine
            .rotate_key(&KeyId(req.key_id))
            .await
            .map_err(Status::from)?;
        tracing::info!(key_id = %out.key_id.0, epoch = out.epoch, "key rotated");
        Ok(Response::new(RotateKeyResponse {
            key_id: out.key_id.0,
            public_key: out.public_key,
            epoch: out.epoch,
        }))
    }

    async fn get_key_metadata(
        &self,
        request: Request<GetKeyMetadataRequest>,
    ) -> Result<Response<GetKeyMetadataResponse>, Status> {
        let req = request.into_inner();
        if req.key_id.is_empty() {
            return Err(Status::invalid_argument("key_id is required"));
        }
        let meta = self
            .engine
            .get_key_metadata(&KeyId(req.key_id))
            .await
            .map_err(Status::from)?;
        Ok(Response::new(GetKeyMetadataResponse {
            key_id: meta.key_id.0,
            chain: match meta.chain {
                Chain::Evm => 1,
                Chain::Solana => 2,
                Chain::Aptos => 3,
                Chain::Sui => 4,
                Chain::Bitcoin => 5,
            },
            public_key: meta.public_key,
            status: format!("{:?}", meta.status).to_lowercase(),
            epoch: meta.epoch,
        }))
    }

    async fn restore_share(
        &self,
        request: Request<RestoreShareRequest>,
    ) -> Result<Response<RestoreShareResponse>, Status> {
        let req = request.into_inner();
        if req.key_id.is_empty() || req.node_id.is_empty() {
            return Err(Status::invalid_argument("key_id and node_id are required"));
        }
        let restored = self
            .engine
            .restore_share(&RestoreParams {
                key_id: KeyId(req.key_id.clone()),
                node_id: req.node_id.clone(),
                quorum_proof: req.quorum_proof,
            })
            .await
            .map_err(Status::from)?;
        tracing::info!(key_id = %req.key_id, node_id = %req.node_id, "share restore");
        Ok(Response::new(RestoreShareResponse {
            key_id: req.key_id,
            node_id: req.node_id,
            restored,
        }))
    }
}

/// Serve the gRPC service on `addr` until `shutdown` resolves.
pub async fn serve(
    service: MpcService,
    addr: std::net::SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> anyhow::Result<()> {
    tracing::info!(%addr, "mpc-signing-service gRPC listening");
    tonic::transport::Server::builder()
        .add_service(MpcSigningServiceServer::new(service))
        .serve_with_shutdown(addr, shutdown)
        .await?;
    Ok(())
}
