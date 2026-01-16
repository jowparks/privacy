//! Error types for the privacy enclave

use thiserror::Error;

/// Errors that can occur in the enclave
#[derive(Error, Debug)]
pub enum EnclaveError {
    #[error("NSM error: {0}")]
    Nsm(String),

    #[error("Attestation error: {0}")]
    Attestation(String),

    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("RPC error: {0}")]
    Rpc(String),
}

pub type Result<T> = std::result::Result<T, EnclaveError>;

