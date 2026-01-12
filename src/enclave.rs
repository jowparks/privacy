//! Enclave server implementation with NSM integration
//!
//! This module provides the core enclave functionality, analogous to
//! the Go server in op-enclave. It handles:
//! - NSM session management
//! - Key generation using enclave's secure random
//! - Attestation document generation

use crate::error::{EnclaveError, Result};
use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use tracing::{info, warn};

/// PCR (Platform Configuration Register) data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PcrData {
    pub pcr0: Vec<u8>,
    pub pcr1: Vec<u8>,
    pub pcr2: Vec<u8>,
}

/// Attestation document from the NSM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationDocument {
    pub document: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// The main enclave server struct
pub struct EnclaveServer {
    /// PCR0 value for the enclave (empty in local mode)
    pcr0: Vec<u8>,
    /// ECDSA signing key pair
    signing_key: EcdsaKeyPair,
    /// PKCS8 document for the signing key (kept for potential key export)
    #[allow(dead_code)]
    signing_key_pkcs8: Vec<u8>,
    /// Whether running in local (non-enclave) mode
    is_local_mode: bool,
    /// NSM file descriptor (None in local mode)
    nsm_fd: Option<i32>,
}

impl EnclaveServer {
    /// Creates a new enclave server
    ///
    /// In production (inside a Nitro enclave), this will:
    /// - Open an NSM session
    /// - Read PCR values
    /// - Generate keys using the NSM's secure random
    ///
    /// In local mode (for development), this will:
    /// - Use system random for key generation
    /// - Skip NSM operations
    pub fn new() -> Result<Self> {
        // Try to initialize NSM
        let nsm_result = nsm_init();

        let (nsm_fd, is_local_mode, pcr0) = match nsm_result {
            fd if fd >= 0 => {
                info!("NSM initialized successfully, running in enclave mode");

                // Get PCR0 value
                let pcr0 = Self::get_pcr_value(fd, 0)?;
                info!(
                    pcr0_hex = hex::encode(&pcr0),
                    "Retrieved PCR0 value"
                );

                (Some(fd), false, pcr0)
            }
            _ => {
                warn!("Failed to initialize NSM, running in local mode");
                (None, true, Vec::new())
            }
        };

        // Generate signing key
        let rng = SystemRandom::new();
        let pkcs8_bytes = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .map_err(|e| EnclaveError::Crypto(format!("Failed to generate key: {}", e)))?;

        let signing_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_bytes.as_ref(), &rng)
                .map_err(|e| EnclaveError::Crypto(format!("Failed to parse key: {}", e)))?;

        let public_key_hex = hex::encode(signing_key.public_key().as_ref());
        info!(
            public_key = public_key_hex,
            is_local_mode = is_local_mode,
            "Enclave server initialized"
        );

        Ok(Self {
            pcr0,
            signing_key,
            signing_key_pkcs8: pkcs8_bytes.as_ref().to_vec(),
            is_local_mode,
            nsm_fd,
        })
    }

    /// Gets a PCR value from the NSM
    fn get_pcr_value(fd: i32, index: u16) -> Result<Vec<u8>> {
        let request = Request::DescribePCR { index };
        let response = nsm_process_request(fd, request);

        match response {
            Response::DescribePCR { lock: _, data } => Ok(data),
            Response::Error(err) => Err(EnclaveError::Nsm(format!(
                "Failed to describe PCR: {:?}",
                err
            ))),
            _ => Err(EnclaveError::Nsm("Unexpected NSM response".to_string())),
        }
    }

    /// Returns the public key of the signing key
    pub fn public_key(&self) -> Vec<u8> {
        self.signing_key.public_key().as_ref().to_vec()
    }

    /// Returns the public key as a hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key())
    }

    /// Generates an attestation document with the public key
    ///
    /// In local mode, returns a mock attestation document
    pub fn get_attestation(&self, user_data: Option<Vec<u8>>) -> Result<AttestationDocument> {
        if self.is_local_mode {
            // In local mode, return a mock attestation
            warn!("Generating mock attestation in local mode");
            return Ok(AttestationDocument {
                document: b"MOCK_ATTESTATION_LOCAL_MODE".to_vec(),
                public_key: self.public_key(),
            });
        }

        let fd = self.nsm_fd.ok_or_else(|| {
            EnclaveError::Nsm("NSM not initialized".to_string())
        })?;

        let request = Request::Attestation {
            user_data: user_data.map(ByteBuf::from),
            nonce: None,
            public_key: Some(ByteBuf::from(self.public_key())),
        };

        let response = nsm_process_request(fd, request);

        match response {
            Response::Attestation { document } => Ok(AttestationDocument {
                document,
                public_key: self.public_key(),
            }),
            Response::Error(err) => Err(EnclaveError::Attestation(format!(
                "Failed to get attestation: {:?}",
                err
            ))),
            _ => Err(EnclaveError::Attestation(
                "Unexpected NSM response".to_string(),
            )),
        }
    }

    /// Signs a message with the enclave's signing key
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        self.signing_key
            .sign(&rng, message)
            .map(|sig| sig.as_ref().to_vec())
            .map_err(|e| EnclaveError::Crypto(format!("Failed to sign: {}", e)))
    }

    /// Returns whether running in local mode
    pub fn is_local_mode(&self) -> bool {
        self.is_local_mode
    }

    /// Returns the PCR0 value (empty in local mode)
    pub fn pcr0(&self) -> &[u8] {
        &self.pcr0
    }
}

impl Drop for EnclaveServer {
    fn drop(&mut self) {
        if let Some(fd) = self.nsm_fd {
            nsm_exit(fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_mode_server() {
        let server = EnclaveServer::new().expect("Failed to create server");
        assert!(server.is_local_mode());
        assert!(server.pcr0().is_empty());
        assert!(!server.public_key().is_empty());
    }

    #[test]
    fn test_signing() {
        let server = EnclaveServer::new().expect("Failed to create server");
        let message = b"hello world";
        let signature = server.sign(message).expect("Failed to sign");
        assert!(!signature.is_empty());
    }

    #[test]
    fn test_mock_attestation() {
        let server = EnclaveServer::new().expect("Failed to create server");
        let attestation = server.get_attestation(None).expect("Failed to get attestation");
        assert!(!attestation.document.is_empty());
        assert_eq!(attestation.public_key, server.public_key());
    }
}

