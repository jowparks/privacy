//! KMS client for Nitro Enclave attestation-based cryptography
//!
//! This module provides a KMS client that uses attestation documents to
//! decrypt data sealed to the enclave. Only code running inside the enclave
//! with the correct PCR values can decrypt data encrypted with the enclave-key.
//!
//! ## Encryption Flow
//!
//! 1. **Encrypt** (can happen anywhere with KMS access):
//!    - Call `kms:Encrypt` with the enclave-key
//!    - Returns ciphertext that only the enclave can decrypt
//!
//! 2. **Decrypt** (must happen inside enclave):
//!    - Generate attestation document from NSM
//!    - Call `kms:Decrypt` with the attestation as `Recipient` parameter
//!    - KMS validates attestation against key policy conditions
//!    - Returns plaintext re-encrypted under a one-time key from attestation
//!
//! ## Reference
//!
//! - [AWS KMS cryptographic attestation](https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html)

use crate::error::{EnclaveError, Result};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{RecipientInfo, KeyEncryptionMechanism};
use aws_sdk_kms::Client as KmsClient;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};

/// Recipient attestation structure for KMS decrypt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KmsRecipient {
    /// The attestation document from the Nitro Secure Module
    pub attestation_document: Vec<u8>,
    /// The encryption algorithm for the plaintext data key
    pub key_encryption_algorithm: String,
}

/// KMS wrapper for enclave operations
pub struct EnclaveKms {
    client: KmsClient,
    key_id: String,
}

impl EnclaveKms {
    /// Creates a new EnclaveKms client
    pub fn new(client: KmsClient, key_id: impl Into<String>) -> Self {
        Self {
            client,
            key_id: key_id.into(),
        }
    }

    /// Encrypts plaintext using the enclave KMS key
    ///
    /// This can be called from anywhere with KMS encrypt permission.
    /// The resulting ciphertext can only be decrypted inside the enclave.
    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        info!(key_id = %self.key_id, plaintext_len = plaintext.len(), "Encrypting data");

        let response = self
            .client
            .encrypt()
            .key_id(&self.key_id)
            .plaintext(Blob::new(plaintext))
            .send()
            .await
            .map_err(|e| EnclaveError::Kms(format!("Encrypt failed: {}", e)))?;

        let ciphertext = response
            .ciphertext_blob()
            .ok_or_else(|| EnclaveError::Kms("No ciphertext in response".to_string()))?;

        debug!(ciphertext_len = ciphertext.as_ref().len(), "Encryption successful");
        Ok(ciphertext.as_ref().to_vec())
    }

    /// Decrypts ciphertext using attestation
    ///
    /// This must be called from inside a Nitro enclave. The attestation document
    /// proves to KMS that the code is running in an enclave with the expected PCR values.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The encrypted data from a previous `encrypt` call
    /// * `attestation_document` - CBOR-encoded attestation from NSM
    ///
    /// # Returns
    ///
    /// The decrypted plaintext, re-encrypted under the ephemeral key from the attestation
    /// document (for RSAES_OAEP_SHA_256) or the raw plaintext (debug mode).
    pub async fn decrypt_with_attestation(
        &self,
        ciphertext: &[u8],
        attestation_document: Vec<u8>,
    ) -> Result<Vec<u8>> {
        info!(
            ciphertext_len = ciphertext.len(),
            attestation_len = attestation_document.len(),
            "Decrypting with attestation"
        );

        // Create recipient info with the attestation document
        let recipient = RecipientInfo::builder()
            .attestation_document(Blob::new(attestation_document))
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .build();

        let response = self
            .client
            .decrypt()
            .key_id(&self.key_id)
            .ciphertext_blob(Blob::new(ciphertext))
            .recipient(recipient)
            .send()
            .await
            .map_err(|e| EnclaveError::Kms(format!("Decrypt with attestation failed: {}", e)))?;

        // When using Recipient, KMS returns the plaintext in CiphertextForRecipient
        // (encrypted with the public key from the attestation document)
        // The enclave then decrypts this with its private key from NSM
        if let Some(ciphertext_for_recipient) = response.ciphertext_for_recipient() {
            debug!(
                recipient_ciphertext_len = ciphertext_for_recipient.as_ref().len(),
                "Received ciphertext for recipient (requires local decryption)"
            );
            // In a real implementation, we'd decrypt this with the NSM's private key
            // For now, return as-is for the caller to handle
            Ok(ciphertext_for_recipient.as_ref().to_vec())
        } else if let Some(plaintext) = response.plaintext() {
            // This happens in debug mode (PCR0 = all zeros) where KMS returns plaintext directly
            debug!(plaintext_len = plaintext.as_ref().len(), "Received plaintext directly (debug mode)");
            Ok(plaintext.as_ref().to_vec())
        } else {
            Err(EnclaveError::Kms(
                "No plaintext or ciphertext_for_recipient in response".to_string(),
            ))
        }
    }

    /// Generates a data key for envelope encryption
    ///
    /// Returns both the plaintext key (for use in the enclave) and the encrypted key
    /// (for storage). The encrypted key can only be decrypted inside the enclave.
    pub async fn generate_data_key(
        &self,
        attestation_document: Vec<u8>,
    ) -> Result<DataKey> {
        info!("Generating data key with attestation");

        let recipient = RecipientInfo::builder()
            .attestation_document(Blob::new(attestation_document))
            .key_encryption_algorithm(KeyEncryptionMechanism::RsaesOaepSha256)
            .build();

        let response = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
            .recipient(recipient)
            .send()
            .await
            .map_err(|e| EnclaveError::Kms(format!("GenerateDataKey failed: {}", e)))?;

        let ciphertext_blob = response
            .ciphertext_blob()
            .ok_or_else(|| EnclaveError::Kms("No ciphertext_blob in response".to_string()))?;

        // The plaintext is either in ciphertext_for_recipient (prod) or plaintext (debug)
        let plaintext_for_enclave = if let Some(cfr) = response.ciphertext_for_recipient() {
            cfr.as_ref().to_vec()
        } else if let Some(pt) = response.plaintext() {
            pt.as_ref().to_vec()
        } else {
            return Err(EnclaveError::Kms(
                "No plaintext data in GenerateDataKey response".to_string(),
            ));
        };

        Ok(DataKey {
            plaintext: plaintext_for_enclave,
            ciphertext: ciphertext_blob.as_ref().to_vec(),
        })
    }
}

/// A data encryption key for envelope encryption
#[derive(Debug, Clone)]
pub struct DataKey {
    /// Plaintext key (or ciphertext for recipient in prod mode)
    pub plaintext: Vec<u8>,
    /// Encrypted key blob (for storage)
    pub ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kms_recipient_serialization() {
        let recipient = KmsRecipient {
            attestation_document: vec![1, 2, 3],
            key_encryption_algorithm: "RSAES_OAEP_SHA_256".to_string(),
        };
        let json = serde_json::to_string(&recipient).unwrap();
        assert!(json.contains("attestation_document"));
    }
}

