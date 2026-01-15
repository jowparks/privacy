//! JSON-RPC handler for the enclave server
//!
//! This module provides a JSON-RPC interface for the privacy enclave.
//! Method names use the "priv" namespace prefix.
//!
//! ## Supported Methods
//!
//! ### Key Management
//! - `priv_signerPublicKey`: Returns the enclave's public signing key
//! - `priv_signerAttestation`: Returns an attestation document for the signer key
//! - `priv_decryptionPublicKey`: Returns the enclave's decryption public key
//! - `priv_decryptionAttestation`: Returns an attestation for the decryption key
//! - `priv_setSignerKey`: Sets the signer key (encrypted)
//! - `priv_sign`: Signs a message with the enclave's signing key
//!
//! ### KMS Operations (attestation-sealed)
//! - `priv_encrypt`: Encrypts data with the enclave-sealed KMS key
//! - `priv_decrypt`: Decrypts data using attestation (enclave only)
//!
//! ### Storage Operations
//! - `priv_storeKey`: Stores an encrypted key in DynamoDB
//! - `priv_getKey`: Retrieves and decrypts a key from DynamoDB

use crate::aws::AwsClients;
use crate::enclave::EnclaveServer;
use crate::error::{EnclaveError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// JSON-RPC request structure
#[derive(Debug, Deserialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<serde_json::Value>,
    pub id: serde_json::Value,
}

/// JSON-RPC response structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: serde_json::Value,
}

/// JSON-RPC error structure
#[derive(Debug, Serialize, Deserialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

// RPC error codes
const PARSE_ERROR: i32 = -32700;
const INVALID_REQUEST: i32 = -32600;
const METHOD_NOT_FOUND: i32 = -32601;
const INTERNAL_ERROR: i32 = -32603;

/// Parameters for the sign method
#[derive(Debug, Deserialize)]
pub struct SignParams {
    /// Hex-encoded message to sign (with or without 0x prefix)
    pub message: String,
}

/// Parameters for encrypt method
#[derive(Debug, Deserialize)]
pub struct EncryptParams {
    /// Hex-encoded plaintext to encrypt (with or without 0x prefix)
    pub plaintext: String,
}

/// Parameters for decrypt method
#[derive(Debug, Deserialize)]
pub struct DecryptParams {
    /// Hex-encoded ciphertext to decrypt (with or without 0x prefix)
    pub ciphertext: String,
}

/// Parameters for storeKey method
#[derive(Debug, Deserialize)]
pub struct StoreKeyParams {
    /// Unique key identifier
    pub key_id: String,
    /// Key type (e.g., "signing", "encryption")
    pub key_type: String,
    /// Hex-encoded key data (with or without 0x prefix)
    pub key_data: String,
}

/// Parameters for getKey method
#[derive(Debug, Deserialize)]
pub struct GetKeyParams {
    /// Key identifier to retrieve
    pub key_id: String,
}


/// RPC handler for the enclave
pub struct RpcHandler {
    enclave: Arc<EnclaveServer>,
    aws_clients: Option<Arc<RwLock<AwsClients>>>,
}

impl RpcHandler {
    /// Creates a new RPC handler without AWS clients
    pub fn new(enclave: Arc<EnclaveServer>) -> Self {
        Self {
            enclave,
            aws_clients: None,
        }
    }

    /// Creates a new RPC handler with AWS clients
    pub fn with_aws(enclave: Arc<EnclaveServer>, aws_clients: Arc<RwLock<AwsClients>>) -> Self {
        Self {
            enclave,
            aws_clients: Some(aws_clients),
        }
    }

    /// Returns reference to AWS clients if configured
    fn aws(&self) -> Result<&Arc<RwLock<AwsClients>>> {
        self.aws_clients
            .as_ref()
            .ok_or_else(|| EnclaveError::Config("AWS clients not configured".to_string()))
    }

    /// Handles an incoming JSON-RPC request
    pub async fn handle(&self, request_body: &[u8]) -> Vec<u8> {
        let response = match serde_json::from_slice::<RpcRequest>(request_body) {
            Ok(request) => self.process_request(request).await,
            Err(e) => RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError {
                    code: PARSE_ERROR,
                    message: format!("Parse error: {}", e),
                }),
                id: serde_json::Value::Null,
            },
        };

        serde_json::to_vec(&response).unwrap_or_else(|_| {
            br#"{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"},"id":null}"#
                .to_vec()
        })
    }

    /// Processes a parsed RPC request
    async fn process_request(&self, request: RpcRequest) -> RpcResponse {
        debug!(method = %request.method, "Processing RPC request");

        if request.jsonrpc != "2.0" {
            return RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: None,
                error: Some(RpcError {
                    code: INVALID_REQUEST,
                    message: "Invalid JSON-RPC version".to_string(),
                }),
                id: request.id,
            };
        }

        let method = request.method.as_str();
        let result = match method {
            // Signing methods (sync)
            "priv_signerPublicKey" => self.handle_signer_public_key(),
            "priv_signerAttestation" => self.handle_signer_attestation(),
            "priv_decryptionPublicKey" => self.handle_decryption_public_key(),
            "priv_decryptionAttestation" => self.handle_decryption_attestation(),
            "priv_setSignerKey" => self.handle_set_signer_key(request.params),
            "priv_sign" => self.handle_sign(request.params),

            // KMS methods (async)
            "priv_encrypt" => self.handle_encrypt(request.params).await,
            "priv_decrypt" => self.handle_decrypt(request.params).await,

            // Storage methods (async)
            "priv_storeKey" => self.handle_store_key(request.params).await,
            "priv_getKey" => self.handle_get_key(request.params).await,

            _ => Err(EnclaveError::Rpc(format!(
                "Method not found: {}",
                request.method
            ))),
        };

        match result {
            Ok(value) => RpcResponse {
                jsonrpc: "2.0".to_string(),
                result: Some(value),
                error: None,
                id: request.id,
            },
            Err(e) => {
                let code = match &e {
                    EnclaveError::Rpc(msg) if msg.starts_with("Method not found") => {
                        METHOD_NOT_FOUND
                    }
                    _ => INTERNAL_ERROR,
                };
                RpcResponse {
                    jsonrpc: "2.0".to_string(),
                    result: None,
                    error: Some(RpcError {
                        code,
                        message: e.to_string(),
                    }),
                    id: request.id,
                }
            }
        }
    }

    /// Handles "priv_signerPublicKey" - returns hex-encoded public key
    fn handle_signer_public_key(&self) -> Result<serde_json::Value> {
        let public_key = format!("0x{}", self.enclave.public_key_hex());
        Ok(serde_json::Value::String(public_key))
    }

    /// Handles "priv_signerAttestation" - returns attestation document
    fn handle_signer_attestation(&self) -> Result<serde_json::Value> {
        let attestation = self.enclave.get_attestation(None)?;
        let doc_hex = format!("0x{}", hex::encode(&attestation.document));
        Ok(serde_json::Value::String(doc_hex))
    }

    /// Handles "priv_decryptionPublicKey" - returns decryption public key
    fn handle_decryption_public_key(&self) -> Result<serde_json::Value> {
        // For now, return the signing public key
        // TODO: Implement separate RSA decryption key
        warn!("decryptionPublicKey called - returning signing key");
        let public_key = format!("0x{}", self.enclave.public_key_hex());
        Ok(serde_json::Value::String(public_key))
    }

    /// Handles "priv_decryptionAttestation" - returns attestation for decryption key
    fn handle_decryption_attestation(&self) -> Result<serde_json::Value> {
        // Same as signer attestation for now
        warn!("decryptionAttestation called - returning signer attestation");
        self.handle_signer_attestation()
    }

    /// Handles "priv_setSignerKey" - sets the signer key from encrypted bytes
    fn handle_set_signer_key(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let _encrypted = params
            .and_then(|p| {
                if p.is_array() {
                    p.as_array().and_then(|arr| arr.first().cloned())
                } else {
                    Some(p)
                }
            })
            .and_then(|p| p.as_str().map(|s| s.to_string()))
            .ok_or_else(|| EnclaveError::Rpc("Missing encrypted key parameter".to_string()))?;

        // TODO: Implement actual key decryption and setting
        warn!("setSignerKey called - not yet implemented");
        
        Ok(serde_json::Value::Null)
    }

    /// Handles "priv_sign" - signs a message
    fn handle_sign(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let params: SignParams = params
            .and_then(|p| {
                if p.is_array() {
                    p.as_array().and_then(|arr| arr.first().cloned())
                } else {
                    Some(p)
                }
            })
            .ok_or_else(|| EnclaveError::Rpc("Missing params".to_string()))
            .and_then(|p| {
                serde_json::from_value(p)
                    .map_err(|e| EnclaveError::Rpc(format!("Invalid params: {}", e)))
            })?;

        let message_hex = params.message.strip_prefix("0x").unwrap_or(&params.message);
        let message = hex::decode(message_hex)
            .map_err(|e| EnclaveError::Rpc(format!("Invalid hex message: {}", e)))?;

        let signature = self.enclave.sign(&message)?;

        Ok(serde_json::Value::String(format!("0x{}", hex::encode(&signature))))
    }

    // ========================================================================
    // KMS Methods
    // ========================================================================

    /// Handles "priv_encrypt" - encrypts data with the enclave KMS key
    async fn handle_encrypt(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let params: EncryptParams = parse_params(params)?;
        let plaintext_hex = params.plaintext.strip_prefix("0x").unwrap_or(&params.plaintext);
        let plaintext = hex::decode(plaintext_hex)
            .map_err(|e| EnclaveError::Rpc(format!("Invalid hex plaintext: {}", e)))?;

        let aws = self.aws()?;
        let clients = aws.read().await;
        let ciphertext = clients.kms.encrypt(&plaintext).await?;

        Ok(serde_json::Value::String(format!("0x{}", hex::encode(&ciphertext))))
    }

    /// Handles "priv_decrypt" - decrypts data using attestation
    async fn handle_decrypt(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let params: DecryptParams = parse_params(params)?;
        let ciphertext_hex = params.ciphertext.strip_prefix("0x").unwrap_or(&params.ciphertext);
        let ciphertext = hex::decode(ciphertext_hex)
            .map_err(|e| EnclaveError::Rpc(format!("Invalid hex ciphertext: {}", e)))?;

        // Get attestation document from NSM
        let attestation = self.enclave.get_attestation(None)?;

        let aws = self.aws()?;
        let clients = aws.read().await;
        let plaintext = clients
            .kms
            .decrypt_with_attestation(&ciphertext, attestation.document)
            .await?;

        Ok(serde_json::Value::String(format!("0x{}", hex::encode(&plaintext))))
    }

    // ========================================================================
    // Storage Methods
    // ========================================================================

    /// Handles "priv_storeKey" - stores an encrypted key
    async fn handle_store_key(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let params: StoreKeyParams = parse_params(params)?;
        let key_data_hex = params.key_data.strip_prefix("0x").unwrap_or(&params.key_data);
        let key_data = hex::decode(key_data_hex)
            .map_err(|e| EnclaveError::Rpc(format!("Invalid hex key_data: {}", e)))?;

        info!(key_id = %params.key_id, key_type = %params.key_type, "Storing key via RPC");

        let aws = self.aws()?;
        let clients = aws.read().await;
        clients
            .store_encrypted_key(&params.key_id, &params.key_type, &key_data)
            .await?;

        Ok(serde_json::json!({
            "success": true,
            "key_id": params.key_id
        }))
    }

    /// Handles "priv_getKey" - retrieves and decrypts a key
    async fn handle_get_key(&self, params: Option<serde_json::Value>) -> Result<serde_json::Value> {
        let params: GetKeyParams = parse_params(params)?;

        info!(key_id = %params.key_id, "Getting key via RPC");

        // Get attestation for decryption
        let attestation = self.enclave.get_attestation(None)?;

        let aws = self.aws()?;
        let clients = aws.read().await;
        let key_data = clients
            .get_decrypted_key(&params.key_id, attestation.document)
            .await?;

        match key_data {
            Some(data) => Ok(serde_json::json!({
                "found": true,
                "key_id": params.key_id,
                "key_data": format!("0x{}", hex::encode(&data))
            })),
            None => Ok(serde_json::json!({
                "found": false,
                "key_id": params.key_id
            })),
        }
    }

}

/// Helper to parse RPC params
fn parse_params<T: serde::de::DeserializeOwned>(params: Option<serde_json::Value>) -> Result<T> {
    params
        .and_then(|p| {
            if p.is_array() {
                p.as_array().and_then(|arr| arr.first().cloned())
            } else {
                Some(p)
            }
        })
        .ok_or_else(|| EnclaveError::Rpc("Missing params".to_string()))
        .and_then(|p| {
            serde_json::from_value(p)
                .map_err(|e| EnclaveError::Rpc(format!("Invalid params: {}", e)))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_handler() -> RpcHandler {
        let enclave = Arc::new(EnclaveServer::new().expect("Failed to create enclave"));
        RpcHandler::new(enclave)
    }

    #[tokio::test]
    async fn test_signer_public_key() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"priv_signerPublicKey","id":1}"#;
        let response = handler.handle(request).await;
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let key = result.as_str().unwrap();
        assert!(key.starts_with("0x"));
    }

    #[tokio::test]
    async fn test_signer_attestation() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"priv_signerAttestation","id":1}"#;
        let response = handler.handle(request).await;
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let attestation = result.as_str().unwrap();
        assert!(attestation.starts_with("0x"));
    }

    #[tokio::test]
    async fn test_sign() {
        let handler = create_handler();
        // Sign hex-encoded "hello"
        let request = br#"{"jsonrpc":"2.0","method":"priv_sign","params":[{"message":"0x68656c6c6f"}],"id":1}"#;
        let response = handler.handle(request).await;
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let sig = result.as_str().unwrap();
        assert!(sig.starts_with("0x"));
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"unknown","id":1}"#;
        let response = handler.handle(request).await;
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn test_encrypt_without_aws_clients() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"priv_encrypt","params":[{"plaintext":"0x68656c6c6f"}],"id":1}"#;
        let response = handler.handle(request).await;
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        // Should fail because AWS clients not configured
        assert!(parsed.error.is_some());
        assert!(parsed.error.unwrap().message.contains("AWS clients not configured"));
    }

    #[test]
    fn test_parse_params() {
        // Test with object
        let params = Some(serde_json::json!({"key_id": "test"}));
        let parsed: GetKeyParams = parse_params(params).unwrap();
        assert_eq!(parsed.key_id, "test");

        // Test with array (common in JSON-RPC)
        let params = Some(serde_json::json!([{"key_id": "test2"}]));
        let parsed: GetKeyParams = parse_params(params).unwrap();
        assert_eq!(parsed.key_id, "test2");
    }
}
