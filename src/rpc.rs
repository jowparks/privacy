//! JSON-RPC handler for the enclave server
//!
//! This module provides a JSON-RPC interface for the privacy enclave.
//! Method names use the "priv" namespace prefix.
//!
//! ## Supported Methods
//!
//! - `priv_signerPublicKey`: Returns the enclave's public signing key
//! - `priv_signerAttestation`: Returns an attestation document for the signer key
//! - `priv_decryptionPublicKey`: Returns the enclave's decryption public key
//! - `priv_decryptionAttestation`: Returns an attestation for the decryption key
//! - `priv_setSignerKey`: Sets the signer key (encrypted)
//! - `priv_sign`: Signs a message with the enclave's signing key

use crate::enclave::EnclaveServer;
use crate::error::{EnclaveError, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};

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

/// RPC handler for the enclave
pub struct RpcHandler {
    enclave: Arc<EnclaveServer>,
}

impl RpcHandler {
    /// Creates a new RPC handler
    pub fn new(enclave: Arc<EnclaveServer>) -> Self {
        Self { enclave }
    }

    /// Handles an incoming JSON-RPC request
    pub fn handle(&self, request_body: &[u8]) -> Vec<u8> {
        let response = match serde_json::from_slice::<RpcRequest>(request_body) {
            Ok(request) => self.process_request(request),
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
    fn process_request(&self, request: RpcRequest) -> RpcResponse {
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
            // Privacy enclave methods
            "priv_signerPublicKey" => self.handle_signer_public_key(),
            "priv_signerAttestation" => self.handle_signer_attestation(),
            "priv_decryptionPublicKey" => self.handle_decryption_public_key(),
            "priv_decryptionAttestation" => self.handle_decryption_attestation(),
            "priv_setSignerKey" => self.handle_set_signer_key(request.params),
            "priv_sign" => self.handle_sign(request.params),

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_handler() -> RpcHandler {
        let enclave = Arc::new(EnclaveServer::new().expect("Failed to create enclave"));
        RpcHandler::new(enclave)
    }

    #[test]
    fn test_signer_public_key() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"priv_signerPublicKey","id":1}"#;
        let response = handler.handle(request);
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let key = result.as_str().unwrap();
        assert!(key.starts_with("0x"));
    }

    #[test]
    fn test_signer_attestation() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"priv_signerAttestation","id":1}"#;
        let response = handler.handle(request);
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let attestation = result.as_str().unwrap();
        assert!(attestation.starts_with("0x"));
    }

    #[test]
    fn test_sign() {
        let handler = create_handler();
        // Sign hex-encoded "hello"
        let request = br#"{"jsonrpc":"2.0","method":"priv_sign","params":[{"message":"0x68656c6c6f"}],"id":1}"#;
        let response = handler.handle(request);
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_none());
        let result = parsed.result.unwrap();
        let sig = result.as_str().unwrap();
        assert!(sig.starts_with("0x"));
    }

    #[test]
    fn test_method_not_found() {
        let handler = create_handler();
        let request = br#"{"jsonrpc":"2.0","method":"unknown","id":1}"#;
        let response = handler.handle(request);
        let parsed: RpcResponse = serde_json::from_slice(&response).unwrap();
        assert!(parsed.error.is_some());
        assert_eq!(parsed.error.unwrap().code, METHOD_NOT_FOUND);
    }
}
