//! Privacy Enclave - A privacy-preserving service for AWS Nitro Enclaves
//!
//! This library provides the core enclave server functionality, including:
//! - NSM (Nitro Secure Module) integration for attestation
//! - Cryptographic key generation using enclave's secure random
//! - JSON-RPC handlers for enclave operations
//! - KMS integration with attestation-based decryption
//! - DynamoDB storage for encrypted data
//!
//! ## Architecture
//!
//! The enclave communicates with AWS services via vsock to the parent EC2 instance,
//! which runs vsock-proxy to forward requests to actual AWS endpoints:
//!
//! ```text
//! ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
//! │  Nitro Enclave  │ vsock   │  Parent EC2     │ HTTPS   │  AWS Services   │
//! │  (this code)    │────────▶│  (vsock-proxy)  │────────▶│  KMS, DynamoDB  │
//! └─────────────────┘         └─────────────────┘         └─────────────────┘
//! ```
//!
//! ## Security Model
//!
//! - All sensitive data is encrypted with a KMS key sealed to the enclave
//! - KMS decrypt operations require attestation with matching PCR values
//! - DynamoDB stores only encrypted blobs - the enclave handles all crypto

pub mod aws;
pub mod dynamodb;
pub mod enclave;
pub mod error;
pub mod kms;
pub mod rpc;
pub mod vsock_transport;

