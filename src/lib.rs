//! Privacy Enclave - A simple Hello World RPC service for AWS Nitro Enclaves
//!
//! This library provides the core enclave server functionality, including:
//! - NSM (Nitro Secure Module) integration for attestation
//! - Cryptographic key generation using enclave's secure random
//! - JSON-RPC handlers for enclave operations

pub mod enclave;
pub mod error;
pub mod rpc;

