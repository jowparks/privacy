//! AWS client initialization for Nitro Enclave
//!
//! This module provides initialization of AWS SDK clients (KMS, DynamoDB) that work
//! inside a Nitro enclave via vsock transport.
//!
//! ## Setup on Parent EC2 Instance
//!
//! The parent instance must run vsock-proxy to forward enclave traffic:
//!
//! ```bash
//! # KMS proxy (port 8000)
//! vsock-proxy 8000 kms.us-east-1.amazonaws.com 443 &
//!
//! # DynamoDB proxy (port 8001)
//! vsock-proxy 8001 dynamodb.us-east-1.amazonaws.com 443 &
//!
//! # Credentials proxy (port 8002) - for instance metadata
//! vsock-proxy 8002 169.254.169.254 80 &
//! ```

use crate::dynamodb::EnclaveStorage;
use crate::error::{EnclaveError, Result};
use crate::kms::EnclaveKms;
use crate::vsock_transport::{VsockConfig, VsockHttpConnector};
use aws_config::Region;
use aws_sdk_dynamodb::Client as DynamoClient;
use aws_sdk_kms::Client as KmsClient;
use tracing::info;

/// Configuration for AWS services in the enclave
#[derive(Debug, Clone)]
pub struct AwsEnclaveConfig {
    /// AWS region
    pub region: String,
    /// KMS key ID or ARN for enclave-sealed encryption
    pub kms_key_id: String,
    /// DynamoDB table name for encrypted storage
    pub dynamodb_table: String,
    /// Vsock configuration
    pub vsock: VsockConfig,
}

impl AwsEnclaveConfig {
    /// Creates a new AWS enclave configuration
    pub fn new(
        region: impl Into<String>,
        kms_key_id: impl Into<String>,
        dynamodb_table: impl Into<String>,
    ) -> Self {
        let region = region.into();
        Self {
            vsock: VsockConfig::new(&region),
            region,
            kms_key_id: kms_key_id.into(),
            dynamodb_table: dynamodb_table.into(),
        }
    }

    /// Creates configuration from environment variables
    ///
    /// Expected environment variables:
    /// - `AWS_REGION`: AWS region (default: us-east-1)
    /// - `KMS_KEY_ID`: KMS key ID or ARN
    /// - `DYNAMODB_TABLE`: DynamoDB table name
    pub fn from_env() -> Result<Self> {
        let region = std::env::var("AWS_REGION").unwrap_or_else(|_| "us-east-1".to_string());
        let kms_key_id = std::env::var("KMS_KEY_ID")
            .map_err(|_| EnclaveError::Config("KMS_KEY_ID environment variable not set".into()))?;
        let dynamodb_table = std::env::var("DYNAMODB_TABLE")
            .map_err(|_| EnclaveError::Config("DYNAMODB_TABLE environment variable not set".into()))?;

        Ok(Self::new(region, kms_key_id, dynamodb_table))
    }
}

/// AWS clients for the enclave
pub struct AwsClients {
    /// KMS client for encryption/decryption with attestation
    pub kms: EnclaveKms,
    /// DynamoDB client for encrypted storage
    pub storage: EnclaveStorage,
    /// Configuration
    pub config: AwsEnclaveConfig,
}

impl AwsClients {
    /// Initializes AWS clients for enclave use
    ///
    /// This sets up KMS and DynamoDB clients that route through vsock
    /// to the parent instance's vsock-proxy.
    pub async fn new(config: AwsEnclaveConfig) -> Result<Self> {
        info!(
            region = %config.region,
            kms_key = %config.kms_key_id,
            table = %config.dynamodb_table,
            "Initializing AWS clients for enclave"
        );

        // Create vsock-based HTTP connector
        let vsock_connector = VsockHttpConnector::new(config.vsock.clone());

        // Build AWS SDK config with custom HTTP client
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .http_client(vsock_connector)
            .load()
            .await;

        // Initialize KMS client
        let kms_client = KmsClient::new(&sdk_config);
        let kms = EnclaveKms::new(kms_client, &config.kms_key_id);

        // Initialize DynamoDB client
        let dynamo_client = DynamoClient::new(&sdk_config);
        let storage = EnclaveStorage::new(dynamo_client, &config.dynamodb_table);

        info!("AWS clients initialized successfully");

        Ok(Self {
            kms,
            storage,
            config,
        })
    }

    /// Creates clients with mock/local configuration for development
    ///
    /// In development mode, this creates clients that connect directly
    /// (not via vsock) for local testing with LocalStack or similar.
    #[cfg(not(target_os = "linux"))]
    pub async fn new_local(config: AwsEnclaveConfig) -> Result<Self> {
        use aws_config::Region;

        info!(
            region = %config.region,
            kms_key = %config.kms_key_id,
            table = %config.dynamodb_table,
            "Initializing local AWS clients (development mode)"
        );

        // Use default HTTP client for local development
        let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .load()
            .await;

        let kms_client = KmsClient::new(&sdk_config);
        let kms = EnclaveKms::new(kms_client, &config.kms_key_id);

        let dynamo_client = DynamoClient::new(&sdk_config);
        let storage = EnclaveStorage::new(dynamo_client, &config.dynamodb_table);

        info!("Local AWS clients initialized (development mode)");

        Ok(Self {
            kms,
            storage,
            config,
        })
    }
}

/// Encrypted key storage operations combining KMS + DynamoDB
impl AwsClients {
    /// Stores an encrypted key with a given identifier
    ///
    /// The key is encrypted with KMS before being stored in DynamoDB.
    /// Only the enclave can decrypt it later.
    pub async fn store_encrypted_key(
        &self,
        key_id: &str,
        key_type: &str,
        plaintext_key: &[u8],
    ) -> Result<()> {
        use crate::dynamodb::EncryptedRecord;
        use std::collections::HashMap;

        info!(key_id = %key_id, key_type = %key_type, "Storing encrypted key");

        // Encrypt the key with KMS
        let encrypted_key = self.kms.encrypt(plaintext_key).await?;

        // Store in DynamoDB
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), key_type.to_string());

        let record = EncryptedRecord::new(
            format!("KEY#{}", key_id),
            "v0".to_string(),
            encrypted_key,
        )
        .with_metadata(metadata);

        self.storage.put(&record).await?;

        info!(key_id = %key_id, "Encrypted key stored successfully");
        Ok(())
    }

    /// Retrieves and decrypts a key using attestation
    ///
    /// This can only succeed inside the enclave with matching PCR values.
    pub async fn get_decrypted_key(
        &self,
        key_id: &str,
        attestation_document: Vec<u8>,
    ) -> Result<Option<Vec<u8>>> {
        info!(key_id = %key_id, "Retrieving encrypted key");

        // Get from DynamoDB
        let pk = format!("KEY#{}", key_id);
        let record = match self.storage.get(&pk, "v0").await? {
            Some(r) => r,
            None => return Ok(None),
        };

        // Decrypt with KMS using attestation
        let plaintext = self
            .kms
            .decrypt_with_attestation(&record.data, attestation_document)
            .await?;

        info!(key_id = %key_id, "Key decrypted successfully");
        Ok(Some(plaintext))
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_new() {
        let config = AwsEnclaveConfig::new(
            "us-west-2",
            "arn:aws:kms:us-west-2:123456789:key/abc",
            "my-table",
        );
        assert_eq!(config.region, "us-west-2");
        assert!(config.kms_key_id.contains("abc"));
        assert_eq!(config.dynamodb_table, "my-table");
    }
}

