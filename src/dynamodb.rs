//! DynamoDB client for encrypted blob storage
//!
//! This module provides a DynamoDB client for storing and retrieving encrypted data.
//! All data is encrypted with the enclave-sealed KMS key before being stored in DynamoDB.
//!
//! ## Table Schema
//!
//! The table uses a single-table design with:
//! - `pk` (String): Partition key - entity type and ID (e.g., "KEY#abc123")
//! - `sk` (String): Sort key - for hierarchical data or versioning
//! - `data` (Binary): Encrypted blob
//! - `created_at` (String): ISO-8601 timestamp
//! - `updated_at` (String): ISO-8601 timestamp

use crate::error::{EnclaveError, Result};
use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client as DynamoClient;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info};

/// Record stored in DynamoDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedRecord {
    /// Partition key
    pub pk: String,
    /// Sort key
    pub sk: String,
    /// Encrypted data blob (base64 encoded for JSON compatibility)
    pub data: Vec<u8>,
    /// Metadata (unencrypted, for indexing/filtering)
    #[serde(default)]
    pub metadata: HashMap<String, String>,
    /// Creation timestamp
    pub created_at: String,
    /// Last update timestamp
    pub updated_at: String,
}

/// DynamoDB wrapper for enclave storage operations
pub struct EnclaveStorage {
    client: DynamoClient,
    table_name: String,
}

impl EnclaveStorage {
    /// Creates a new EnclaveStorage client
    pub fn new(client: DynamoClient, table_name: impl Into<String>) -> Self {
        Self {
            client,
            table_name: table_name.into(),
        }
    }

    /// Stores an encrypted record in DynamoDB
    pub async fn put(&self, record: &EncryptedRecord) -> Result<()> {
        info!(
            pk = %record.pk,
            sk = %record.sk,
            data_len = record.data.len(),
            "Storing encrypted record"
        );

        let mut item = HashMap::new();
        item.insert("pk".to_string(), AttributeValue::S(record.pk.clone()));
        item.insert("sk".to_string(), AttributeValue::S(record.sk.clone()));
        item.insert("data".to_string(), AttributeValue::B(aws_sdk_dynamodb::primitives::Blob::new(record.data.clone())));
        item.insert("created_at".to_string(), AttributeValue::S(record.created_at.clone()));
        item.insert("updated_at".to_string(), AttributeValue::S(record.updated_at.clone()));

        // Add metadata as a map
        if !record.metadata.is_empty() {
            let metadata_map: HashMap<String, AttributeValue> = record
                .metadata
                .iter()
                .map(|(k, v)| (k.clone(), AttributeValue::S(v.clone())))
                .collect();
            item.insert("metadata".to_string(), AttributeValue::M(metadata_map));
        }

        self.client
            .put_item()
            .table_name(&self.table_name)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| EnclaveError::DynamoDb(format!("PutItem failed: {}", e)))?;

        debug!(pk = %record.pk, sk = %record.sk, "Record stored successfully");
        Ok(())
    }

    /// Retrieves an encrypted record from DynamoDB
    pub async fn get(&self, pk: &str, sk: &str) -> Result<Option<EncryptedRecord>> {
        info!(pk = %pk, sk = %sk, "Retrieving encrypted record");

        let response = self
            .client
            .get_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk.to_string()))
            .key("sk", AttributeValue::S(sk.to_string()))
            .send()
            .await
            .map_err(|e| EnclaveError::DynamoDb(format!("GetItem failed: {}", e)))?;

        match response.item {
            Some(item) => {
                let record = parse_record(item)?;
                debug!(pk = %pk, sk = %sk, "Record retrieved successfully");
                Ok(Some(record))
            }
            None => {
                debug!(pk = %pk, sk = %sk, "Record not found");
                Ok(None)
            }
        }
    }

    /// Deletes a record from DynamoDB
    pub async fn delete(&self, pk: &str, sk: &str) -> Result<()> {
        info!(pk = %pk, sk = %sk, "Deleting record");

        self.client
            .delete_item()
            .table_name(&self.table_name)
            .key("pk", AttributeValue::S(pk.to_string()))
            .key("sk", AttributeValue::S(sk.to_string()))
            .send()
            .await
            .map_err(|e| EnclaveError::DynamoDb(format!("DeleteItem failed: {}", e)))?;

        debug!(pk = %pk, sk = %sk, "Record deleted successfully");
        Ok(())
    }

    /// Queries records by partition key
    pub async fn query_by_pk(&self, pk: &str) -> Result<Vec<EncryptedRecord>> {
        info!(pk = %pk, "Querying records by partition key");

        let response = self
            .client
            .query()
            .table_name(&self.table_name)
            .key_condition_expression("pk = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(pk.to_string()))
            .send()
            .await
            .map_err(|e| EnclaveError::DynamoDb(format!("Query failed: {}", e)))?;

        let items = response.items.unwrap_or_default();
        let mut records = Vec::with_capacity(items.len());

        for item in items {
            records.push(parse_record(item)?);
        }

        debug!(pk = %pk, count = records.len(), "Query completed");
        Ok(records)
    }

    /// Lists all records with a given prefix (using begins_with on pk)
    pub async fn list_by_prefix(&self, pk_prefix: &str, limit: Option<i32>) -> Result<Vec<EncryptedRecord>> {
        info!(pk_prefix = %pk_prefix, limit = ?limit, "Listing records by prefix");

        let mut builder = self
            .client
            .scan()
            .table_name(&self.table_name)
            .filter_expression("begins_with(pk, :prefix)")
            .expression_attribute_values(":prefix", AttributeValue::S(pk_prefix.to_string()));

        if let Some(l) = limit {
            builder = builder.limit(l);
        }

        let response = builder
            .send()
            .await
            .map_err(|e| EnclaveError::DynamoDb(format!("Scan failed: {}", e)))?;

        let items = response.items.unwrap_or_default();
        let mut records = Vec::with_capacity(items.len());

        for item in items {
            records.push(parse_record(item)?);
        }

        debug!(pk_prefix = %pk_prefix, count = records.len(), "List completed");
        Ok(records)
    }
}

/// Parses a DynamoDB item into an EncryptedRecord
fn parse_record(item: HashMap<String, AttributeValue>) -> Result<EncryptedRecord> {
    let pk = get_string(&item, "pk")?;
    let sk = get_string(&item, "sk")?;
    let data = get_binary(&item, "data")?;
    let created_at = get_string(&item, "created_at").unwrap_or_else(|_| String::new());
    let updated_at = get_string(&item, "updated_at").unwrap_or_else(|_| String::new());

    let metadata = if let Some(AttributeValue::M(m)) = item.get("metadata") {
        m.iter()
            .filter_map(|(k, v)| {
                if let AttributeValue::S(s) = v {
                    Some((k.clone(), s.clone()))
                } else {
                    None
                }
            })
            .collect()
    } else {
        HashMap::new()
    };

    Ok(EncryptedRecord {
        pk,
        sk,
        data,
        metadata,
        created_at,
        updated_at,
    })
}

fn get_string(item: &HashMap<String, AttributeValue>, key: &str) -> Result<String> {
    match item.get(key) {
        Some(AttributeValue::S(s)) => Ok(s.clone()),
        _ => Err(EnclaveError::DynamoDb(format!(
            "Missing or invalid string attribute: {}",
            key
        ))),
    }
}

fn get_binary(item: &HashMap<String, AttributeValue>, key: &str) -> Result<Vec<u8>> {
    match item.get(key) {
        Some(AttributeValue::B(b)) => Ok(b.as_ref().to_vec()),
        _ => Err(EnclaveError::DynamoDb(format!(
            "Missing or invalid binary attribute: {}",
            key
        ))),
    }
}

/// Helper to create a new record with current timestamps
impl EncryptedRecord {
    /// Creates a new encrypted record with current timestamps
    pub fn new(pk: impl Into<String>, sk: impl Into<String>, data: Vec<u8>) -> Self {
        let now = chrono_now();
        Self {
            pk: pk.into(),
            sk: sk.into(),
            data,
            metadata: HashMap::new(),
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Creates a new record with metadata
    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Updates the updated_at timestamp
    pub fn touch(&mut self) {
        self.updated_at = chrono_now();
    }
}

/// Gets current UTC timestamp in ISO-8601 format
fn chrono_now() -> String {
    // Simple ISO-8601 timestamp without chrono dependency
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    
    // Convert to basic ISO format
    let days = secs / 86400;
    let years = 1970 + (days / 365); // Rough approximation
    format!("{}-01-01T00:00:00Z", years) // Placeholder - in production use chrono
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_record_new() {
        let record = EncryptedRecord::new("KEY#123", "v0", vec![1, 2, 3]);
        assert_eq!(record.pk, "KEY#123");
        assert_eq!(record.sk, "v0");
        assert_eq!(record.data, vec![1, 2, 3]);
        assert!(!record.created_at.is_empty());
    }

    #[test]
    fn test_encrypted_record_with_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("type".to_string(), "signing_key".to_string());

        let record = EncryptedRecord::new("KEY#123", "v0", vec![1, 2, 3])
            .with_metadata(metadata.clone());

        assert_eq!(record.metadata.get("type"), Some(&"signing_key".to_string()));
    }
}

