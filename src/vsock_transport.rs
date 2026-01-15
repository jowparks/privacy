//! Vsock transport for AWS SDK
//!
//! This module provides a custom HTTP connector that routes AWS SDK requests
//! through vsock to the parent EC2 instance, which runs vsock-proxy to forward
//! to actual AWS services.
//!
//! Architecture:
//! ```text
//! ┌─────────────────┐         ┌─────────────────┐         ┌─────────────────┐
//! │  Enclave        │ vsock   │  Parent EC2     │ HTTPS   │  AWS Services   │
//! │  (this code)    │────────▶│  (vsock-proxy)  │────────▶│  KMS, DynamoDB  │
//! └─────────────────┘         └─────────────────┘         └─────────────────┘
//! ```

use aws_smithy_runtime_api::client::connector_metadata::ConnectorMetadata;
use aws_smithy_runtime_api::client::http::{
    HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::client::result::ConnectorError;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
#[cfg(target_os = "linux")]
use aws_smithy_runtime_api::http::StatusCode as SmithyStatusCode;
#[cfg(target_os = "linux")]
use aws_smithy_types::body::SdkBody;

/// CID for the parent/host instance in vsock
pub const VSOCK_CID_HOST: u32 = 3;

/// Default vsock ports for AWS services (must match vsock-proxy config on parent)
pub const VSOCK_PORT_KMS: u32 = 8000;
pub const VSOCK_PORT_DYNAMODB: u32 = 8001;

/// Configuration for vsock-based AWS connectivity
#[derive(Debug, Clone)]
pub struct VsockConfig {
    /// vsock port for KMS service
    pub kms_port: u32,
    /// vsock port for DynamoDB service
    pub dynamodb_port: u32,
    /// AWS region
    pub region: String,
}

impl Default for VsockConfig {
    fn default() -> Self {
        Self {
            kms_port: VSOCK_PORT_KMS,
            dynamodb_port: VSOCK_PORT_DYNAMODB,
            region: "us-east-1".to_string(),
        }
    }
}

impl VsockConfig {
    /// Creates a new vsock config with the specified region
    pub fn new(region: impl Into<String>) -> Self {
        Self {
            region: region.into(),
            ..Default::default()
        }
    }

    /// Gets the vsock port for a given AWS service endpoint
    pub fn port_for_endpoint(&self, endpoint: &str) -> u32 {
        if endpoint.contains("kms.") {
            self.kms_port
        } else if endpoint.contains("dynamodb.") {
            self.dynamodb_port
        } else {
            // Default to KMS port for unknown endpoints
            self.kms_port
        }
    }
}

/// A vsock-based HTTP connector for the AWS SDK
///
/// This connector routes HTTP requests through vsock to the parent instance,
/// where vsock-proxy forwards them to the actual AWS endpoints.
#[derive(Debug, Clone)]
pub struct VsockHttpConnector {
    config: VsockConfig,
}

impl VsockHttpConnector {
    /// Creates a new vsock HTTP connector
    pub fn new(config: VsockConfig) -> Self {
        Self { config }
    }
}

impl HttpConnector for VsockHttpConnector {
    fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
        let config = self.config.clone();
        HttpConnectorFuture::new(async move {
            vsock_send_request(request, &config).await
        })
    }
}

impl HttpClient for VsockHttpConnector {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        SharedHttpConnector::new(self.clone())
    }

    fn connector_metadata(&self) -> Option<ConnectorMetadata> {
        Some(ConnectorMetadata::new("vsock-connector", None))
    }
}

/// Sends an HTTP request over vsock
#[cfg(target_os = "linux")]
async fn vsock_send_request(
    request: HttpRequest,
    config: &VsockConfig,
) -> Result<aws_smithy_runtime_api::client::orchestrator::HttpResponse, ConnectorError> {
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::client::conn::http1::Builder;
    use hyper_util::rt::TokioIo;
    use tokio_vsock::{VsockAddr, VsockStream};

    let uri_string = format!("{}", request.uri());
    let host = uri_string.split("://")
        .nth(1)
        .and_then(|s| s.split('/').next())
        .and_then(|s| s.split(':').next())
        .unwrap_or("localhost");
    let port = config.port_for_endpoint(host);

    // Get the method and URI before consuming the request
    let method_str = request.method().to_string();
    let uri_for_request = request.uri().to_string();

    // Connect via vsock to the parent instance
    let vsock_addr = VsockAddr::new(VSOCK_CID_HOST, port);
    let stream = VsockStream::connect(vsock_addr)
        .await
        .map_err(|e| ConnectorError::io(e.into()))?;

    let io = TokioIo::new(stream);

    // Create HTTP/1.1 connection
    let (mut sender, conn) = Builder::new()
        .handshake(io)
        .await
        .map_err(|e| ConnectorError::other(e.into(), None))?;

    // Spawn connection handler
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!(error = %e, "vsock connection error");
        }
    });

    // Convert the SDK request to hyper request
    let req_parts = request.into_parts();
    
    // Read the body - bytes() returns Option<&[u8]>, not a future
    let body_bytes: Vec<u8> = req_parts.body
        .bytes()
        .map(|b| b.to_vec())
        .unwrap_or_default();

    // Build a new hyper request with the body
    let mut hyper_request = hyper::Request::builder()
        .method(method_str.as_str())
        .uri(&uri_for_request);
    
    for (name, value) in req_parts.headers.iter() {
        hyper_request = hyper_request.header(name.to_string(), value.as_bytes());
    }
    
    let hyper_request = hyper_request
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| ConnectorError::other(e.into(), None))?;

    // Send request
    let response = sender
        .send_request(hyper_request)
        .await
        .map_err(|e| ConnectorError::other(e.into(), None))?;

    // Convert response back to SDK format
    let (parts, body) = response.into_parts();
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| ConnectorError::other(e.into(), None))?
        .to_bytes();

    let status_code = SmithyStatusCode::try_from(parts.status.as_u16())
        .map_err(|e| ConnectorError::other(e.into(), None))?;

    let sdk_response = aws_smithy_runtime_api::client::orchestrator::HttpResponse::new(
        status_code,
        SdkBody::from(body_bytes),
    );

    Ok(sdk_response)
}

/// Fallback for non-Linux platforms (development mode)
/// Returns an error since vsock is not available
#[cfg(not(target_os = "linux"))]
async fn vsock_send_request(
    _request: HttpRequest,
    _config: &VsockConfig,
) -> Result<aws_smithy_runtime_api::client::orchestrator::HttpResponse, ConnectorError> {
    // In development mode without vsock, we can't connect to AWS services
    // The caller should use the regular AWS SDK HTTP client for local development
    Err(ConnectorError::other(
        "vsock transport is only available on Linux inside a Nitro enclave. \
         For local development, use the default AWS SDK HTTP client."
            .into(),
        None,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_port_for_endpoint() {
        let config = VsockConfig::default();
        
        assert_eq!(config.port_for_endpoint("kms.us-east-1.amazonaws.com"), VSOCK_PORT_KMS);
        assert_eq!(config.port_for_endpoint("dynamodb.us-east-1.amazonaws.com"), VSOCK_PORT_DYNAMODB);
    }
}

