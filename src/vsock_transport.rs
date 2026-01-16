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
pub const VSOCK_PORT_IMDS: u32 = 8002;

/// Configuration for vsock-based AWS connectivity
#[derive(Debug, Clone)]
pub struct VsockConfig {
    /// vsock port for KMS service
    pub kms_port: u32,
    /// vsock port for DynamoDB service
    pub dynamodb_port: u32,
    /// vsock port for EC2 Instance Metadata Service (IMDS)
    pub imds_port: u32,
    /// AWS region
    pub region: String,
}

impl Default for VsockConfig {
    fn default() -> Self {
        Self {
            kms_port: VSOCK_PORT_KMS,
            dynamodb_port: VSOCK_PORT_DYNAMODB,
            imds_port: VSOCK_PORT_IMDS,
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
        } else if endpoint.contains("169.254.169.254") {
            self.imds_port
        } else {
            tracing::warn!(
                endpoint = %endpoint,
                "Unknown endpoint, defaulting to IMDS port. \
                 Add explicit port mapping if this is unexpected."
            );
            self.imds_port
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
    use std::time::Instant;

    let start = Instant::now();
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

    tracing::info!(
        method = %method_str,
        host = %host,
        vsock_cid = VSOCK_CID_HOST,
        vsock_port = port,
        "[VSOCK] Step 1: Initiating connection to vsock-proxy"
    );

    // Connect via vsock to the parent instance
    let vsock_addr = VsockAddr::new(VSOCK_CID_HOST, port);
    let stream = VsockStream::connect(vsock_addr)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                host = %host,
                vsock_cid = VSOCK_CID_HOST,
                vsock_port = port,
                elapsed_ms = start.elapsed().as_millis(),
                "[VSOCK] FAILED at Step 1: Cannot connect to vsock. \
                 Ensure vsock-proxy is running on parent: \
                 vsock-proxy {} {}.{}.amazonaws.com 443",
                port,
                if host.contains("kms") { "kms" } 
                else if host.contains("dynamodb") { "dynamodb" }
                else { "sts" },
                config.region
            );
            ConnectorError::io(e.into())
        })?;

    tracing::info!(
        elapsed_ms = start.elapsed().as_millis(),
        "[VSOCK] Step 2: vsock connected, starting HTTP handshake"
    );

    let io = TokioIo::new(stream);

    // Create HTTP/1.1 connection
    let (mut sender, conn) = Builder::new()
        .handshake(io)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                host = %host,
                elapsed_ms = start.elapsed().as_millis(),
                "[VSOCK] FAILED at Step 2: HTTP handshake failed. \
                 vsock-proxy may not be forwarding correctly to AWS"
            );
            ConnectorError::other(e.into(), None)
        })?;

    tracing::info!(
        elapsed_ms = start.elapsed().as_millis(),
        "[VSOCK] Step 3: HTTP handshake complete, spawning connection handler"
    );

    // Spawn connection handler
    let host_for_spawn = host.to_string();
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::error!(
                error = %e, 
                host = %host_for_spawn,
                "[VSOCK] Connection handler error"
            );
        }
    });

    // Convert the SDK request to hyper request
    let req_parts = request.into_parts();
    
    // Read the body - bytes() returns Option<&[u8]>, not a future
    let body_bytes: Vec<u8> = req_parts.body
        .bytes()
        .map(|b| b.to_vec())
        .unwrap_or_default();

    tracing::info!(
        method = %method_str,
        uri = %uri_for_request,
        body_len = body_bytes.len(),
        header_count = req_parts.headers.len(),
        "[VSOCK] Step 4: Building HTTP request"
    );

    // Build a new hyper request with the body
    let mut hyper_request = hyper::Request::builder()
        .method(method_str.as_str())
        .uri(&uri_for_request);
    
    for (name, value) in req_parts.headers.iter() {
        hyper_request = hyper_request.header(name.to_string(), value.as_bytes());
    }
    
    let hyper_request = hyper_request
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "[VSOCK] FAILED at Step 4: Failed to build HTTP request"
            );
            ConnectorError::other(e.into(), None)
        })?;

    tracing::info!(
        elapsed_ms = start.elapsed().as_millis(),
        "[VSOCK] Step 5: Sending HTTP request..."
    );

    // Send request
    let response = sender
        .send_request(hyper_request)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                uri = %uri_for_request,
                elapsed_ms = start.elapsed().as_millis(),
                "[VSOCK] FAILED at Step 5: HTTP request failed. \
                 Check if vsock-proxy can reach AWS endpoint"
            );
            ConnectorError::other(e.into(), None)
        })?;

    // Convert response back to SDK format
    let (parts, body) = response.into_parts();
    
    tracing::info!(
        status = parts.status.as_u16(),
        elapsed_ms = start.elapsed().as_millis(),
        "[VSOCK] Step 6: Received HTTP response, reading body..."
    );
    
    let body_bytes = body
        .collect()
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "[VSOCK] FAILED at Step 6: Failed to read response body"
            );
            ConnectorError::other(e.into(), None)
        })?
        .to_bytes();

    let status_code = SmithyStatusCode::try_from(parts.status.as_u16())
        .map_err(|e| ConnectorError::other(e.into(), None))?;

    // Log response details (truncate body for logging)
    let body_preview = if body_bytes.len() > 200 {
        format!("{}... ({} bytes total)", 
            String::from_utf8_lossy(&body_bytes[..200]), 
            body_bytes.len())
    } else {
        String::from_utf8_lossy(&body_bytes).to_string()
    };

    tracing::info!(
        status = status_code.as_u16(),
        body_len = body_bytes.len(),
        body_preview = %body_preview,
        elapsed_ms = start.elapsed().as_millis(),
        header_count = parts.headers.len(),
        "[VSOCK] Step 7: Request complete!"
    );

    // Build SDK response with headers preserved from the upstream response
    // This is critical for IMDS which requires the x-aws-ec2-metadata-token-ttl-seconds header
    let mut sdk_response = aws_smithy_runtime_api::client::orchestrator::HttpResponse::new(
        status_code,
        SdkBody::from(body_bytes),
    );

    // Copy all response headers from the upstream response
    // This is critical for IMDS which requires the x-aws-ec2-metadata-token-ttl-seconds header
    for (name, value) in parts.headers.iter() {
        // Log the TTL header specifically as it's required by the AWS SDK for IMDS
        if name.as_str().eq_ignore_ascii_case("x-aws-ec2-metadata-token-ttl-seconds") {
            tracing::debug!(
                header_name = %name,
                header_value = %String::from_utf8_lossy(value.as_bytes()),
                "[VSOCK] Found IMDS TTL header"
            );
        }

        // Convert header value to string - Headers::insert accepts String which implements AsHeaderComponent
        if let Ok(header_value_str) = value.to_str() {
            sdk_response.headers_mut().insert(
                name.as_str().to_string(),
                header_value_str.to_string(),
            );
        } else {
            tracing::warn!(
                header_name = %name,
                "[VSOCK] Failed to convert response header value to string (non-UTF8)"
            );
        }
    }

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

