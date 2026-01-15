//! Privacy Enclave Server
//!
//! A Rust enclave server for AWS Nitro Enclaves.
//!
//! This server listens on vsock port 1234 for raw JSON-RPC requests.
//!
//! # Modes
//!
//! - **vsock** (production): `USE_VSOCK=1` - Listens on vsock port 1234
//! - **raw RPC** (testing): `USE_RAW_RPC=1` - Listens on TCP for testing
//! - **HTTP** (development): Default - HTTP server for curl testing

use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use privacy_enclave::aws::{AwsClients, AwsEnclaveConfig};
use privacy_enclave::enclave::EnclaveServer;
use privacy_enclave::rpc::RpcHandler;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;

/// Default vsock port
const VSOCK_PORT: u32 = 1234;

/// Default HTTP port for development
const HTTP_PORT: u16 = 5000;

struct AppState {
    rpc_handler: RpcHandler,
}

async fn handle_http_request(
    state: Arc<AppState>,
    req: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::POST, "/rpc") | (&Method::POST, "/") => {
            match req.collect().await {
                Ok(body) => {
                    let body_bytes = body.to_bytes();
                    let response_bytes = state.rpc_handler.handle(&body_bytes).await;
                    Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(response_bytes)))
                        .unwrap()
                }
                Err(e) => {
                    error!("Failed to read request body: {}", e);
                    Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(Full::new(Bytes::from(format!(
                            r#"{{"error":"{}"}}"#,
                            e
                        ))))
                        .unwrap()
                }
            }
        }
        (&Method::GET, "/health") => Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(r#"{"status":"ok"}"#)))
            .unwrap(),
        _ => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(r#"{"error":"Not found"}"#)))
            .unwrap(),
    };

    Ok(response)
}

async fn run_http_server(state: Arc<AppState>, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(address = %addr, "HTTP server listening");

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let service = service_fn(move |req| handle_http_request(Arc::clone(&state), req));

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                error!(remote_addr = %remote_addr, error = %e, "Connection error");
            }
        });
    }
}

/// Raw JSON-RPC over TCP (simulates vsock for local testing)
async fn run_raw_rpc_server(state: Arc<AppState>, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(address = %addr, "Raw JSON-RPC server listening");

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let response = state.rpc_handler.handle(line.trim().as_bytes()).await;
                        if writer.write_all(&response).await.is_err() {
                            break;
                        }
                        if writer.write_all(b"\n").await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(remote_addr = %remote_addr, error = %e, "Read error");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(target_os = "linux")]
async fn run_vsock_server(state: Arc<AppState>, port: u32) -> Result<()> {
    use tokio_vsock::{VsockAddr, VsockListener};

    let addr = VsockAddr::new(nix::libc::VMADDR_CID_ANY, port);
    let mut listener = VsockListener::bind(addr)?;
    info!(cid = "ANY", port = port, "vsock server listening");

    loop {
        let (stream, addr) = listener.accept().await?;
        let state = Arc::clone(&state);

        tokio::spawn(async move {
            let (reader, mut writer) = tokio::io::split(stream);
            let mut reader = BufReader::new(reader);
            let mut line = String::new();

            loop {
                line.clear();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let response = state.rpc_handler.handle(line.trim().as_bytes()).await;
                        if writer.write_all(&response).await.is_err() {
                            break;
                        }
                        if writer.write_all(b"\n").await.is_err() {
                            break;
                        }
                        if writer.flush().await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!(addr = ?addr, error = %e, "Read error");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(not(target_os = "linux"))]
async fn run_vsock_server(_state: Arc<AppState>, _port: u32) -> Result<()> {
    anyhow::bail!("vsock is only supported on Linux")
}

/// Initialize AWS clients for the enclave
async fn init_aws_clients() -> Result<AwsClients> {
    let config = AwsEnclaveConfig::default();
    let clients = AwsClients::new(config).await?;
    Ok(clients)
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Privacy Enclave Server...");

    let enclave = Arc::new(EnclaveServer::new()?);
    
    // Auto-detect: if NSM is available (we're in an enclave), use vsock
    // Otherwise, check environment variables for explicit mode selection
    let in_enclave = !enclave.is_local_mode();
    let use_vsock = in_enclave || std::env::var("USE_VSOCK").is_ok();
    let use_raw_rpc = std::env::var("USE_RAW_RPC").is_ok();
    
    // Initialize AWS clients
    info!("Initializing AWS clients...");
    let aws_clients = init_aws_clients().await?;
    info!("AWS clients initialized successfully");
    let rpc_handler = RpcHandler::with_aws(Arc::clone(&enclave), Arc::new(RwLock::new(aws_clients)));
    
    let state = Arc::new(AppState { rpc_handler });

    if use_vsock {
        info!(
            "Running vsock server on port {} (enclave_detected={})",
            VSOCK_PORT, in_enclave
        );
        run_vsock_server(state, VSOCK_PORT).await
    } else if use_raw_rpc {
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(VSOCK_PORT as u16);
        run_raw_rpc_server(state, port).await
    } else {
        let port: u16 = std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(HTTP_PORT);
        run_http_server(state, port).await
    }
}
