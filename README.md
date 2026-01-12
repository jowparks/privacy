# Privacy Enclave

A Rust enclave server for AWS Nitro Enclaves

## Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                         EC2 Instance (Parent)                          │
│                                                                        │
│  ┌──────────────────┐           vsock              ┌────────────────┐  │
│  │   Go Proxy       │◄──────────────────────────►  │   Nitro        │  │
│  │   (main.go)      │    CID 16, Port 1234         │   Enclave      │  │
│  │                  │                              │                │  │
│  │  HTTP :7333      │                              │  Rust Server   │  │
│  └──────────────────┘                              └────────────────┘  │
└────────────────────────────────────────────────────────────────────────┘
```

## RPC Methods

All methods use the `priv_` namespace prefix.

| Method | Description |
|--------|-------------|
| `priv_signerPublicKey` | Returns the ECDSA public signing key (hex) |
| `priv_signerAttestation` | Returns an NSM attestation document |
| `priv_decryptionPublicKey` | Returns the decryption public key |
| `priv_decryptionAttestation` | Returns attestation for decryption key |
| `priv_setSignerKey` | Sets the signer key (encrypted) |
| `priv_sign` | Signs a message |

## Quick Start

### Local Development

```bash
cargo run

# Test signerPublicKey
curl -X POST http://localhost:5000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"priv_signerPublicKey","id":1}'

# Test sign
curl -X POST http://localhost:5000/rpc \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"priv_sign","params":[{"message":"0x68656c6c6f"}],"id":2}'
```

### Raw JSON-RPC Mode (simulates vsock)

```bash
USE_RAW_RPC=1 PORT=1234 cargo run

# Test with netcat
echo '{"jsonrpc":"2.0","method":"priv_signerPublicKey","id":1}' | nc localhost 1234
```

## Building for Nitro Enclave

```bash
# Build Docker image
docker build -t privacy-enclave .

# Build EIF (on EC2 with Nitro CLI)
nitro-cli build-enclave \
  --docker-uri privacy-enclave:latest \
  --output-file privacy-enclave.eif
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `USE_VSOCK` | Enable vsock mode | unset |
| `USE_RAW_RPC` | Enable raw JSON-RPC over TCP | unset |
| `PORT` | Server port | 5000 (HTTP) / 1234 (raw RPC) |

## Project Structure

```
privacy-enclave/
├── Cargo.toml
├── Dockerfile
├── README.md
└── src/
    ├── main.rs         # Server entry point
    ├── lib.rs          # Library root
    ├── enclave.rs      # NSM integration
    ├── error.rs        # Error types
    └── rpc.rs          # JSON-RPC handler
```

## License

MIT
