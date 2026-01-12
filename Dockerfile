# Dockerfile for building the Rust enclave EIF
#
# This produces an EIF (Enclave Image File) that can be used with the
# privacy-enclave infrastructure by replacing the op-enclave eif.bin.
#
# Build: docker build -t privacy-enclave .
# Extract EIF: Use nitro-cli build-enclave (see below)

# Stage 1: Build the Rust application
FROM rust:1.75-slim-bookworm as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Create a dummy src to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release && rm -rf src target/release/deps/privacy_enclave*

# Copy actual source code
COPY src ./src

# Build the application
RUN cargo build --release

# Stage 2: Create the minimal enclave image
# This is what gets converted to an EIF
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/target/release/enclave-server /app/enclave-server

# Set environment variables for enclave mode
# USE_VSOCK enables vsock listener on port 1234
ENV USE_VSOCK=1
ENV RUST_LOG=info

# The enclave will use vsock for communication with the parent instance
# Port 1234 matches what the privacy-enclave Go proxy expects
CMD ["/app/enclave-server"]
