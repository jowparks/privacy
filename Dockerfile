# Dockerfile for building the Rust enclave EIF
#
# This produces an EIF (Enclave Image File) for AWS Nitro Enclaves.
#
# Build: docker build -t privacy-enclave .
# The final image contains eif.bin at /build/eif.bin

# =============================================================================
# Stage 1: Bootstrap - Pre-built kernel and init for Nitro Enclaves
# =============================================================================
# github.com/mdehoog/aws-nitro-enclaves-sdk-bootstrap
FROM ghcr.io/mdehoog/aws-nitro-enclaves-sdk-bootstrap@sha256:6e5e53bd47370dbc1920208e93d222533a36f9f5dc85615591cbfe56a03312b0 AS bootstrap

# =============================================================================
# Stage 2: Build the Rust application
# =============================================================================
FROM rust:1.83-slim-bookworm AS rust-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    musl-tools \
    && rm -rf /var/lib/apt/lists/*

# Add musl target for static linking
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Create a dummy src to build dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs

# Build dependencies (this layer will be cached)
RUN cargo build --release --target x86_64-unknown-linux-musl \
    && rm -rf src target/x86_64-unknown-linux-musl/release/deps/privacy_enclave*

# Copy actual source code
COPY src ./src

# Build the application (statically linked)
RUN cargo build --release --target x86_64-unknown-linux-musl

# Copy binary to predictable location
RUN mkdir -p /app/bin && \
    cp /app/target/x86_64-unknown-linux-musl/release/enclave-server /app/bin/enclave-server

# =============================================================================
# Stage 3: Build ramdisk images using linuxkit
# =============================================================================
# golang:1.22
FROM golang:1.22 AS ramdisk-builder

# Install linuxkit
RUN go install github.com/linuxkit/linuxkit/src/cmd/linuxkit@270fd1c5aa1986977b31af6c743c6a2681f67a29

WORKDIR /build

# Copy EIF configuration files
COPY eif eif/

# Copy bootstrap files (kernel, init, nsm.ko)
COPY --from=bootstrap /build/out bootstrap

# Copy the compiled enclave binary
COPY --from=rust-builder /app/bin/enclave-server bin/enclave-server

# Build the ramdisk images
RUN linuxkit build --format kernel+initrd --no-sbom --name init-ramdisk ./eif/init-ramdisk.yaml
RUN linuxkit build --format kernel+initrd --no-sbom --name user-ramdisk ./eif/user-ramdisk.yaml

# =============================================================================
# Stage 4: Build EIF using eif_build from aws-nitro-enclaves-image-format
# =============================================================================
# Using full rust image which includes git, pkg-config, libssl-dev, etc.
FROM rust:1.83 AS eif-builder

RUN mkdir /build
WORKDIR /build

# Clone and build eif_build tool
ENV REPO=https://github.com/aws/aws-nitro-enclaves-image-format.git
ENV COMMIT=483114f1da3bad913ad1fb7d5c00dadacc6cbae6
RUN git init && \
    git remote add origin $REPO && \
    git fetch --depth=1 origin $COMMIT && \
    git reset --hard FETCH_HEAD

RUN cargo build --all --release

# Copy cmdline (kernel boot parameters)
COPY eif/cmdline-x86_64 cmdline

# Copy bootstrap files (kernel and config)
COPY --from=bootstrap /build/out bootstrap

# Copy ramdisk images
COPY --from=ramdisk-builder /build/init-ramdisk-initrd.img .
COPY --from=ramdisk-builder /build/user-ramdisk-initrd.img .

# Build the EIF
RUN ./target/release/eif_build \
    --kernel bootstrap/bzImage \
    --kernel_config bootstrap/bzImage.config \
    --cmdline "$(cat cmdline)" \
    --ramdisk init-ramdisk-initrd.img \
    --ramdisk user-ramdisk-initrd.img \
    --output eif.bin

# =============================================================================
# Stage 5: Final minimal image with just the EIF
# =============================================================================
FROM busybox

RUN mkdir /build
WORKDIR /build

COPY --from=eif-builder /build/eif.bin .

# The eif.bin can be extracted from this image or used directly
CMD ["cat", "eif.bin"]
