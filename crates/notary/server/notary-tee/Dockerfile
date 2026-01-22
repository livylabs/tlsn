# Multi-stage build for notary-server with Alpine Linux
# Build stage - use rust:alpine for smaller build image
FROM rust:alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    musl-dev \
    clang \
    clang-dev \
    llvm-dev \
    openssl-dev \
    openssl-libs-static \
    zlib-static \
    zlib-dev \
    pkgconfig

WORKDIR /usr/src/tlsn

# Copy the entire workspace
COPY . .

# Provide a default commit hash for build scripts when .git is unavailable
ENV GIT_COMMIT_HASH=unknown

# Build the notary-server binary
# Using --locked to use Cargo.lock for reproducible builds
RUN cargo build --release \
    --package notary-server \
    --locked

# Runtime stage - minimal Alpine image
FROM alpine:latest

# Install runtime dependencies (only if needed)
RUN apk add --no-cache \
    ca-certificates \
    && update-ca-certificates

# Create a non-root user for security
RUN addgroup -g 1000 notary && \
    adduser -D -u 1000 -G notary notary

# Set working directory
WORKDIR /home/notary

# Copy the binary from builder
COPY --from=builder \
    /usr/src/tlsn/target/release/notary-server \
    /usr/local/bin/notary-server

# Make sure binary is executable
RUN chmod +x /usr/local/bin/notary-server

# Switch to non-root user
USER notary

# Expose default ports (adjust as needed)
EXPOSE 7047

# Set entrypoint
ENTRYPOINT ["notary-server"]

# Default command (run server with defaults)
CMD []

