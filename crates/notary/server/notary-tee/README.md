# Notary Server (TEE)

An implementation of the notary server inside a Trusted Execution Environment.

## Benefits

By executing the notary server inside a TEE, we reduce the trust assumptions from having a trusted notary server with a trusted key, since we produce the key inside the enclave. Since it's tamper-proof, we can trust it. This makes this component publicly auditable and verifiable by anyone.

## Architecture

Notary Server → Attestation of Initialization → Atomic attestations for each MPC that connects to the notary server.

For more context, you can look at `fetch.rs` in the examples folder, which takes a `.env` file with the secure enclave configuration.

## Docker Deployment

### Build the Alpine Image

build manually from the repository root:

```bash
docker build -f crates/notary/server/notary-tee/Dockerfile -t notary-server:alpine .
```

### Run the Container

Basic usage:

```bash
docker run --rm notary-server:alpine --help
```

With configuration file:

```bash
docker run --rm \
  -v $(pwd)/config:/config \
  -p 7047:7047 \
  notary-server:alpine \
  --config-file /config/config.yaml
```

With environment variables:

```bash
docker run --rm \
  -e NOTARY_SERVER_HOST=0.0.0.0 \
  -e NOTARY_SERVER_PORT=7047 \
  -p 7047:7047 \
  notary-server:alpine
```



