# Notary Server (TEE)

An implementation of the notary server inside a Trusted Execution Environment.

## Benefits

By executing the notary server inside a TEE, we reduce the trust assumptions from having a trusted notary server with a trusted key, since we produce the key inside the enclave. Since it's tamper-proof, we can trust it. This makes this component publicly auditable and verifiable by anyone.

## Architecture

Notary Server → Attestation of Initialization → Atomic attestations for each MPC that connects to the notary server.

For more context, you can look at `fetch.rs` in the examples folder, which takes a `.env` file with the secure enclave configuration.

## Configuration

The notary server can be configured via:
1. **Config file** using `--config <path-to-config.yaml>`
2. **Environment variables** with `NS_` prefix (e.g., `NS_PORT`, `NS_TLS__ENABLED`)

For all available configuration options and examples, see the [main server README](../README.md#configuration).

## Docker Deployment

### Build the Alpine Image

Build from the repository root:

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
  --config /config/config.yaml
```

With environment variables (prefix `NS_`, separator `__`):

```bash
docker run --rm \
  -e NS_HOST=0.0.0.0 \
  -e NS_PORT=7047 \
  -p 7047:7047 \
  notary-server:alpine
```

## Attestation Artifacts

`POST /api/v1/prove` runs notarization and returns a `job_id`. The proxy writes
artifacts to `${TLSN_PROXY_JOBS_DIR}/${job_id}` (for example,
`/tmp/tlsn-proxy/<job_id>` when using `.env.example`).

On startup, the proxy prunes old job directories in `TLSN_PROXY_JOBS_DIR`.
Retention is controlled by `TLSN_PROXY_JOB_RETENTION_MINUTES` (default `1440`).
Set it to `0` to disable startup cleanup.

To download the raw TLSN attestation binary for a job:

```bash
curl -sS "http://127.0.0.1:7048/api/v1/jobs/<job_id>/attestation" \
  --output "attestation-<job_id>.tlsn"
```

To download the raw TLSN secrets binary for a job:

```bash
curl -sS "http://127.0.0.1:7048/api/v1/jobs/<job_id>/secrets" \
  --output "secrets-<job_id>.tlsn"
```

Notes:
- `job_id` must be a 32-character hex string.
- The endpoint returns `404` if the artifact does not exist.
