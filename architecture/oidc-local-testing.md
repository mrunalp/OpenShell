# OIDC Local Testing Guide

Step-by-step instructions for testing OIDC/Keycloak authentication locally.

## Prerequisites

- Docker or Podman
- Rust toolchain (edition 2024, rust 1.88+)
- `grpcurl` (optional, for raw gRPC testing)
- `jq` (optional, for JSON pretty-printing)

## 1. Start Keycloak

```bash
./scripts/keycloak-dev.sh start
```

Wait for "Keycloak is ready." The script prints connection info including test users.

Verify:
```bash
curl -s http://localhost:8180/realms/openshell/.well-known/openid-configuration | jq .issuer
# Expected: "http://localhost:8180/realms/openshell"
```

## 2. Test Server-Side Validation (Standalone, No K3s)

Start the server directly with OIDC enabled (no Kubernetes required):

```bash
cargo run -p openshell-server -- \
  --disable-tls \
  --db-url sqlite::memory: \
  --ssh-handshake-secret test \
  --oidc-issuer http://localhost:8180/realms/openshell
```

You'll see k8s watcher warnings (expected without a cluster) and:
```
OIDC JWT validation enabled (issuer: http://localhost:8180/realms/openshell)
Server listening address=0.0.0.0:8080
```

### Test with grpcurl

```bash
# Health — should succeed without token (skip list)
grpcurl -plaintext -import-path proto -proto openshell.proto \
  localhost:8080 openshell.v1.OpenShell/Health

# ListSandboxes without token — should fail
grpcurl -plaintext -import-path proto -proto openshell.proto \
  localhost:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: Code: Unauthenticated, Message: missing authorization header

# Get a token from Keycloak
TOKEN=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
  | jq -r .access_token)

# ListSandboxes with token — should succeed
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $TOKEN" \
  localhost:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: {} (empty list)

# OIDC discovery endpoint
curl -s http://localhost:8080/auth/oidc-config | jq .
# Expected: {"audience":"openshell-cli","issuer":"http://localhost:8180/realms/openshell"}
```

Stop the standalone server (Ctrl+C) before proceeding.

## 3. Test CLI OIDC Flow (Standalone, No K3s)

With the standalone server still running from step 2:

```bash
# Register the gateway with OIDC auth
cargo run -p openshell-cli --features bundled-z3 -- gateway add http://localhost:8080 \
  --oidc-issuer http://localhost:8180/realms/openshell

# This opens a browser to Keycloak. Login with:
#   Username: admin@test
#   Password: admin
# After login, the browser shows "Authentication successful!"

# Verify stored token
cat ~/.config/openshell/gateways/localhost/oidc_token.json | jq .

# Test an authenticated CLI command
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: "no sandboxes found" (no k8s, so no sandboxes)
```

### Test Client Credentials (CI Mode)

```bash
OPENSHELL_OIDC_CLIENT_SECRET=ci-test-secret \
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Expected: ✓ Authenticated to gateway 'localhost' (no browser opened)
```

## 4. Test End-to-End with K3s Gateway

This deploys a full K3s cluster with OIDC enforcement and creates sandboxes.

### Determine Host IP

Keycloak runs on the host. The K3s container needs to reach it, so use the host IP (not localhost):

```bash
HOST_IP=$(hostname -I | awk '{print $1}')
echo $HOST_IP
```

### Start Gateway with OIDC

```bash
cargo run -p openshell-cli --features bundled-z3 -- gateway start \
  --oidc-issuer "http://${HOST_IP}:8180/realms/openshell" \
  --plaintext \
  --recreate
```

Wait for "Gateway ready."

**Note**: The released gateway image does not include OIDC support. To get full end-to-end enforcement inside K3s, you need to build a custom server image and inject it into the cluster. See the "Custom Server Image" section below.

### Login and Create Sandbox

```bash
# Authenticate (opens browser)
cargo run -p openshell-cli --features bundled-z3 -- gateway login

# Create a sandbox
cargo run -p openshell-cli --features bundled-z3 -- sandbox create

# List sandboxes
cargo run -p openshell-cli --features bundled-z3 -- sandbox list

# Enter the sandbox
cargo run -p openshell-cli --features bundled-z3 -- sandbox create
```

### Verify OIDC Enforcement

```bash
# Remove stored token
mv ~/.config/openshell/gateways/openshell/oidc_token.json /tmp/oidc_backup.json

# Should fail with Unauthenticated
cargo run -p openshell-cli --features bundled-z3 -- sandbox list

# Restore token
mv /tmp/oidc_backup.json ~/.config/openshell/gateways/openshell/oidc_token.json

# Should succeed again
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
```

### Test Token Expiry

Keycloak access tokens expire after 5 minutes by default. Wait 5 minutes, then:

```bash
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: Unauthenticated: ExpiredSignature

# Re-login to get a fresh token
cargo run -p openshell-cli --features bundled-z3 -- gateway login
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: success
```

### Delete Sandbox

```bash
cargo run -p openshell-cli --features bundled-z3 -- sandbox delete <sandbox-name>
```

## 5. Custom Server Image for K3s (Full OIDC Enforcement)

The released `gateway:dev` image doesn't have OIDC code. To test full enforcement inside K3s, build a custom image with the locally-compiled server binary:

```bash
# Build the server binary
cargo build -p openshell-server --release

# Create a custom image layered on the released one
cat > /tmp/Dockerfile.gateway-oidc <<'EOF'
FROM ghcr.io/nvidia/openshell/gateway:dev
USER root
COPY openshell-server /usr/local/bin/openshell-server
RUN chmod +x /usr/local/bin/openshell-server
# Symlink migrations to where the locally-built binary expects them.
# The baked CARGO_MANIFEST_DIR differs from the Docker build context.
RUN mkdir -p $(strings /usr/local/bin/openshell-server | grep -oP '.*/crates/openshell-server' | head -1) && \
    ln -sf /build/crates/openshell-server/migrations \
           $(strings /usr/local/bin/openshell-server | grep -oP '.*/crates/openshell-server' | head -1)/migrations
USER openshell
EOF

docker build -t gateway:oidc-local \
  -f /tmp/Dockerfile.gateway-oidc \
  target/release

# Import into K3s containerd
CONTAINER=$(docker ps --format '{{.Names}}' | grep openshell-cluster)
docker save gateway:oidc-local | docker exec -i $CONTAINER ctr images import --all-platforms -

# Patch the statefulset to use the custom image with OIDC env vars
docker exec $CONTAINER kubectl -n openshell set env statefulset/openshell \
  OPENSHELL_OIDC_ISSUER=http://${HOST_IP}:8180/realms/openshell \
  OPENSHELL_OIDC_AUDIENCE=openshell-cli

docker exec $CONTAINER kubectl -n openshell patch statefulset openshell --type='json' -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/image","value":"docker.io/library/gateway:oidc-local"},
  {"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}
]'

# Wait for rollout
docker exec $CONTAINER kubectl -n openshell rollout status statefulset/openshell --timeout=90s

# Verify OIDC is active in server logs
docker exec $CONTAINER kubectl -n openshell logs openshell-0 | grep OIDC
# Expected: OIDC JWT validation enabled (issuer: ...)
```

## 6. Cleanup

```bash
# Stop the gateway
cargo run -p openshell-cli --features bundled-z3 -- gateway stop

# Stop Keycloak
./scripts/keycloak-dev.sh stop
```

## Test Users

| Username | Password | Roles |
|---|---|---|
| `admin@test` | `admin` | `openshell-admin`, `openshell-user` |
| `user@test` | `user` | `openshell-user` |

## OIDC Clients

| Client ID | Type | Grant | Secret |
|---|---|---|---|
| `openshell-cli` | Public | Auth Code + PKCE | N/A |
| `openshell-ci` | Confidential | Client Credentials | `ci-test-secret` |

## Troubleshooting

**"missing authorization header"** — No OIDC token stored. Run `openshell gateway login`.

**"invalid token: ExpiredSignature"** — Token expired (default 5 min). Run `openshell gateway login`.

**"OIDC discovery request failed"** — Server can't reach Keycloak. Check that the issuer URL is reachable from the server (use host IP, not localhost, for K3s).

**"invalid token: unknown signing key"** — JWKS key mismatch. Keycloak may have rotated keys. Restart the server to refresh the JWKS cache.

**Sandbox list works without token** — The server binary doesn't have OIDC support. Follow the "Custom Server Image" section to build and deploy a local image.
