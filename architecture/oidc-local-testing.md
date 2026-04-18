# OIDC Local Testing Guide

Step-by-step instructions for testing OIDC/Keycloak authentication locally,
including both standalone server testing and full end-to-end K3s testing.

## Prerequisites

- Docker or Podman
- Rust toolchain (edition 2024, rust 1.88+)
- `grpcurl` (for raw gRPC testing)
- `jq` (for JSON parsing)

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

## 2. Standalone Server Testing (No K3s)

Start the server directly with OIDC enabled. No Kubernetes cluster required.

```bash
cargo run -p openshell-server -- \
  --disable-tls \
  --db-url sqlite:/tmp/openshell-test.db \
  --ssh-handshake-secret test \
  --oidc-issuer http://localhost:8180/realms/openshell
```

You should see:
```
OIDC JWT validation enabled (issuer: http://localhost:8180/realms/openshell)
Server listening address=0.0.0.0:8080
```

K8s compute driver warnings are expected and non-fatal.

### 2a. Test Health (unauthenticated — should succeed)

```bash
grpcurl -plaintext -import-path proto -proto openshell.proto \
  127.0.0.1:8080 openshell.v1.OpenShell/Health
# Expected: SERVICE_STATUS_HEALTHY
```

### 2b. Test without token (should fail)

```bash
grpcurl -plaintext -import-path proto -proto openshell.proto \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: Code: Unauthenticated, Message: missing authorization header
```

### 2c. Get tokens from Keycloak

```bash
ADMIN_TOKEN=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=admin@test&password=admin' \
  | jq -r .access_token)

USER_TOKEN=$(curl -s -X POST http://localhost:8180/realms/openshell/protocol/openid-connect/token \
  -d 'grant_type=password&client_id=openshell-cli&username=user@test&password=user' \
  | jq -r .access_token)
```

### 2d. Test authenticated access

```bash
# Admin can list sandboxes
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: {} (empty list)

# User can list sandboxes
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $USER_TOKEN" \
  127.0.0.1:8080 openshell.v1.OpenShell/ListSandboxes
# Expected: {} (empty list)
```

### 2e. Test RBAC

```bash
# User CANNOT create provider (requires openshell-admin)
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $USER_TOKEN" \
  -d '{"provider":{"name":"test","type":"claude","credentials":{"key":"val"}}}' \
  127.0.0.1:8080 openshell.v1.OpenShell/CreateProvider
# Expected: Code: PermissionDenied, Message: role 'openshell-admin' required

# Admin CAN create provider
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -d '{"provider":{"name":"test","type":"claude","credentials":{"key":"val"}}}' \
  127.0.0.1:8080 openshell.v1.OpenShell/CreateProvider
# Expected: success
```

### 2f. Test sandbox secret auth

```bash
# Correct secret — should succeed (returns NOT_FOUND since sandbox doesn't exist)
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "x-sandbox-secret: test" \
  -d '{"sandbox_id":"fake"}' \
  127.0.0.1:8080 openshell.v1.OpenShell/GetSandboxConfig
# Expected: Code: NotFound (sandbox doesn't exist, but auth passed)

# Wrong secret — should fail at auth
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -H "x-sandbox-secret: wrong" \
  -d '{"sandbox_id":"fake"}' \
  127.0.0.1:8080 openshell.v1.OpenShell/GetSandboxConfig
# Expected: Code: Unauthenticated, Message: invalid sandbox secret

# No secret — should fail at auth
grpcurl -plaintext -import-path proto -proto openshell.proto \
  -d '{"sandbox_id":"fake"}' \
  127.0.0.1:8080 openshell.v1.OpenShell/GetSandboxConfig
# Expected: Code: Unauthenticated, Message: sandbox secret required
```

### 2g. Test OIDC discovery endpoint

```bash
curl -s http://127.0.0.1:8080/auth/oidc-config | jq .
# Expected: {"audience":"openshell-cli","issuer":"http://localhost:8180/realms/openshell"}
```

Stop the standalone server (Ctrl+C) before proceeding to K3s testing.

## 3. CLI OIDC Flow (Standalone)

With the standalone server running from step 2:

```bash
# Register the gateway with OIDC auth
cargo run -p openshell-cli --features bundled-z3 -- gateway add http://127.0.0.1:8080 \
  --oidc-issuer http://localhost:8180/realms/openshell

# Browser opens to Keycloak. Login with: admin@test / admin
# Expected: ✓ Authenticated to gateway 'localhost' as admin@test

# Verify stored token
cat ~/.config/openshell/gateways/127.0.0.1/oidc_token.json | jq .

# Test authenticated CLI command
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
```

### Test client credentials (CI mode)

```bash
OPENSHELL_OIDC_CLIENT_SECRET=ci-test-secret \
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Expected: ✓ Authenticated to gateway (no browser opened)
```

### Test logout

```bash
cargo run -p openshell-cli --features bundled-z3 -- gateway logout
# Expected: ✓ Logged out of gateway

cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: error (no token)
```

## 4. End-to-End K3s Testing

This deploys a full K3s cluster with OIDC enforcement and tests sandbox
creation, RBAC, login/logout, and token expiry.

### 4a. Determine host IP

Keycloak runs on the host. The K3s container must reach it via the host IP:

```bash
HOST_IP=$(hostname -I | awk '{print $1}')
echo "Host IP: $HOST_IP"
```

### 4b. Start K3s gateway

```bash
cargo run -p openshell-cli --features bundled-z3 -- gateway start \
  --oidc-issuer "http://${HOST_IP}:8180/realms/openshell" \
  --plaintext \
  --recreate
```

Wait for "Gateway ready."

### 4c. Build and deploy custom server image

The released `gateway:dev` image does not include OIDC code. Build a custom
image with the locally-compiled server binary and inject it into K3s.

The binary name changed to `openshell-gateway` after the compute-driver
refactor, but the base image's `ENTRYPOINT` still references
`openshell-server`. The Dockerfile copies the binary under both names.

```bash
# Build the server binary
cargo build -p openshell-server --release

# Create the custom image
cat > /tmp/Dockerfile.gateway-oidc <<'EOF'
FROM ghcr.io/nvidia/openshell/gateway:dev
USER root
COPY openshell-gateway /usr/local/bin/openshell-gateway
COPY openshell-gateway /usr/local/bin/openshell-server
RUN chmod +x /usr/local/bin/openshell-gateway /usr/local/bin/openshell-server
USER openshell
EOF

docker build -t gateway:oidc-local \
  -f /tmp/Dockerfile.gateway-oidc \
  target/release

# Import into K3s containerd
CONTAINER=$(docker ps --format '{{.Names}}' | grep openshell-cluster)
docker save gateway:oidc-local | docker exec -i $CONTAINER ctr images import --all-platforms -

# Patch the statefulset: custom image + OIDC env vars
HOST_IP=$(hostname -I | awk '{print $1}')
docker exec $CONTAINER kubectl -n openshell set env statefulset/openshell \
  OPENSHELL_OIDC_ISSUER=http://${HOST_IP}:8180/realms/openshell \
  OPENSHELL_OIDC_AUDIENCE=openshell-cli

docker exec $CONTAINER kubectl -n openshell patch statefulset openshell --type='json' -p='[
  {"op":"replace","path":"/spec/template/spec/containers/0/image","value":"docker.io/library/gateway:oidc-local"},
  {"op":"replace","path":"/spec/template/spec/containers/0/imagePullPolicy","value":"Never"}
]'

# Restart the pod to pick up the new image
docker exec $CONTAINER kubectl -n openshell delete pod openshell-0

# Wait for the new pod and verify OIDC is active
sleep 15
docker exec $CONTAINER kubectl -n openshell logs openshell-0 | grep OIDC
# Expected: OIDC JWT validation enabled (issuer: http://...)
```

If you don't see the "OIDC JWT validation enabled" line, check that:
- The pod is using the custom image (not the released one)
- The OIDC env vars are set on the pod
- Keycloak is reachable from inside the K3s container at the host IP

```bash
# Verify image
docker exec $CONTAINER kubectl -n openshell get pod openshell-0 \
  -o jsonpath='{.spec.containers[0].image}'; echo

# Verify env vars
docker exec $CONTAINER kubectl -n openshell get pod openshell-0 \
  -o jsonpath='{range .spec.containers[0].env[*]}{.name}={.value}{"\n"}{end}' | grep OIDC
```

### 4d. Login and create sandboxes

```bash
# Login as admin
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Login with: admin@test / admin
# Expected: ✓ Authenticated to gateway 'openshell' as admin@test

# Create a sandbox
cargo run -p openshell-cli --features bundled-z3 -- sandbox create
# Expected: Created sandbox: <name>

# List sandboxes
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: shows the created sandbox
```

### 4e. Verify authentication enforcement

```bash
# Logout
cargo run -p openshell-cli --features bundled-z3 -- gateway logout
# Expected: ✓ Logged out of gateway 'openshell'

# Should fail without token
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: Unauthenticated error

# Login again
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Login with: admin@test / admin

# Should work again
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: shows sandboxes
```

### 4f. Verify token expiry

Keycloak access tokens expire after 5 minutes by default.

```bash
# Wait 5+ minutes, then:
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: Unauthenticated: ExpiredSignature

# Re-login
cargo run -p openshell-cli --features bundled-z3 -- gateway login
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: success
```

### 4g. Verify RBAC

```bash
# Login as admin
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Login with: admin@test / admin

# Admin can create a provider
cargo run -p openshell-cli --features bundled-z3 -- provider create \
  --name test-provider --type claude --credential API_KEY=test123
# Expected: success

# Login as user (openshell-user only, no openshell-admin)
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Login with: user@test / user
# Expected: ✓ Authenticated to gateway 'openshell' as user@test

# User can list sandboxes
cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: success

# User can list providers
cargo run -p openshell-cli --features bundled-z3 -- provider list
# Expected: shows test-provider

# User CANNOT create a provider
cargo run -p openshell-cli --features bundled-z3 -- provider create \
  --name blocked --type claude --credential API_KEY=nope
# Expected: PermissionDenied: role 'openshell-admin' required

# User CANNOT delete a provider
cargo run -p openshell-cli --features bundled-z3 -- provider delete test-provider
# Expected: PermissionDenied: role 'openshell-admin' required

# User CAN create sandboxes
cargo run -p openshell-cli --features bundled-z3 -- sandbox create
# Expected: success
```

### 4h. Test client credentials (CI mode)

```bash
OPENSHELL_OIDC_CLIENT_SECRET=ci-test-secret \
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Expected: ✓ Authenticated to gateway 'openshell' (no browser)

cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Expected: success
```

### 4i. Clean up sandboxes

```bash
# Login as admin to clean up
cargo run -p openshell-cli --features bundled-z3 -- gateway login
# Login with: admin@test / admin

cargo run -p openshell-cli --features bundled-z3 -- sandbox list
# Note sandbox names, then:
cargo run -p openshell-cli --features bundled-z3 -- sandbox delete <name>

cargo run -p openshell-cli --features bundled-z3 -- provider delete test-provider
```

## 5. Cleanup

```bash
# Stop the gateway (preserves K3s state for next start)
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

## Method Authentication Categories

| Category | Methods | Auth Mechanism |
|---|---|---|
| Unauthenticated | Health, gRPC reflection | None |
| Sandbox-secret | GetSandboxConfig, GetSandboxProviderEnvironment, ReportPolicyStatus, PushSandboxLogs, SubmitPolicyAnalysis | `x-sandbox-secret` header |
| Dual-auth | UpdateConfig | Bearer token OR `x-sandbox-secret` |
| OIDC Bearer | All other RPCs | `authorization: Bearer <JWT>` |

## Role Requirements

| Operation | Required Role |
|---|---|
| Sandbox create, list, delete, exec, SSH | `openshell-user` |
| Provider list, get | `openshell-user` |
| Provider create, update, delete | `openshell-admin` |
| Global config/policy updates | `openshell-admin` |
| Draft policy approvals | `openshell-admin` |

## Troubleshooting

**"missing authorization header"** — No OIDC token stored. Run `openshell gateway login`.

**"invalid token: ExpiredSignature"** — Token expired (default 5 min). Run `openshell gateway login`.

**"PermissionDenied: role 'openshell-admin' required"** — Logged in as a user without the admin role. Login as `admin@test`.

**"sandbox secret required for this method"** — A sandbox-to-server RPC was called without the `x-sandbox-secret` header.

**"OIDC discovery request failed"** — Server can't reach Keycloak. Use the host IP (not `localhost`) for K3s deployments.

**"invalid token: unknown signing key"** — JWKS key mismatch. Restart the server to refresh the cache.

**No "OIDC JWT validation enabled" in K3s logs** — The server pod is running the released binary (no OIDC code). Follow section 4c to build and deploy a custom image. Ensure the Dockerfile copies the binary as both `openshell-gateway` and `openshell-server` since the base image entrypoint uses `openshell-server`.

**"connection refused" with grpcurl** — On Fedora/systems where `localhost` resolves to IPv6, use `127.0.0.1` instead of `localhost`.

**"no such table: objects"** — Using `sqlite::memory:` which doesn't run migrations. Use a file path like `sqlite:/tmp/openshell-test.db`.
