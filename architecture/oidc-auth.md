# OIDC Authentication

OpenShell supports OAuth2/OIDC (OpenID Connect) as an authentication mode alongside mTLS and Cloudflare Access. When enabled, the gateway server validates JWT bearer tokens on gRPC requests against an OIDC provider's JWKS endpoint. The CLI acquires tokens via browser-based login (Authorization Code + PKCE) or environment variables (Client Credentials).

## Architecture

```
                                    +-------------------+
                                    |    Keycloak /      |
                                    |    OIDC Provider   |
                                    +--------+----------+
                                             |
                          JWKS (cached)      |  Token exchange
                          +---------+--------+---------+
                          |                            |
                          v                            v
+----------+    Bearer token    +-----------+    Auth Code    +---------+
|          | -----------------> |           | <-------------- |         |
|   CLI    |    gRPC metadata   |  Gateway  |    + PKCE       | Browser |
|          | <----------------- |  Server   |                 |         |
+----------+    response        +-----------+                 +---------+
```

## Auth Modes

OpenShell determines the authentication strategy per gateway via the `auth_mode` field in gateway metadata (`~/.config/openshell/gateways/<name>/metadata.json`):

| `auth_mode` | Transport | Identity | Token Storage |
|---|---|---|---|
| `"mtls"` | mTLS client cert | Cert CN | N/A |
| `"plaintext"` | HTTP (no TLS) | None | N/A |
| `"cloudflare_jwt"` | Edge TLS (CF Tunnel) | CF Access JWT | `edge_token` file |
| `"oidc"` | mTLS or plaintext | OIDC JWT | `oidc_token.json` |

## Token Acquisition

### Interactive: Authorization Code + PKCE

Used by `openshell gateway login` for interactive CLI sessions.

```
CLI                            Browser                       Keycloak
 |                               |                              |
 |  1. Discover OIDC endpoints   |                              |
 |  GET {issuer}/.well-known/openid-configuration               |
 |                               |                              |
 |  2. Generate PKCE pair        |                              |
 |     code_verifier  = random(32 bytes) -> base64url           |
 |     code_challenge = base64url(SHA256(code_verifier))        |
 |     state          = random(16 bytes) -> hex                 |
 |                               |                              |
 |  3. Start localhost callback  |                              |
 |     on 127.0.0.1:<random>     |                              |
 |                               |                              |
 |  4. Open browser              |                              |
 |  -------xdg-open------------->|                              |
 |                               |  5. Redirect to Keycloak     |
 |                               |  /auth?response_type=code    |
 |                               |  &client_id=openshell-cli    |
 |                               |  &redirect_uri=localhost:... |
 |                               |  &code_challenge=...         |
 |                               |  &code_challenge_method=S256 |
 |                               |  &state=... --------------->|
 |                               |                              |
 |                               |                 6. User logs |
 |                               |                    in        |
 |                               |                              |
 |                               |  7. Redirect back            |
 |                               |  <-- ?code=...&state=... ---|
 |                               |                              |
 |  8. Receive code on callback  |                              |
 |  <----GET /callback?code=..---|                              |
 |                               |                              |
 |  9. Validate state matches    |                              |
 |                               |                              |
 | 10. Exchange code for tokens  |                              |
 |  POST {token_endpoint}        |                              |
 |    grant_type=authorization_code                             |
 |    code=...                   |                              |
 |    redirect_uri=...           |                              |
 |    client_id=openshell-cli    |                              |
 |    code_verifier=...  ------------------------------------->|
 |                               |                              |
 |  <-- { access_token, refresh_token, expires_in } -----------|
 |                               |                              |
 | 11. Store token bundle        |                              |
 |     ~/.config/openshell/gateways/<name>/oidc_token.json      |
```

### Non-Interactive: Client Credentials

Used for CI/automation when `OPENSHELL_OIDC_CLIENT_SECRET` is set.

```
CI Agent                                                    Keycloak
 |                                                             |
 |  POST {token_endpoint}                                      |
 |    grant_type=client_credentials                            |
 |    client_id={OPENSHELL_OIDC_CLIENT_ID}                     |
 |    client_secret={OPENSHELL_OIDC_CLIENT_SECRET}             |
 |    scope=openid  ----------------------------------------->|
 |                                                             |
 |  <-- { access_token, expires_in } -------------------------|
 |                                                             |
 |  Store token bundle (no refresh_token)                      |
```

## Token Storage

OIDC tokens are stored as JSON at `~/.config/openshell/gateways/<name>/oidc_token.json` with `0600` permissions:

```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci...",
  "expires_at": 1718400300,
  "issuer": "http://localhost:8180/realms/openshell",
  "client_id": "openshell-cli"
}
```

The CLI checks `expires_at` before each request. If the token is within 30 seconds of expiry and a `refresh_token` is available, it silently refreshes via the token endpoint's `refresh_token` grant. If refresh fails, the user is prompted to re-authenticate with `openshell gateway login`.

## Per-Request Flow

On every gRPC call, the CLI interceptor injects the token as a standard HTTP header:

```
authorization: Bearer eyJhbGci...
```

The server-side OIDC middleware (`OidcGrpcRouter` in `multiplex.rs`) processes each request:

1. Check if the gRPC method is on the **skip list** — if so, pass through without auth.
2. Extract the `authorization: Bearer <token>` header.
3. Decode the JWT header to find the `kid` (key ID).
4. Look up the signing key in the **JWKS cache**. On cache miss, refresh from the JWKS endpoint.
5. Validate the JWT: signature (RS256), `exp`, `iss`, `aud` claims.
6. On success, forward the request to the RPC handler.
7. On failure, return `UNAUTHENTICATED` status.

## JWKS Key Caching

The server fetches the OIDC provider's JSON Web Key Set at startup via discovery:

```
GET {issuer}/.well-known/openid-configuration  ->  jwks_uri
GET {jwks_uri}                                 ->  { keys: [...] }
```

Keys are cached in memory with a configurable TTL (default: 1 hour). The cache refreshes:
- When the TTL expires (background, on next request).
- Immediately when a JWT references a `kid` not in the cache (handles key rotation).

## Skip List

These gRPC methods bypass OIDC validation:

| Method | Reason |
|---|---|
| `Health` (both services) | Kubernetes liveness/readiness probes |
| `GetSandboxConfig` | Called by sandbox supervisor (mTLS auth) |
| `ReportPolicyStatus` | Called by sandbox supervisor |
| `PushSandboxLogs` | Called by sandbox supervisor |
| `GetSandboxProviderEnvironment` | Called by sandbox supervisor |
| `SubmitPolicyAnalysis` | Called by sandbox supervisor |
| `/grpc.reflection.*` | gRPC server reflection (debugging tools) |
| `/grpc.health.*` | gRPC health check protocol |

## Role-Based Access Control (RBAC)

After JWT validation, the server checks the user's roles against a per-method requirement. Roles are extracted from a configurable claim path in the JWT.

### Role Mapping

| Operation | Required Role |
|---|---|
| Health, sandbox supervisor RPCs | (no auth — skip list) |
| Sandbox create, list, delete, exec, SSH | user role |
| Provider list, get | user role |
| Provider create, update, delete | admin role |
| Global config/policy updates | admin role |
| Draft policy approvals/rejections | admin role |
| All other authenticated RPCs | user role |

### Configurable Roles

The roles claim path and role names are configurable to support different OIDC providers. Each provider stores roles differently in the JWT:

| Provider | Roles Claim | Example Admin Role | Example User Role |
|---|---|---|---|
| Keycloak | `realm_access.roles` (default) | `openshell-admin` | `openshell-user` |
| Microsoft Entra ID | `roles` | `OpenShell.Admin` | `OpenShell.User` |
| Okta | `groups` | `openshell-admin` | `openshell-user` |
| GitHub | N/A | (empty — skip RBAC) | (empty — skip RBAC) |

When both `--oidc-admin-role` and `--oidc-user-role` are set to empty strings, RBAC is skipped entirely — any valid JWT is authorized. This supports providers like GitHub that don't emit roles in JWTs (authentication-only mode).

## Server Configuration

### CLI Flags / Environment Variables

| Flag | Env Var | Default | Description |
|---|---|---|---|
| `--oidc-issuer` | `OPENSHELL_OIDC_ISSUER` | (none) | OIDC issuer URL (enables JWT validation) |
| `--oidc-audience` | `OPENSHELL_OIDC_AUDIENCE` | `openshell-cli` | Expected `aud` claim |
| `--oidc-jwks-ttl` | `OPENSHELL_OIDC_JWKS_TTL` | `3600` | JWKS cache TTL in seconds |
| `--oidc-roles-claim` | `OPENSHELL_OIDC_ROLES_CLAIM` | `realm_access.roles` | Dot-separated path to roles array in JWT |
| `--oidc-admin-role` | `OPENSHELL_OIDC_ADMIN_ROLE` | `openshell-admin` | Role name for admin access |
| `--oidc-user-role` | `OPENSHELL_OIDC_USER_ROLE` | `openshell-user` | Role name for user access |

When `--oidc-issuer` is not set, OIDC validation is disabled and the server falls back to mTLS-only or plaintext behavior.

### Helm Values

```yaml
server:
  oidc:
    issuer: "https://keycloak.example.com/realms/openshell"
    audience: "openshell-cli"
    jwksTtl: 3600
```

### Discovery Endpoint

The server exposes `GET /auth/oidc-config` which returns the configured OIDC issuer and audience. This allows CLI auto-discovery during `gateway add`.

## Provider Examples

### Keycloak

```bash
openshell gateway start \
  --oidc-issuer http://keycloak:8180/realms/openshell
# Defaults work: realm_access.roles, openshell-admin, openshell-user
```

### Microsoft Entra ID

Register an app in Azure Portal with app roles `OpenShell.Admin` and `OpenShell.User`, then:

```bash
openshell gateway start \
  --oidc-issuer https://login.microsoftonline.com/{tenant-id}/v2.0 \
  --oidc-audience api://openshell \
  --oidc-roles-claim roles \
  --oidc-admin-role OpenShell.Admin \
  --oidc-user-role OpenShell.User
```

CLI registration:

```bash
openshell gateway add https://gateway:8080 \
  --oidc-issuer https://login.microsoftonline.com/{tenant-id}/v2.0 \
  --oidc-client-id {client-id}
```

### Okta

Create an authorization server with a `groups` claim, then:

```bash
openshell gateway start \
  --oidc-issuer https://dev-xxxxx.okta.com/oauth2/default \
  --oidc-roles-claim groups \
  --oidc-admin-role openshell-admin \
  --oidc-user-role openshell-user
```

### GitHub (Authentication Only)

GitHub's OIDC tokens (from Actions) don't carry roles. Use empty role names to skip RBAC — any valid GitHub JWT is authorized:

```bash
openshell gateway start \
  --oidc-issuer https://token.actions.githubusercontent.com \
  --oidc-audience https://github.com/{org} \
  --oidc-admin-role "" \
  --oidc-user-role ""
```

## CLI Commands

### Register an OIDC Gateway

```bash
openshell gateway add http://gateway:8080 \
  --oidc-issuer http://keycloak:8180/realms/openshell

# With custom client ID:
openshell gateway add http://gateway:8080 \
  --oidc-issuer http://keycloak:8180/realms/openshell \
  --oidc-client-id my-client
```

### Start a K3s Gateway with OIDC

```bash
openshell gateway start \
  --oidc-issuer http://keycloak:8180/realms/openshell \
  --plaintext
```

### Authenticate

```bash
# Interactive (opens browser)
openshell gateway login
# Expected: ✓ Authenticated to gateway 'openshell' as admin@test

# CI / automation
OPENSHELL_OIDC_CLIENT_SECRET=secret openshell gateway login
```

### Logout

```bash
openshell gateway logout
# Expected: ✓ Logged out of gateway 'openshell'
```

## Keycloak Setup

### Realm Configuration

The `scripts/keycloak-realm.json` file provides a pre-configured realm for development:

- **Realm**: `openshell`
- **Clients**:
  - `openshell-cli` — Public client, Authorization Code + PKCE, redirect URIs `http://127.0.0.1:*`
  - `openshell-ci` — Confidential client, Client Credentials grant, secret `ci-test-secret`
- **Roles**: `openshell-admin`, `openshell-user`
- **Test Users**:
  - `admin@test` / `admin` (roles: `openshell-admin`, `openshell-user`)
  - `user@test` / `user` (roles: `openshell-user`)

### Dev Server

```bash
# Start Keycloak on port 8180
./scripts/keycloak-dev.sh start

# Check status
./scripts/keycloak-dev.sh status

# Stop
./scripts/keycloak-dev.sh stop
```

Admin console: `http://localhost:8180/admin` (admin/admin).

## Coexistence with Other Auth Modes

OIDC is additive — it does not replace mTLS or Cloudflare Access. The server checks auth sources in order:

```
Request arrives
  |
  +-- Is method on skip list? --> Pass through
  |
  +-- Has "authorization: Bearer" header?
  |     +-- Validate JWT --> Authenticated (OIDC)
  |     +-- Invalid JWT  --> UNAUTHENTICATED
  |
  +-- No bearer header + OIDC configured --> UNAUTHENTICATED
  |
  +-- No bearer header + OIDC not configured
        +-- mTLS verified at TLS layer --> Authenticated (mTLS)
        +-- Plaintext --> Unauthenticated (no enforcement)
```

The CLI determines which auth mode to use based on `auth_mode` in gateway metadata. Only one mode is active per gateway registration.

## Key Files

| Component | File |
|---|---|
| Server OIDC validation | `crates/openshell-server/src/oidc.rs` |
| Server auth middleware | `crates/openshell-server/src/multiplex.rs` (`OidcGrpcRouter`) |
| Server config | `crates/openshell-core/src/config.rs` (`OidcConfig`) |
| Server CLI flags | `crates/openshell-server/src/main.rs` |
| Server discovery endpoint | `crates/openshell-server/src/auth.rs` (`/auth/oidc-config`) |
| CLI OIDC flows | `crates/openshell-cli/src/oidc_auth.rs` |
| CLI interceptor | `crates/openshell-cli/src/tls.rs` (`EdgeAuthInterceptor`) |
| CLI auth dispatch | `crates/openshell-cli/src/main.rs` (`apply_auth`) |
| CLI gateway commands | `crates/openshell-cli/src/run.rs` (`gateway_add`, `gateway_login`) |
| Token storage | `crates/openshell-bootstrap/src/oidc_token.rs` |
| Gateway metadata | `crates/openshell-bootstrap/src/metadata.rs` |
| Bootstrap pipeline | `crates/openshell-bootstrap/src/lib.rs`, `docker.rs` |
| K3s entrypoint | `deploy/docker/cluster-entrypoint.sh` |
| HelmChart template | `deploy/kube/manifests/openshell-helmchart.yaml` |
| Helm values | `deploy/helm/openshell/values.yaml` |
| Helm statefulset | `deploy/helm/openshell/templates/statefulset.yaml` |
| Keycloak dev script | `scripts/keycloak-dev.sh` |
| Keycloak realm config | `scripts/keycloak-realm.json` |
