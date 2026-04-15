// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OIDC JWT validation for gRPC requests.
//!
//! Validates `authorization: Bearer <JWT>` headers against a Keycloak (or
//! any OIDC-compliant) issuer using cached JWKS keys. When the server is
//! started with `--oidc-issuer`, all gRPC requests (except those on the
//! skip list) must carry a valid Bearer token.

use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use openshell_core::OidcConfig;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tonic::Status;
use tracing::{debug, info, warn};

/// gRPC method paths that bypass OIDC validation.
///
/// These are either health probes or sandbox-to-server RPCs that authenticate
/// via mTLS / SSH handshake secret instead of OIDC tokens.
/// Exact gRPC method paths that bypass OIDC validation.
const SKIP_METHODS: &[&str] = &[
    "/openshell.v1.OpenShell/Health",
    "/openshell.inference.v1.Inference/Health",
    "/openshell.v1.OpenShell/GetSandboxConfig",
    "/openshell.v1.OpenShell/ReportPolicyStatus",
    "/openshell.v1.OpenShell/PushSandboxLogs",
    "/openshell.v1.OpenShell/GetSandboxProviderEnvironment",
    "/openshell.v1.OpenShell/SubmitPolicyAnalysis",
    "/openshell.sandbox.v1.SandboxService/GetSandboxConfig",
];

/// Path prefixes that bypass OIDC validation (gRPC reflection, health probes).
const SKIP_PREFIXES: &[&str] = &[
    "/grpc.reflection.",
    "/grpc.health.",
];

/// Returns `true` if the given gRPC path should skip OIDC validation.
pub fn is_skip_method(path: &str) -> bool {
    SKIP_METHODS.contains(&path)
        || SKIP_PREFIXES.iter().any(|prefix| path.starts_with(prefix))
}

/// gRPC methods that require the `openshell-admin` role.
/// All other authenticated methods require `openshell-user`.
const ADMIN_METHODS: &[&str] = &[
    // Provider management
    "/openshell.v1.OpenShell/CreateProvider",
    "/openshell.v1.OpenShell/UpdateProvider",
    "/openshell.v1.OpenShell/DeleteProvider",
    // Global config and policy
    "/openshell.v1.OpenShell/UpdateConfig",
    // Draft policy approvals
    "/openshell.v1.OpenShell/ApproveDraftChunk",
    "/openshell.v1.OpenShell/ApproveAllDraftChunks",
    "/openshell.v1.OpenShell/RejectDraftChunk",
    "/openshell.v1.OpenShell/EditDraftChunk",
    "/openshell.v1.OpenShell/UndoDraftChunk",
    "/openshell.v1.OpenShell/ClearDraftChunks",
];

/// Returns `true` if the method requires the admin role.
pub fn is_admin_method(path: &str) -> bool {
    ADMIN_METHODS.contains(&path)
}

/// Check that the validated claims include the required role for the method.
///
/// Uses the configured role names from `OidcConfig` so different OIDC
/// providers (Keycloak, Entra ID, Okta) can use their own role naming.
pub fn check_role(claims: &OidcClaims, path: &str, config: &OidcConfig) -> Result<(), Status> {
    let required = if is_admin_method(path) {
        &config.admin_role
    } else {
        &config.user_role
    };

    // If the required role is empty, skip RBAC (authentication-only mode).
    // This supports providers like GitHub that don't emit roles in JWTs.
    if required.is_empty() {
        return Ok(());
    }

    if claims.roles.iter().any(|r| r == required) {
        Ok(())
    } else {
        debug!(
            sub = %claims.sub,
            required_role = required,
            user_roles = ?claims.roles,
            method = path,
            "OIDC role check failed"
        );
        Err(Status::permission_denied(format!(
            "role '{required}' required"
        )))
    }
}

/// Cached JWKS key set fetched from the OIDC issuer.
pub struct JwksCache {
    keys: Arc<RwLock<HashMap<String, DecodingKey>>>,
    jwks_uri: String,
    ttl: Duration,
    last_refresh: Arc<RwLock<Instant>>,
    http: Client,
    config: OidcConfig,
}

impl std::fmt::Debug for JwksCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksCache")
            .field("jwks_uri", &self.jwks_uri)
            .field("ttl", &self.ttl)
            .finish()
    }
}

/// OIDC discovery document (subset of fields we need).
#[derive(Deserialize)]
struct OidcDiscovery {
    jwks_uri: String,
}

/// JWKS key set.
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<JwkKey>,
}

/// A single JWK key.
#[derive(Deserialize)]
struct JwkKey {
    kid: Option<String>,
    kty: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
}

/// Claims extracted from a validated JWT.
#[derive(Debug, Deserialize)]
pub struct OidcClaims {
    pub sub: String,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    /// Roles extracted from the configurable claim path.
    #[serde(skip)]
    pub roles: Vec<String>,
    /// Raw claims for flexible role extraction.
    #[serde(flatten)]
    extra: serde_json::Value,
}

impl OidcClaims {
    /// Extract roles from the JWT claims using a dot-separated path.
    ///
    /// Supports paths like:
    /// - `realm_access.roles` (Keycloak)
    /// - `roles` (Entra ID)
    /// - `groups` (Okta)
    fn extract_roles(&mut self, roles_claim: &str) {
        let mut value = &self.extra;
        for segment in roles_claim.split('.') {
            match value.get(segment) {
                Some(v) => value = v,
                None => return,
            }
        }
        if let Some(arr) = value.as_array() {
            self.roles = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
    }
}

impl JwksCache {
    /// Create a new JWKS cache, discovering the JWKS URI and fetching the
    /// initial key set.
    pub async fn new(config: &OidcConfig) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to create HTTP client: {e}"))?;

        // Discover JWKS URI from the OIDC discovery endpoint.
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            config.issuer.trim_end_matches('/')
        );
        info!(url = %discovery_url, "Discovering OIDC configuration");

        let discovery: OidcDiscovery = http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| format!("OIDC discovery request failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("OIDC discovery response parse failed: {e}"))?;

        info!(jwks_uri = %discovery.jwks_uri, "OIDC JWKS URI discovered");

        let cache = Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            jwks_uri: discovery.jwks_uri,
            ttl: Duration::from_secs(config.jwks_ttl_secs),
            last_refresh: Arc::new(RwLock::new(
                Instant::now() - Duration::from_secs(config.jwks_ttl_secs + 1),
            )),
            http,
            config: config.clone(),
        };

        cache.refresh_keys().await?;
        Ok(cache)
    }

    /// Fetch the JWKS and update the cached keys.
    async fn refresh_keys(&self) -> Result<(), String> {
        debug!(uri = %self.jwks_uri, "Refreshing JWKS keys");

        let jwk_set: JwkSet = self
            .http
            .get(&self.jwks_uri)
            .send()
            .await
            .map_err(|e| format!("JWKS fetch failed: {e}"))?
            .json()
            .await
            .map_err(|e| format!("JWKS parse failed: {e}"))?;

        let mut new_keys = HashMap::new();
        for key in &jwk_set.keys {
            if key.kty != "RSA" {
                continue;
            }
            let Some(ref kid) = key.kid else {
                continue;
            };
            match DecodingKey::from_rsa_components(&key.n, &key.e) {
                Ok(dk) => {
                    new_keys.insert(kid.clone(), dk);
                }
                Err(e) => {
                    warn!(kid = %kid, error = %e, "Failed to parse JWK");
                }
            }
        }

        info!(count = new_keys.len(), "JWKS keys loaded");
        *self.keys.write().await = new_keys;
        *self.last_refresh.write().await = Instant::now();
        Ok(())
    }

    /// Refresh keys if the TTL has elapsed.
    async fn refresh_if_stale(&self) -> Result<(), String> {
        let last = *self.last_refresh.read().await;
        if last.elapsed() > self.ttl {
            self.refresh_keys().await?;
        }
        Ok(())
    }

    /// Validate a JWT and return the extracted claims.
    pub async fn validate_token(&self, token: &str) -> Result<OidcClaims, Status> {
        self.refresh_if_stale().await.map_err(|e| {
            warn!(error = %e, "JWKS refresh failed");
            Status::internal("OIDC key refresh failed")
        })?;

        // Decode the header to find the key ID.
        let header = decode_header(token).map_err(|e| {
            debug!(error = %e, "Failed to decode JWT header");
            Status::unauthenticated("invalid token")
        })?;

        let kid = header.kid.ok_or_else(|| {
            debug!("JWT has no kid in header");
            Status::unauthenticated("invalid token: missing kid")
        })?;

        // Look up the key in cache.
        let keys = self.keys.read().await;
        let decoding_key = match keys.get(&kid) {
            Some(k) => k.clone(),
            None => {
                // Key not found -- try refreshing once (key rotation).
                drop(keys);
                self.refresh_keys().await.map_err(|e| {
                    warn!(error = %e, "JWKS refresh on kid miss failed");
                    Status::internal("OIDC key refresh failed")
                })?;
                let keys = self.keys.read().await;
                keys.get(&kid).cloned().ok_or_else(|| {
                    debug!(kid = %kid, "JWT kid not found in JWKS");
                    Status::unauthenticated("invalid token: unknown signing key")
                })?
            }
        };

        // Validate the JWT.
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.config.issuer]);
        validation.set_audience(&[&self.config.audience]);

        let token_data = decode::<OidcClaims>(token, &decoding_key, &validation).map_err(|e| {
            debug!(error = %e, "JWT validation failed");
            Status::unauthenticated(format!("invalid token: {e}"))
        })?;

        let mut claims = token_data.claims;
        claims.extract_roles(&self.config.roles_claim);
        Ok(claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skip_list_contains_health() {
        assert!(is_skip_method("/openshell.v1.OpenShell/Health"));
    }

    #[test]
    fn skip_list_rejects_sandbox_operations() {
        assert!(!is_skip_method("/openshell.v1.OpenShell/CreateSandbox"));
        assert!(!is_skip_method("/openshell.v1.OpenShell/ListSandboxes"));
    }

    #[test]
    fn skip_list_allows_grpc_reflection() {
        assert!(is_skip_method(
            "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo"
        ));
        assert!(is_skip_method(
            "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo"
        ));
    }

    #[test]
    fn skip_list_allows_grpc_health() {
        assert!(is_skip_method("/grpc.health.v1.Health/Check"));
    }

    #[test]
    fn admin_methods_detected() {
        assert!(is_admin_method("/openshell.v1.OpenShell/CreateProvider"));
        assert!(is_admin_method("/openshell.v1.OpenShell/UpdateConfig"));
        assert!(is_admin_method("/openshell.v1.OpenShell/ApproveDraftChunk"));
        assert!(!is_admin_method("/openshell.v1.OpenShell/CreateSandbox"));
        assert!(!is_admin_method("/openshell.v1.OpenShell/ListSandboxes"));
    }

    fn default_config() -> OidcConfig {
        OidcConfig {
            issuer: "http://localhost".to_string(),
            audience: "test".to_string(),
            jwks_ttl_secs: 3600,
            roles_claim: "realm_access.roles".to_string(),
            admin_role: "openshell-admin".to_string(),
            user_role: "openshell-user".to_string(),
        }
    }

    fn claims_with_roles(roles: &[&str]) -> OidcClaims {
        OidcClaims {
            sub: "test-user".to_string(),
            preferred_username: None,
            email: None,
            roles: roles.iter().map(|r| (*r).to_string()).collect(),
            extra: serde_json::Value::Null,
        }
    }

    #[test]
    fn check_role_accepts_matching_role() {
        let claims = claims_with_roles(&["openshell-user"]);
        let config = default_config();
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes", &config).is_ok());
    }

    #[test]
    fn check_role_rejects_missing_role() {
        let claims = claims_with_roles(&["openshell-user"]);
        let config = default_config();
        assert!(check_role(&claims, "/openshell.v1.OpenShell/CreateProvider", &config).is_err());
    }

    #[test]
    fn check_role_admin_has_admin_access() {
        let claims = claims_with_roles(&["openshell-admin", "openshell-user"]);
        let config = default_config();
        assert!(check_role(&claims, "/openshell.v1.OpenShell/CreateProvider", &config).is_ok());
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes", &config).is_ok());
    }

    #[test]
    fn check_role_rejects_empty_roles() {
        let claims = claims_with_roles(&[]);
        let config = default_config();
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes", &config).is_err());
    }

    #[test]
    fn check_role_skips_when_role_name_empty() {
        // Simulates providers like GitHub that don't emit roles.
        let claims = claims_with_roles(&[]);
        let config = OidcConfig {
            user_role: String::new(),
            admin_role: String::new(),
            ..default_config()
        };
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes", &config).is_ok());
        assert!(check_role(&claims, "/openshell.v1.OpenShell/CreateProvider", &config).is_ok());
    }

    #[test]
    fn check_role_custom_role_names() {
        // Simulates Entra ID with custom role names.
        let claims = claims_with_roles(&["OpenShell.Admin", "OpenShell.User"]);
        let config = OidcConfig {
            admin_role: "OpenShell.Admin".to_string(),
            user_role: "OpenShell.User".to_string(),
            ..default_config()
        };
        assert!(check_role(&claims, "/openshell.v1.OpenShell/CreateProvider", &config).is_ok());
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes", &config).is_ok());
    }

    #[test]
    fn extract_roles_keycloak_path() {
        let json = serde_json::json!({
            "sub": "user1",
            "realm_access": { "roles": ["openshell-user", "openshell-admin"] }
        });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("realm_access.roles");
        assert_eq!(claims.roles, vec!["openshell-user", "openshell-admin"]);
    }

    #[test]
    fn extract_roles_flat_path() {
        // Entra ID / Okta style: roles at top level
        let json = serde_json::json!({
            "sub": "user1",
            "roles": ["OpenShell.Admin", "OpenShell.User"]
        });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("roles");
        assert_eq!(claims.roles, vec!["OpenShell.Admin", "OpenShell.User"]);
    }

    #[test]
    fn extract_roles_groups_path() {
        // Okta style: groups claim
        let json = serde_json::json!({
            "sub": "user1",
            "groups": ["everyone", "openshell-admin"]
        });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("groups");
        assert_eq!(claims.roles, vec!["everyone", "openshell-admin"]);
    }

    #[test]
    fn extract_roles_missing_claim() {
        let json = serde_json::json!({ "sub": "user1" });
        let mut claims: OidcClaims = serde_json::from_value(json).unwrap();
        claims.extract_roles("realm_access.roles");
        assert!(claims.roles.is_empty());
    }
}
