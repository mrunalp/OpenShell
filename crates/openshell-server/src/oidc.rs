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

const ROLE_ADMIN: &str = "openshell-admin";
const ROLE_USER: &str = "openshell-user";

/// Returns the role required to call the given gRPC method.
/// Admin methods require `openshell-admin`; all others require `openshell-user`.
pub fn required_role_for_method(path: &str) -> &'static str {
    if ADMIN_METHODS.contains(&path) {
        ROLE_ADMIN
    } else {
        ROLE_USER
    }
}

/// Check that the validated claims include the required role for the method.
pub fn check_role(claims: &OidcClaims, path: &str) -> Result<(), Status> {
    let required = required_role_for_method(path);
    let roles = claims.roles();
    if roles.iter().any(|r| r == required) {
        Ok(())
    } else {
        debug!(
            sub = %claims.sub,
            required_role = required,
            user_roles = ?roles,
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
    #[serde(default)]
    pub realm_access: Option<RealmAccess>,
}

#[derive(Debug, Deserialize)]
pub struct RealmAccess {
    #[serde(default)]
    pub roles: Vec<String>,
}

impl OidcClaims {
    pub fn roles(&self) -> &[String] {
        self.realm_access
            .as_ref()
            .map_or(&[], |ra| ra.roles.as_slice())
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

        Ok(token_data.claims)
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
    fn admin_methods_require_admin_role() {
        assert_eq!(
            required_role_for_method("/openshell.v1.OpenShell/CreateProvider"),
            "openshell-admin"
        );
        assert_eq!(
            required_role_for_method("/openshell.v1.OpenShell/UpdateConfig"),
            "openshell-admin"
        );
        assert_eq!(
            required_role_for_method("/openshell.v1.OpenShell/ApproveDraftChunk"),
            "openshell-admin"
        );
    }

    #[test]
    fn sandbox_methods_require_user_role() {
        assert_eq!(
            required_role_for_method("/openshell.v1.OpenShell/CreateSandbox"),
            "openshell-user"
        );
        assert_eq!(
            required_role_for_method("/openshell.v1.OpenShell/ListSandboxes"),
            "openshell-user"
        );
    }

    fn claims_with_roles(roles: &[&str]) -> OidcClaims {
        OidcClaims {
            sub: "test-user".to_string(),
            preferred_username: None,
            email: None,
            realm_access: Some(RealmAccess {
                roles: roles.iter().map(|r| (*r).to_string()).collect(),
            }),
        }
    }

    #[test]
    fn check_role_accepts_matching_role() {
        let claims = claims_with_roles(&["openshell-user"]);
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes").is_ok());
    }

    #[test]
    fn check_role_rejects_missing_role() {
        let claims = claims_with_roles(&["openshell-user"]);
        assert!(check_role(&claims, "/openshell.v1.OpenShell/CreateProvider").is_err());
    }

    #[test]
    fn check_role_admin_has_admin_access() {
        let claims = claims_with_roles(&["openshell-admin", "openshell-user"]);
        assert!(check_role(&claims, "/openshell.v1.OpenShell/CreateProvider").is_ok());
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes").is_ok());
    }

    #[test]
    fn check_role_rejects_empty_roles() {
        let claims = claims_with_roles(&[]);
        assert!(check_role(&claims, "/openshell.v1.OpenShell/ListSandboxes").is_err());
    }
}
