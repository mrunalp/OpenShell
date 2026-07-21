// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Descriptor-pool-based authorization metadata.
//!
//! Reads per-method `(openshell.options.v1.authorization)` annotations from
//! the compiled `FileDescriptorSet` and builds an auth lookup table keyed by
//! gRPC path. This module runs alongside the proc-macro-based tables in
//! `method_authz` during the migration; a cross-validation test ensures both
//! agree before the proc macro is removed.

// Public API consumed by the runtime in Step 2; only tests use it in Step 1.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::LazyLock;

use prost_reflect::{DescriptorPool, Value};

use super::method_authz::{AuthMode, Role};

const AUTHORIZATION_EXTENSION: &str = "openshell.options.v1.authorization";

/// Gateway-served protobuf packages.
const GATEWAY_PACKAGES: &[&str] = &["openshell.v1", "openshell.inference.v1"];

/// Per-method authorization entry decoded from proto annotations.
#[derive(Debug, Clone)]
pub struct DescriptorAuthEntry {
    pub auth_mode: AuthMode,
    pub scope: Option<String>,
    pub workspace_role: Option<String>,
    pub global_role: Option<String>,
}

impl DescriptorAuthEntry {
    /// Map the Phase 2 role fields back to the flat `Role` enum used by the
    /// existing middleware. `global_role: "platform_admin"` and
    /// `workspace_role: "admin"` both map to `Role::Admin`;
    /// `workspace_role: "user"` maps to `Role::User`.
    pub fn effective_role(&self) -> Option<Role> {
        self.global_role.as_deref().map_or_else(
            || {
                self.workspace_role.as_deref().and_then(|wr| match wr {
                    "admin" => Some(Role::Admin),
                    "user" => Some(Role::User),
                    _ => None,
                })
            },
            |gr| match gr {
                "platform_admin" => Some(Role::Admin),
                _ => None,
            },
        )
    }

    /// Returns `true` when this method uses workspace-level authorization
    /// (checked by the handler) rather than global-level (checked by
    /// middleware).
    pub fn is_workspace_scoped(&self) -> bool {
        self.workspace_role.is_some()
    }
}

/// Auth table built from the descriptor pool.
pub struct DescriptorAuthTable {
    entries: HashMap<String, DescriptorAuthEntry>,
}

static TABLE: LazyLock<DescriptorAuthTable> = LazyLock::new(|| {
    DescriptorAuthTable::from_descriptor_set(openshell_core::FILE_DESCRIPTOR_SET)
        .expect("failed to build auth table from descriptor set")
});

impl DescriptorAuthTable {
    fn from_descriptor_set(bytes: &[u8]) -> Result<Self, String> {
        let pool =
            DescriptorPool::decode(bytes).map_err(|e| format!("decode descriptor pool: {e}"))?;

        let auth_ext = pool
            .get_extension_by_name(AUTHORIZATION_EXTENSION)
            .ok_or_else(|| {
                format!("extension {AUTHORIZATION_EXTENSION} not found in descriptor pool")
            })?;

        let mut entries = HashMap::new();

        for service in pool.services() {
            let file = service.parent_file();
            let package = file.package_name();
            if !GATEWAY_PACKAGES.contains(&package) {
                continue;
            }

            for method in service.methods() {
                let path = format!("/{}.{}/{}", package, service.name(), method.name());
                let options = method.options();

                if !options.has_extension(&auth_ext) {
                    return Err(format!("method {path} missing (authorization) option"));
                }

                let auth_value = options.get_extension(&auth_ext);
                let Value::Message(ref auth_msg) = *auth_value else {
                    return Err(format!(
                        "method {path}: authorization option is not a message"
                    ));
                };

                let auth_mode_str = string_field(auth_msg, "auth_mode");
                let workspace_role_str = string_field(auth_msg, "workspace_role");
                let global_role_str = string_field(auth_msg, "global_role");
                let scope_str = string_field(auth_msg, "scope");

                let auth_mode = match auth_mode_str.as_str() {
                    "unauthenticated" => AuthMode::Unauthenticated,
                    "sandbox" => AuthMode::Sandbox,
                    "bearer" => AuthMode::Bearer,
                    "dual" => AuthMode::Dual,
                    other => {
                        return Err(format!("method {path}: unknown auth_mode '{other}'"));
                    }
                };

                let workspace_role = non_empty(workspace_role_str);
                let global_role = non_empty(global_role_str);
                let scope = non_empty(scope_str);

                entries.insert(
                    path,
                    DescriptorAuthEntry {
                        auth_mode,
                        scope,
                        workspace_role,
                        global_role,
                    },
                );
            }
        }

        Ok(Self { entries })
    }
}

fn string_field(msg: &prost_reflect::DynamicMessage, name: &str) -> String {
    msg.get_field_by_name(name)
        .and_then(|v| match &*v {
            Value::String(s) => Some(s.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

fn non_empty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

/// Look up descriptor-pool auth metadata for a gRPC method path.
pub fn lookup(method: &str) -> Option<&'static DescriptorAuthEntry> {
    TABLE.entries.get(method)
}

/// Iterator over all registered method paths.
pub fn all_paths() -> impl Iterator<Item = &'static str> {
    TABLE.entries.keys().map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_proto_rpc_has_authorization_option() {
        let pool = DescriptorPool::decode(openshell_core::FILE_DESCRIPTOR_SET)
            .expect("decode descriptor set");

        let mut missing: Vec<String> = Vec::new();

        for service in pool.services() {
            let file = service.parent_file();
            let package = file.package_name();
            if !GATEWAY_PACKAGES.contains(&package) {
                continue;
            }
            for method in service.methods() {
                let path = format!("/{}.{}/{}", package, service.name(), method.name());
                if lookup(&path).is_none() {
                    missing.push(path);
                }
            }
        }

        assert!(
            missing.is_empty(),
            "RPC methods missing (authorization) option: {missing:?}"
        );
    }

    #[test]
    fn no_duplicate_paths() {
        let paths: Vec<&str> = all_paths().collect();
        let mut seen = Vec::new();
        for path in &paths {
            assert!(
                !seen.contains(path),
                "duplicate path in descriptor auth table: {path}"
            );
            seen.push(path);
        }
    }

    /// Cross-validate descriptor-pool annotations against the proc-macro
    /// annotations. This test ensures the proto annotations are a faithful
    /// mirror of the existing `#[rpc_auth]` attributes before the cutover.
    ///
    /// Known intentional divergences (Phase 2 role changes) are listed in
    /// `KNOWN_ROLE_CHANGES` and excluded from the role comparison.
    #[test]
    fn proto_annotations_match_proc_macro_annotations() {
        use super::super::method_authz;

        // Methods where the proto annotation intentionally changes the role
        // relative to the current proc-macro annotation. These are Phase 2
        // role escalations applied in the proto from the start.
        const KNOWN_ROLE_CHANGES: &[&str] = &[
            // Currently role=user in proc-macro, promoted to
            // global_role=platform_admin in proto.
            "/openshell.v1.OpenShell/GetGatewayConfig",
        ];

        let mut mismatches: Vec<String> = Vec::new();

        for path in method_authz::all_paths() {
            let macro_entry = method_authz::lookup(path).expect("proc-macro lookup should succeed");

            let Some(desc_entry) = lookup(path) else {
                mismatches.push(format!(
                    "{path}: present in proc-macro but missing in descriptor pool"
                ));
                continue;
            };

            // auth_mode must match
            if macro_entry.mode != desc_entry.auth_mode {
                mismatches.push(format!(
                    "{path}: auth_mode mismatch — proc-macro={:?}, descriptor={:?}",
                    macro_entry.mode, desc_entry.auth_mode
                ));
            }

            // scope must match
            let macro_scope = macro_entry.scope.map(String::from);
            if macro_scope != desc_entry.scope {
                mismatches.push(format!(
                    "{path}: scope mismatch — proc-macro={:?}, descriptor={:?}",
                    macro_entry.scope, desc_entry.scope
                ));
            }

            // role must match (unless known divergence)
            if !KNOWN_ROLE_CHANGES.contains(&path) {
                let desc_role = desc_entry.effective_role();
                if macro_entry.role != desc_role {
                    mismatches.push(format!(
                        "{path}: role mismatch — proc-macro={:?}, descriptor={:?}",
                        macro_entry.role, desc_role
                    ));
                }
            }
        }

        // Also check that every descriptor-pool entry has a matching
        // proc-macro entry (catches stale proto annotations).
        for path in all_paths() {
            if method_authz::lookup(path).is_none() {
                mismatches.push(format!(
                    "{path}: present in descriptor pool but missing in proc-macro"
                ));
            }
        }

        assert!(
            mismatches.is_empty(),
            "cross-validation failures:\n{}",
            mismatches.join("\n")
        );
    }
}
