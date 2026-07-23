// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(target_os = "linux")]

//! End-to-end coverage for interactive OIDC PKCE login and gateway RBAC.
//!
//! The test replaces Linux's `xdg-open` with a recorder, then drives the
//! captured Keycloak login URL with curl. This exercises the same loopback
//! callback and token exchange used by a real browser without requiring a GUI.
//! It logs in as both fixture users and verifies standard-user and admin-only
//! actions against a live Podman-backed gateway.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Output, Stdio};
use std::time::Duration;

use base64::Engine as _;
use openshell_e2e::harness::binary::openshell_cmd;
use serde_json::Value;
use tokio::process::Command;
use url::Url;

struct IdentityScenario {
    gateway_name: &'static str,
    username: &'static str,
    password: &'static str,
    expected_role: &'static str,
    is_admin: bool,
}

#[tokio::test]
async fn browser_pkce_enforces_admin_and_user_actions() {
    let issuer = std::env::var("OPENSHELL_E2E_OIDC_ISSUER")
        .unwrap_or_else(|_| "http://localhost:8180/realms/openshell".to_string());
    let gateway_endpoint = std::env::var("OPENSHELL_E2E_OIDC_GATEWAY_ENDPOINT")
        .expect("OIDC E2E requires a live gateway endpoint");

    for scenario in [
        IdentityScenario {
            gateway_name: "oidc-pkce-admin",
            username: "admin@test",
            password: "admin",
            expected_role: "openshell-admin",
            is_admin: true,
        },
        IdentityScenario {
            gateway_name: "oidc-pkce-user",
            username: "user@test",
            password: "user",
            expected_role: "openshell-user",
            is_admin: false,
        },
    ] {
        run_identity_scenario(&issuer, &gateway_endpoint, &scenario).await;
    }
}

async fn run_identity_scenario(issuer: &str, gateway_endpoint: &str, scenario: &IdentityScenario) {
    let temp = tempfile::tempdir().expect("create isolated test directory");
    let fake_bin = temp.path().join("bin");
    std::fs::create_dir(&fake_bin).expect("create fake bin directory");
    let browser_url_file = temp.path().join("browser-url");
    install_xdg_open_recorder(&fake_bin);

    let path = prepend_path(&fake_bin);
    let mut cli = openshell_cmd();
    cli.args([
        "gateway",
        "add",
        gateway_endpoint,
        "--name",
        scenario.gateway_name,
        "--local",
        "--oidc-issuer",
        issuer,
        "--oidc-scopes",
        "profile email openshell:all",
    ])
    .env("XDG_CONFIG_HOME", temp.path())
    .env("HOME", temp.path())
    .env("PATH", path)
    .env("OPENSHELL_E2E_BROWSER_URL_FILE", &browser_url_file)
    .env_remove("OPENSHELL_GATEWAY")
    .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
    .env_remove("OPENSHELL_NO_BROWSER")
    .env_remove("OPENSHELL_OIDC_CLIENT_SECRET")
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let child = cli.spawn().expect("start openshell PKCE login");
    let authorization_url = wait_for_browser_url(&browser_url_file).await;
    let redirect_uri = assert_pkce_authorization_url(&authorization_url, issuer);

    let cookie_jar = temp.path().join("keycloak-cookies");
    let login_page = curl_get(&authorization_url, &cookie_jar).await;
    let login_action = extract_login_action(&login_page);
    let callback_page = curl_login(
        &login_action,
        &cookie_jar,
        scenario.username,
        scenario.password,
    )
    .await;
    assert!(
        callback_page.contains("Authentication successful"),
        "loopback callback did not return its success page:\n{callback_page}"
    );

    let output = tokio::time::timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .expect("openshell did not finish after receiving the OIDC callback")
        .expect("wait for openshell PKCE login");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "openshell PKCE login failed:\n{combined}"
    );
    assert!(
        combined.contains("Authenticated successfully"),
        "missing successful authentication message:\n{combined}"
    );

    assert_persisted_login(
        temp.path(),
        issuer,
        &redirect_uri,
        scenario.gateway_name,
        scenario.username,
        scenario.expected_role,
    );
    assert_gateway_actions(temp.path(), scenario).await;
    assert_provider_actions(temp.path(), scenario).await;
}

fn install_xdg_open_recorder(bin_dir: &Path) {
    let script = bin_dir.join("xdg-open");
    std::fs::write(
        &script,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$1\" > \"$OPENSHELL_E2E_BROWSER_URL_FILE\"\n",
    )
    .expect("write xdg-open recorder");
    std::fs::set_permissions(&script, Permissions::from_mode(0o755))
        .expect("make xdg-open recorder executable");
}

fn prepend_path(bin_dir: &Path) -> OsString {
    let current = std::env::var_os("PATH").unwrap_or_default();
    std::env::join_paths(
        std::iter::once(bin_dir.to_path_buf()).chain(std::env::split_paths(&current)),
    )
    .expect("construct PATH with xdg-open recorder")
}

async fn wait_for_browser_url(path: &Path) -> String {
    for _ in 0..200 {
        if let Ok(contents) = tokio::fs::read_to_string(path).await {
            let url = contents.trim();
            if !url.is_empty() {
                return url.to_string();
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "xdg-open did not receive an authorization URL within 10 seconds ({})",
        path.display()
    );
}

fn assert_pkce_authorization_url(authorization_url: &str, issuer: &str) -> String {
    let url = Url::parse(authorization_url).expect("authorization URL is valid");
    let expected_path = format!(
        "{}/protocol/openid-connect/auth",
        Url::parse(issuer)
            .expect("issuer URL is valid")
            .path()
            .trim_end_matches('/')
    );
    assert_eq!(url.path(), expected_path);

    let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
    assert_eq!(
        params.get("response_type").map(String::as_str),
        Some("code")
    );
    assert_eq!(
        params.get("client_id").map(String::as_str),
        Some("openshell-cli")
    );
    assert_eq!(
        params.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    let challenge = params
        .get("code_challenge")
        .expect("authorization URL has a PKCE challenge");
    assert_eq!(challenge.len(), 43, "S256 challenge is base64url encoded");
    assert!(
        challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "PKCE challenge must use unpadded base64url"
    );
    assert!(
        params.get("state").is_some_and(|state| !state.is_empty()),
        "authorization URL must contain CSRF state"
    );

    let scopes: Vec<_> = params
        .get("scope")
        .expect("authorization URL has scopes")
        .split_whitespace()
        .collect();
    for expected in ["openid", "profile", "email", "openshell:all"] {
        assert!(scopes.contains(&expected), "missing OIDC scope {expected}");
    }

    let redirect_uri = params
        .get("redirect_uri")
        .expect("authorization URL has a redirect URI");
    let redirect = Url::parse(redirect_uri).expect("redirect URI is valid");
    assert_eq!(redirect.scheme(), "http");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    assert!(
        redirect.port().is_some(),
        "redirect URI has a callback port"
    );
    assert_eq!(redirect.path(), "/callback");
    redirect_uri.clone()
}

async fn curl_get(url: &str, cookie_jar: &Path) -> String {
    let output = Command::new("curl")
        .args(["--fail", "--silent", "--show-error", "--cookie-jar"])
        .arg(cookie_jar)
        .arg(url)
        .output()
        .await
        .expect("run curl for Keycloak login page");
    assert!(
        output.status.success(),
        "failed to load Keycloak login page: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("Keycloak login page is UTF-8")
}

async fn curl_login(action: &str, cookie_jar: &Path, username: &str, password: &str) -> String {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--cookie",
        ])
        .arg(cookie_jar)
        .arg("--cookie-jar")
        .arg(cookie_jar)
        .arg("--data-urlencode")
        .arg(format!("username={username}"))
        .arg("--data-urlencode")
        .arg(format!("password={password}"))
        .arg("--data-urlencode")
        .arg("credentialId=")
        .arg(action)
        .output()
        .await
        .expect("run curl for Keycloak credentials submission");
    assert!(
        output.status.success(),
        "Keycloak login submission failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("OIDC callback page is UTF-8")
}

fn extract_login_action(html: &str) -> String {
    let form_id = html
        .find("id=\"kc-form-login\"")
        .expect("Keycloak page has the login form");
    let form_start = html[..form_id]
        .rfind("<form")
        .expect("Keycloak login form has a start tag");
    let form_end = form_id
        + html[form_id..]
            .find('>')
            .expect("Keycloak login form start tag is closed");
    let form = &html[form_start..form_end];
    let action_start = form
        .find("action=\"")
        .map(|index| index + "action=\"".len())
        .expect("Keycloak login form has an action");
    let action_end = action_start
        + form[action_start..]
            .find('"')
            .expect("Keycloak login action is quoted");
    form[action_start..action_end]
        .replace("&amp;", "&")
        .replace("&#38;", "&")
}

fn assert_persisted_login(
    config_home: &Path,
    issuer: &str,
    redirect_uri: &str,
    gateway_name: &str,
    username: &str,
    expected_role: &str,
) {
    let gateway_dir = config_home
        .join("openshell")
        .join("gateways")
        .join(gateway_name);
    let metadata: Value = read_json(&gateway_dir.join("metadata.json"));
    assert_eq!(metadata["auth_mode"], "oidc");
    assert_eq!(metadata["oidc_issuer"], issuer);
    assert_eq!(metadata["oidc_client_id"], "openshell-cli");
    assert_eq!(metadata["oidc_scopes"], "profile email openshell:all");

    let token: Value = read_json(&gateway_dir.join("oidc_token.json"));
    let access_token = token["access_token"]
        .as_str()
        .expect("stored access token is a string");
    assert!(!access_token.is_empty());
    assert!(
        token["refresh_token"]
            .as_str()
            .is_some_and(|refresh| !refresh.is_empty()),
        "browser flow should persist a refresh token"
    );
    assert_eq!(token["issuer"], issuer);
    assert_eq!(token["client_id"], "openshell-cli");

    let claims = decode_jwt_claims(access_token);
    assert!(jwt_audience_contains(&claims["aud"], "openshell-cli"));
    assert_eq!(claims["azp"], "openshell-cli");
    assert_eq!(claims["preferred_username"], username);
    assert!(
        claims["realm_access"]["roles"]
            .as_array()
            .is_some_and(|roles| roles.iter().any(|role| role == expected_role)),
        "access token should contain the {expected_role} realm role"
    );

    let redirect = Url::parse(redirect_uri).expect("saved redirect URI remains valid");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
}

async fn assert_gateway_actions(config_home: &Path, scenario: &IdentityScenario) {
    let list = run_cli(
        config_home,
        &[
            "--gateway",
            scenario.gateway_name,
            "sandbox",
            "list",
            "--output",
            "json",
        ],
    )
    .await;
    assert!(
        list.status.success(),
        "{} should be allowed to list sandboxes:\n{}",
        scenario.username,
        combined_output(&list)
    );

    let gateway_info = run_cli(
        config_home,
        &["--gateway", scenario.gateway_name, "gateway", "info"],
    )
    .await;

    if scenario.is_admin {
        assert!(
            gateway_info.status.success(),
            "admin should be allowed to inspect gateway info:\n{}",
            combined_output(&gateway_info)
        );
        let info = combined_output(&gateway_info);
        assert!(
            info.to_ascii_lowercase().contains("podman"),
            "gateway info should report the Podman compute driver: {info}"
        );
    } else {
        assert!(
            !gateway_info.status.success(),
            "standard user unexpectedly accessed admin-only gateway info:\n{}",
            combined_output(&gateway_info)
        );
        let denied = combined_output(&gateway_info);
        let compact_denial: String = denied
            .chars()
            .filter(|character| !character.is_whitespace() && *character != '│')
            .collect();
        assert!(
            denied.contains("requires admin privileges")
                && compact_denial.contains("openshell-admin"),
            "standard user denial did not identify the required admin role:\n{denied}"
        );
    }
}

async fn assert_provider_actions(config_home: &Path, scenario: &IdentityScenario) {
    let provider_name = if scenario.is_admin {
        "oidc-pkce-admin-provider"
    } else {
        "oidc-pkce-user-provider"
    };

    let list = run_cli(
        config_home,
        &[
            "--gateway",
            scenario.gateway_name,
            "provider",
            "list",
            "--output",
            "json",
        ],
    )
    .await;
    assert!(
        list.status.success(),
        "{} should be allowed to list providers:\n{}",
        scenario.username,
        combined_output(&list)
    );

    let create = run_cli(
        config_home,
        &[
            "--gateway",
            scenario.gateway_name,
            "provider",
            "create",
            "--name",
            provider_name,
            "--type",
            "generic",
            "--credential",
            "TOKEN=e2e-test-value",
        ],
    )
    .await;

    if scenario.is_admin {
        assert!(
            create.status.success(),
            "admin should be allowed to create providers:\n{}",
            combined_output(&create)
        );

        let get = run_cli(
            config_home,
            &[
                "--gateway",
                scenario.gateway_name,
                "provider",
                "get",
                provider_name,
            ],
        )
        .await;
        assert!(
            get.status.success() && combined_output(&get).contains(provider_name),
            "admin should be able to read the created provider:\n{}",
            combined_output(&get)
        );

        let delete = run_cli(
            config_home,
            &[
                "--gateway",
                scenario.gateway_name,
                "provider",
                "delete",
                provider_name,
            ],
        )
        .await;
        assert!(
            delete.status.success(),
            "admin should be allowed to delete providers:\n{}",
            combined_output(&delete)
        );
    } else {
        assert_admin_role_denial(&create, "create a provider");

        let delete = run_cli(
            config_home,
            &[
                "--gateway",
                scenario.gateway_name,
                "provider",
                "delete",
                provider_name,
            ],
        )
        .await;
        assert_admin_role_denial(&delete, "delete a provider");
    }
}

fn assert_admin_role_denial(output: &Output, action: &str) {
    let denied = combined_output(output);
    let compact_denial: String = denied
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '│')
        .collect();
    assert!(
        !output.status.success() && compact_denial.contains("openshell-admin"),
        "standard user unexpectedly authorized to {action}, or denial omitted the admin role:\n{denied}"
    );
}

async fn run_cli(config_home: &Path, args: &[&str]) -> Output {
    openshell_cmd()
        .arg("--gateway-insecure")
        .args(args)
        .env("XDG_CONFIG_HOME", config_home)
        .env("HOME", config_home)
        .env_remove("OPENSHELL_GATEWAY")
        .env_remove("OPENSHELL_GATEWAY_ENDPOINT")
        .env_remove("OPENSHELL_OIDC_CLIENT_SECRET")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .expect("run openshell authorization action")
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn read_json(path: &Path) -> Value {
    let contents = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("parse {} as JSON: {error}", path.display()))
}

fn decode_jwt_claims(token: &str) -> Value {
    let payload = token.split('.').nth(1).expect("access token is a JWT");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("decode JWT claims");
    serde_json::from_slice(&bytes).expect("parse JWT claims")
}

fn jwt_audience_contains(audience: &Value, expected: &str) -> bool {
    audience.as_str() == Some(expected)
        || audience
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value == expected))
}
