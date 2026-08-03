#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Verify per-gateway access control across two Podman-backed gateways sharing
# one Keycloak instance.
#
# Usage:
#   scripts/multi-gateway/isolation-test.sh <roles|client|realm>
#
# Topologies (see README.md):
#   roles   one realm, one client, per-gateway admin_role/user_role
#   client  one client per gateway, per-gateway audience + client roles
#   realm   one realm per gateway, per-gateway issuer
#
# Requires: podman, grpcurl, jq, curl, cargo. Builds the gateway from source.

set -euo pipefail

TOPOLOGY="${1:-}"
case "$TOPOLOGY" in
  roles | client | realm) ;;
  *)
    echo "Usage: $0 <roles|client|realm>" >&2
    exit 2
    ;;
esac

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
# shellcheck source=e2e/support/gateway-common.sh
source "${ROOT}/e2e/support/gateway-common.sh"

KC_PORT="${KC_PORT:-8190}"
KC_NAME="openshell-multigw-kc"
KC_IMAGE="${KEYCLOAK_IMAGE:-quay.io/keycloak/keycloak:24.0}"
WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/openshell-multigw.XXXXXX")"
REALM_DIR="${WORKDIR}/realms"
GW_A_PID=""; GW_B_PID=""; NET_A=""; NET_B=""
FAILURES=0

cleanup() {
  local code=$?
  [ -n "$GW_A_PID" ] && kill "$GW_A_PID" 2>/dev/null || true
  [ -n "$GW_B_PID" ] && kill "$GW_B_PID" 2>/dev/null || true
  wait 2>/dev/null || true
  for net in "$NET_A" "$NET_B"; do
    [ -n "$net" ] && podman network rm "$net" >/dev/null 2>&1 || true
  done
  podman rm -f "$KC_NAME" >/dev/null 2>&1 || true
  if [ "$code" -ne 0 ]; then
    echo "=== gateway A log ==="; tail -30 "${WORKDIR}/a.log" 2>/dev/null || true
    echo "=== gateway B log ==="; tail -30 "${WORKDIR}/b.log" 2>/dev/null || true
  fi
  rm -rf "$WORKDIR"
  exit "$code"
}
trap cleanup EXIT

for tool in podman grpcurl jq curl python3; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done

# --- Keycloak ---------------------------------------------------------------
python3 "${ROOT}/scripts/multi-gateway/make-realms.py" "$TOPOLOGY" --out-dir "$REALM_DIR"

podman rm -f "$KC_NAME" >/dev/null 2>&1 || true
podman run -d --name "$KC_NAME" -p "${KC_PORT}:8080" \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "${REALM_DIR}:/opt/keycloak/data/import:ro,z" \
  "$KC_IMAGE" start-dev --import-realm >/dev/null

case "$TOPOLOGY" in
  roles)  REALM_A=rolename;  REALM_B=rolename ;;
  client) REALM_A=perclient; REALM_B=perclient ;;
  realm)  REALM_A=gateway-a; REALM_B=gateway-b ;;
esac
ISS_A="http://localhost:${KC_PORT}/realms/${REALM_A}"
ISS_B="http://localhost:${KC_PORT}/realms/${REALM_B}"

echo "Waiting for Keycloak (topology: ${TOPOLOGY})..."
for _ in $(seq 1 90); do
  if curl -sf "${ISS_A}/.well-known/openid-configuration" >/dev/null 2>&1 &&
     curl -sf "${ISS_B}/.well-known/openid-configuration" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
curl -sf "${ISS_A}/.well-known/openid-configuration" >/dev/null || {
  echo "Keycloak realm import failed"; podman logs --tail 30 "$KC_NAME"; exit 1; }
echo "Keycloak ready."

# --- gateways ---------------------------------------------------------------
e2e_build_gateway_binaries "$ROOT" TARGET_DIR GATEWAY_BIN CLI_BIN
PODMAN_SOCKET="${OPENSHELL_PODMAN_SOCKET:-${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock}"
SUPERVISOR_IMAGE="${OPENSHELL_SUPERVISOR_IMAGE:-openshell/supervisor:dev}"
SANDBOX_IMAGE="${OPENSHELL_SANDBOX_IMAGE:-ghcr.io/nvidia/openshell-community/sandboxes/base:latest}"

# start_gateway <label> <issuer> <audience> <roles_claim> <admin_role> <user_role>
start_gateway() {
  local label=$1 issuer=$2 audience=$3 roles_claim=$4 admin_role=$5 user_role=$6
  local dir="${WORKDIR}/${label}"
  mkdir -p "${dir}/state"

  local port health_port
  port=$(e2e_pick_port)
  health_port=$(e2e_pick_port)

  e2e_generate_pki "$GATEWAY_BIN" "${dir}/pki" "host.containers.internal" >/dev/null

  local net="openshell-multigw-${label}-$$"
  podman network create --driver bridge --label openshell.managed=true "$net" >/dev/null
  eval "NET_${label^^}=\$net"

  e2e_generate_gateway_jwt "${dir}/state/jwt"
  local cfg="${dir}/state/gateway.toml"
  cp "${ROOT}/deploy/rpm/gateway.toml.default" "$cfg"
  {
    e2e_write_gateway_jwt_config "${dir}/state/jwt" "openshell-multigw-${label}"
    printf '\n[openshell.drivers.podman]\n'
    printf 'network_name = %s\n' "$(e2e_toml_string "$net")"
    printf 'gateway_port = %s\n' "$port"
    printf 'default_image = %s\n' "$(e2e_toml_string "$SANDBOX_IMAGE")"
    printf 'image_pull_policy = "missing"\n'
    printf 'stop_timeout_secs = 15\n'
    printf 'supervisor_image = %s\n' "$(e2e_toml_string "$SUPERVISOR_IMAGE")"
    printf 'guest_tls_ca = %s\n' "$(e2e_toml_string "${dir}/pki/ca.crt")"
    printf 'guest_tls_cert = %s\n' "$(e2e_toml_string "${dir}/pki/client/tls.crt")"
    printf 'guest_tls_key = %s\n' "$(e2e_toml_string "${dir}/pki/client/tls.key")"
    printf 'socket_path = %s\n' "$(e2e_toml_string "$PODMAN_SOCKET")"
  } >>"$cfg"

  XDG_STATE_HOME="${dir}/state" "$GATEWAY_BIN" \
    --config "$cfg" \
    --port "$port" \
    --health-port "$health_port" \
    --tls-cert "${dir}/pki/server/tls.crt" \
    --tls-key "${dir}/pki/server/tls.key" \
    --db-url "sqlite:${dir}/state/gateway.db?mode=rwc" \
    --oidc-issuer "$issuer" \
    --oidc-audience "$audience" \
    --oidc-roles-claim "$roles_claim" \
    --oidc-admin-role "$admin_role" \
    --oidc-user-role "$user_role" \
    --log-level info >"${WORKDIR}/${label}.log" 2>&1 &

  local pid=$!
  eval "GW_${label^^}_PID=\$pid"

  for _ in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || {
      echo "gateway ${label} exited early"; tail -30 "${WORKDIR}/${label}.log"; exit 1; }
    curl -sf "http://127.0.0.1:${health_port}/healthz" >/dev/null 2>&1 && break
    sleep 2
  done
  curl -sf "http://127.0.0.1:${health_port}/healthz" >/dev/null 2>&1 || {
    echo "gateway ${label} never became healthy"; tail -30 "${WORKDIR}/${label}.log"; exit 1; }

  eval "GW_${label^^}_PORT=\$port"
  eval "GW_${label^^}_CA=\${dir}/pki/ca.crt"
  echo "Gateway ${label}: aud=${audience} roles_claim=${roles_claim} admin_role=${admin_role}"
}

case "$TOPOLOGY" in
  roles)
    start_gateway a "$ISS_A" openshell-cli realm_access.roles gw-a-admin gw-a-user
    start_gateway b "$ISS_B" openshell-cli realm_access.roles gw-b-admin gw-b-user
    ;;
  client)
    start_gateway a "$ISS_A" openshell-gw-a \
      resource_access.openshell-gw-a.roles openshell-admin openshell-user
    start_gateway b "$ISS_B" openshell-gw-b \
      resource_access.openshell-gw-b.roles openshell-admin openshell-user
    ;;
  realm)
    start_gateway a "$ISS_A" openshell-cli realm_access.roles openshell-admin openshell-user
    start_gateway b "$ISS_B" openshell-cli realm_access.roles openshell-admin openshell-user
    ;;
esac

# --- helpers ----------------------------------------------------------------
# token <issuer> <client_id> <user> <password>
token() {
  curl -s -X POST "$1/protocol/openid-connect/token" \
    -d grant_type=password -d "client_id=$2" \
    -d "username=$3" -d "password=$4" -d scope=openid | jq -r .access_token
}

# call <ca> <port> <token> <method> -> gRPC status code, or OK
call() {
  local out
  out=$(grpcurl -import-path "${ROOT}/proto" -proto openshell.proto \
    -cacert "$1" -H "authorization: Bearer $3" \
    -d '{}' "127.0.0.1:$2" "$4" 2>&1) || true
  if grep -qE '^[[:space:]]*Code:[[:space:]]' <<<"$out"; then
    grep -m1 -E '^[[:space:]]*Code:[[:space:]]' <<<"$out" | sed 's/.*Code:[[:space:]]*//'
  elif grep -qiE 'error|failed' <<<"$out"; then
    printf 'ERROR: %s' "$(tr '\n' ' ' <<<"$out" | cut -c1-90)"
  else
    echo OK
  fi
}

expect() {
  if [ "$2" = "$3" ]; then
    printf '  PASS  %-52s %s\n' "$1" "$3"
  else
    printf '  FAIL  %-52s want=%s got=%s\n' "$1" "$2" "$3"
    FAILURES=$((FAILURES + 1))
  fi
}

INFO=openshell.v1.OpenShell/GetGatewayInfo
LIST=openshell.v1.OpenShell/ListSandboxes

echo
case "$TOPOLOGY" in
  roles)
    T_ALICE=$(token "$ISS_A" openshell-cli alice@test alice)
    T_BOB=$(token "$ISS_A" openshell-cli bob@test bob)
    T_CAROL=$(token "$ISS_A" openshell-cli carol@test carol)
    echo "=== Per-gateway roles: access follows role names ==="
    expect "alice (gw-a-admin) admin on A" OK "$(call "$GW_A_CA" "$GW_A_PORT" "$T_ALICE" "$INFO")"
    expect "bob (no gw-a-* role) on A" PermissionDenied "$(call "$GW_A_CA" "$GW_A_PORT" "$T_BOB" "$INFO")"
    expect "carol (no gateway roles) on A" PermissionDenied "$(call "$GW_A_CA" "$GW_A_PORT" "$T_CAROL" "$INFO")"
    expect "bob (gw-b-admin) admin on B" OK "$(call "$GW_B_CA" "$GW_B_PORT" "$T_BOB" "$INFO")"
    expect "alice (gw-b-user only) admin on B" PermissionDenied "$(call "$GW_B_CA" "$GW_B_PORT" "$T_ALICE" "$INFO")"
    echo
    echo "=== Shared audience: one token authenticates at BOTH gateways ==="
    echo "  alice's token at A: $(call "$GW_A_CA" "$GW_A_PORT" "$T_ALICE" "$INFO") (admin)"
    echo "  a gateway receiving this token can replay it against the other"
    echo
    echo "=== Role-exempt RPCs are reachable without any gateway role ==="
    echo "  carol GetCurrentUser on A:   $(call "$GW_A_CA" "$GW_A_PORT" "$T_CAROL" openshell.v1.OpenShell/GetCurrentUser)"
    echo "  carol GetGatewayConfig on A: $(call "$GW_A_CA" "$GW_A_PORT" "$T_CAROL" openshell.v1.OpenShell/GetGatewayConfig)"
    ;;
  client)
    T_A_FOR_A=$(token "$ISS_A" openshell-gw-a admin-a@test admin-a)
    T_A_FOR_B=$(token "$ISS_B" openshell-gw-b admin-a@test admin-a)
    T_B_FOR_B=$(token "$ISS_B" openshell-gw-b admin-b@test admin-b)
    T_LEAKY=$(token "$ISS_A" openshell-gw-leaky admin-a@test admin-a)
    echo "=== Per-gateway client: admin is scoped to the gateway's client ==="
    expect "admin-a on A (own gateway)" OK "$(call "$GW_A_CA" "$GW_A_PORT" "$T_A_FOR_A" "$INFO")"
    expect "admin-b on B (own gateway)" OK "$(call "$GW_B_CA" "$GW_B_PORT" "$T_B_FOR_B" "$INFO")"
    expect "admin-a on B (token minted for B)" PermissionDenied "$(call "$GW_B_CA" "$GW_B_PORT" "$T_A_FOR_B" "$INFO")"
    echo
    echo "=== Audience confines the token to one gateway ==="
    expect "gateway-A token replayed at B" Unauthenticated "$(call "$GW_B_CA" "$GW_B_PORT" "$T_A_FOR_A" "$INFO")"
    expect "gateway-A token replayed at B (user RPC)" Unauthenticated "$(call "$GW_B_CA" "$GW_B_PORT" "$T_A_FOR_A" "$LIST")"
    echo
    echo "=== CONTROL: fullScopeAllowed=true client bypasses the boundary ==="
    expect "leaky-client token is admin on A" OK "$(call "$GW_A_CA" "$GW_A_PORT" "$T_LEAKY" "$INFO")"
    ;;
  realm)
    T_ALICE_A=$(token "$ISS_A" openshell-cli alice@test alice)
    T_BOB_B=$(token "$ISS_B" openshell-cli bob@test bob)
    T_ALICE_B=$(token "$ISS_B" openshell-cli alice@test alice)
    echo "=== Per-gateway realm: admin follows the realm behind each gateway ==="
    expect "alice (admin in realm A) on A" OK "$(call "$GW_A_CA" "$GW_A_PORT" "$T_ALICE_A" "$INFO")"
    expect "bob (admin in realm B) on B" OK "$(call "$GW_B_CA" "$GW_B_PORT" "$T_BOB_B" "$INFO")"
    expect "alice (user in realm B) on B" PermissionDenied "$(call "$GW_B_CA" "$GW_B_PORT" "$T_ALICE_B" "$INFO")"
    echo
    echo "=== Cross-realm replay fails at signature verification ==="
    expect "realm-A token at gateway B" Unauthenticated "$(call "$GW_B_CA" "$GW_B_PORT" "$T_ALICE_A" "$INFO")"
    expect "realm-B token at gateway A" Unauthenticated "$(call "$GW_A_CA" "$GW_A_PORT" "$T_BOB_B" "$INFO")"
    SUB_A=$(echo "$T_ALICE_A" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r .sub)
    SUB_B=$(echo "$T_ALICE_B" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r .sub)
    echo
    echo "=== Subjects are realm-scoped (workspace membership is per gateway) ==="
    if [ "$SUB_A" != "$SUB_B" ]; then
      printf '  PASS  %-52s A=%s… B=%s…\n' "alice sub differs across realms" "${SUB_A:0:8}" "${SUB_B:0:8}"
    else
      printf '  FAIL  %-52s identical subjects\n' "alice sub differs across realms"
      FAILURES=$((FAILURES + 1))
    fi
    ;;
esac

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "All expectations met (0 failures)."
else
  echo "${FAILURES} expectation(s) did not match."
  exit 1
fi
