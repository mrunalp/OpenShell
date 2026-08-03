#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate Keycloak realm fixtures for the multi-gateway isolation topologies.

Each topology separates two gateways a different way. See README.md.

  roles   one realm, one client, per-gateway realm roles (gw-a-*, gw-b-*)
  client  one realm, one client per gateway, client roles + audience mapper
  realm   one realm per gateway, distinct issuer and signing keys

Usage:
  make-realms.py <roles|client|realm> --out-dir DIR
"""

import argparse
import copy
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BASE_REALM = REPO_ROOT / "scripts" / "keycloak-realm.json"

# Client scope shipped in scripts/keycloak-realm.json that emits client roles
# as resource_access.<client_id>.roles. Required by the "client" topology.
GATEWAY_ROLES_SCOPE = "gateway-roles"

DEFAULT_SCOPES = ["openid", "profile", "email", "roles", "web-origins", "acr"]


def load_base():
    with BASE_REALM.open() as fh:
        return json.load(fh)


def make_user(name, password, realm_roles=None, client_roles=None):
    user = {
        "username": f"{name}@test",
        "email": f"{name}@test",
        "emailVerified": True,
        "enabled": True,
        "firstName": name.capitalize(),
        "lastName": "User",
        "credentials": [{"type": "password", "value": password, "temporary": False}],
    }
    if realm_roles:
        user["realmRoles"] = realm_roles
    if client_roles:
        user["clientRoles"] = client_roles
    return user


def topology_roles(base):
    """One realm, one shared client, per-gateway realm roles.

    Gateways differ only by admin_role/user_role. No new clients.
    """
    realm = copy.deepcopy(base)
    realm["realm"] = "rolename"
    for role in ("gw-a-admin", "gw-a-user", "gw-b-admin", "gw-b-user"):
        realm["roles"]["realm"].append({"name": role})
    realm["users"] = [
        # admin on gateway A, plain user on gateway B
        make_user("alice", "alice", ["openshell-user", "gw-a-admin", "gw-b-user"]),
        # admin on gateway B only
        make_user("bob", "bob", ["openshell-user", "gw-b-admin"]),
        # no gateway access at all
        make_user("carol", "carol", ["openshell-user"]),
    ]
    return {"rolename": realm}


def gateway_client(client_id, full_scope_allowed):
    return {
        "clientId": client_id,
        "name": client_id,
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "serviceAccountsEnabled": False,
        "redirectUris": ["http://127.0.0.1:*", "http://localhost:*"],
        "webOrigins": ["http://127.0.0.1:*", "http://localhost:*"],
        "attributes": {"pkce.code.challenge.method": "S256"},
        "protocol": "openid-connect",
        # Keycloak defaults this to true, which leaks every client's roles into
        # every token and defeats the isolation. See README.md.
        "fullScopeAllowed": full_scope_allowed,
        "defaultClientScopes": [*DEFAULT_SCOPES, GATEWAY_ROLES_SCOPE],
        "protocolMappers": [
            {
                "name": "aud",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.client.audience": client_id,
                    "access.token.claim": "true",
                    "introspection.token.claim": "true",
                },
            }
        ],
    }


def add_audience_resolve_mapper(realm):
    """Model a stock Keycloak realm's built-in `roles` client scope.

    Stock Keycloak ships an oidc-audience-resolve-mapper in the `roles` scope,
    which adds to `aud` every client the token carries roles for.
    scripts/keycloak-realm.json omits it. Without it the fullScopeAllowed
    bypass is only half reproducible: a leaky client's token carries other
    gateways' roles in resource_access, but `aud` stays narrow so the other
    gateway still rejects it. Both halves are needed to show the real risk.
    """
    for scope in realm["clientScopes"]:
        if scope["name"] == "roles":
            scope.setdefault("protocolMappers", []).append(
                {
                    "name": "audience resolve",
                    "protocol": "openid-connect",
                    "protocolMapper": "oidc-audience-resolve-mapper",
                    "consentRequired": False,
                    "config": {
                        "access.token.claim": "true",
                        "introspection.token.claim": "true",
                    },
                }
            )
            return
    raise SystemExit("base realm has no 'roles' client scope")


def topology_client(base):
    """One realm, one client per gateway, client roles scoped to that client."""
    realm = copy.deepcopy(base)
    realm["realm"] = "perclient"
    add_audience_resolve_mapper(realm)
    realm["clients"].append(gateway_client("openshell-gw-a", False))
    realm["clients"].append(gateway_client("openshell-gw-b", False))
    # Control client left at Keycloak's fullScopeAllowed default, used to
    # demonstrate the cross-gateway admin bypass.
    realm["clients"].append(gateway_client("openshell-gw-leaky", True))
    realm["roles"]["client"] = {
        cid: [{"name": "openshell-admin"}, {"name": "openshell-user"}]
        for cid in ("openshell-gw-a", "openshell-gw-b", "openshell-gw-leaky")
    }
    realm["users"] = [
        make_user(
            "admin-a",
            "admin-a",
            client_roles={
                "openshell-gw-a": ["openshell-admin", "openshell-user"],
                "openshell-gw-b": ["openshell-user"],
                "openshell-gw-leaky": ["openshell-user"],
            },
        ),
        make_user(
            "admin-b",
            "admin-b",
            client_roles={
                "openshell-gw-a": ["openshell-user"],
                "openshell-gw-b": ["openshell-admin", "openshell-user"],
                "openshell-gw-leaky": ["openshell-user"],
            },
        ),
    ]
    return {"perclient": realm}


def topology_realm(base):
    """One realm per gateway. Same usernames, different subjects and keys."""
    out = {}
    for realm_name, admin_user in (("gateway-a", "alice"), ("gateway-b", "bob")):
        realm = copy.deepcopy(base)
        realm["realm"] = realm_name
        realm["users"] = [
            make_user(
                name,
                name,
                ["openshell-admin", "openshell-user"]
                if name == admin_user
                else ["openshell-user"],
            )
            for name in ("alice", "bob")
        ]
        out[realm_name] = realm
    return out


TOPOLOGIES = {
    "roles": topology_roles,
    "client": topology_client,
    "realm": topology_realm,
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("topology", choices=sorted(TOPOLOGIES))
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for stale in args.out_dir.glob("*.json"):
        stale.unlink()

    realms = TOPOLOGIES[args.topology](load_base())
    for name, realm in realms.items():
        path = args.out_dir / f"{name}-realm.json"
        with path.open("w") as fh:
            json.dump(realm, fh, indent=2)
        print(f"wrote {path} (realm={name})")


if __name__ == "__main__":
    main()
