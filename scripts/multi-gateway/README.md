<!--
SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
SPDX-License-Identifier: Apache-2.0
-->

# Multi-Gateway Access Control Harness

Reproduces the per-gateway access control topologies documented in
[docs/reference/gateway-auth.mdx](../../docs/reference/gateway-auth.mdx), and
measures what each one costs at scale.

A single identity provider left at its defaults authorizes every user on every
gateway: all gateways share the `openshell-cli` audience and the realm roles
`openshell-admin` and `openshell-user`. These scripts verify the three
topologies that separate them, and record where each one breaks.

## Scripts

| Script | Purpose |
|---|---|
| `make-realms.py` | Generate Keycloak realm fixtures for one topology |
| `isolation-test.sh` | Run two Podman-backed gateways and assert the boundary holds |
| `scale-test.py` | Provision many gateway clients and measure token issuance |

## Topologies

| Topology | Boundary | Per-gateway settings |
|---|---|---|
| `roles` | Role names, in one shared realm and client | `admin_role`, `user_role` |
| `client` | Audience and client roles | `audience`, `roles_claim` |
| `realm` | Issuer and signing keys | `issuer` |

## Running the isolation tests

Each run builds the gateway from source, starts a Keycloak container and two
Podman-backed gateways, asserts, and tears everything down.

```shell
scripts/multi-gateway/isolation-test.sh roles
scripts/multi-gateway/isolation-test.sh client
scripts/multi-gateway/isolation-test.sh realm
```

Requires `podman`, `grpcurl`, `jq`, `curl`, `python3`, and `cargo`. Override
`KC_PORT`, `KEYCLOAK_IMAGE`, `OPENSHELL_SUPERVISOR_IMAGE`, or
`OPENSHELL_SANDBOX_IMAGE` as needed.

## Running the scale test

Start a Keycloak with the shipped realm, then allow the Admin API over plain
HTTP (the master realm requires HTTPS for non-local callers by default):

```shell
mise run keycloak

podman exec openshell-keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master --user admin --password admin
podman exec openshell-keycloak /opt/keycloak/bin/kcadm.sh update realms/master \
  -s sslRequired=NONE
```

Then provision and measure:

```shell
scripts/multi-gateway/scale-test.py all --count 10000
```

To isolate client-lookup cost from password hashing, set the realm password
policy to `hashIterations(1)` and authenticate once before benchmarking.
Otherwise ~150ms of PBKDF2 dominates every measurement.

## Findings

Measured on a single-node Keycloak 24.0 with a local PostgreSQL, against
Podman-backed gateways built from this tree. Absolute numbers are specific to
that setup; the relative results are what matter.

### Isolation

- All three topologies keep an admin on one gateway from being an admin on
  another.
- `client` and `realm` confine a token to a single gateway. Replaying a token
  at another gateway fails during authentication: `InvalidAudience` for
  `client`, `unknown signing key` for `realm`.
- `roles` does not. One token is valid at every gateway the user can reach, so
  a gateway that receives it can replay it against the others. This matters
  when gateways do not trust each other.
- `roles` also leaves `GetCurrentUser` and `GetGatewayConfig` reachable by any
  authenticated user in the realm. Both RPCs deliberately require no role, so
  no choice of role names gates them.

### `fullScopeAllowed` is load-bearing for the `client` topology

Keycloak defaults `fullScopeAllowed` to `true`, which puts every role a user
holds into the token regardless of which client requested it. Combined with the
audience-resolve mapper in Keycloak's built-in `roles` client scope, a token
minted for any client in the realm then carries the other gateways' client IDs
in `aud` and their admin roles in `resource_access` — and every gateway in the
realm accepts it as a platform admin.

`isolation-test.sh client` provisions an `openshell-gw-leaky` client left at
the default to demonstrate this. It is a control, not a recommendation.

### Scale

- **Client count is not a constraint.** A realm holding 10,000 gateway clients
  issued tokens at the same rate as a realm holding one (~2,450/s, p50 ~6ms
  over a full sweep of all 10,000). Raising the `realms` Infinispan cache from
  its 10,000-entry default to 40,000 made no measurable difference on a local
  database.
- **Bulk realm import is the real bottleneck.** A realm import containing
  10,000 clients runs as a single transaction and did not complete in 35
  minutes on PostgreSQL. The same 10,000 clients created incrementally through
  the Admin REST API took 8 seconds.
- **Realm count is the expensive axis.** Keycloak degrades on realm count well
  before client or role count. Use `realm` for a handful of trust domains, not
  one realm per user or per sandbox.
- **The `roles` topology has a per-user ceiling.** The roles claim carries every
  role the user holds and the token travels in a gRPC header capped at 16 KB.
  Measured: 201 roles produced a 5.4 KB token and worked; 2,001 roles produced
  a 44 KB token and failed with `header list size to send violates the maximum
  size (16384 bytes)`. At roughly 22 bytes per role that puts the ceiling in
  the low hundreds of gateways per user. The failure surfaces as a transport
  error, not an authorization error.

### Caveats

- The database was local, so cache misses are cheap. Keycloak's guidance about
  concurrent client counts overflowing the caches assumes a real round trip;
  a remote or loaded database would show more from cache tuning than this
  harness did.
- 10,000 clients against a 10,000-entry cache is barely over capacity, so cache
  thrash was minimal by construction.
- Single node, single JVM. These are not production sizing numbers.
