#!/usr/bin/env python3

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Provision many gateway clients into a Keycloak realm and measure the cost.

Answers two questions about the one-client-per-gateway topology:

  1. Can a realm hold thousands of gateway clients?
  2. Does token issuance slow down as client count grows?

Bulk realm import is NOT a viable provisioning path at this size: the whole
import runs in a single transaction and does not complete. This script uses
incremental Admin REST API creation instead.

Usage:
  scale-test.py provision --count 10000
  scale-test.py bench --count 10000
  scale-test.py all --count 10000

Prerequisites: a running Keycloak with the target realm imported, and the
master realm reachable over plain HTTP. See README.md.
"""

import argparse
import json
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

DEFAULT_BASE = "http://localhost:8180"
DEFAULT_REALM = "openshell"
# Client scope shipped in scripts/keycloak-realm.json.
GATEWAY_ROLES_SCOPE = "gateway-roles"


class Admin:
    """Admin REST client with a periodically refreshed master-realm token."""

    def __init__(self, base, user="admin", password="admin"):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self._tok = None
        self._at = 0.0
        self._lock = threading.Lock()

    def token(self):
        with self._lock:
            if self._tok and time.time() - self._at < 30:
                return self._tok
            data = urllib.parse.urlencode(
                {
                    "grant_type": "password",
                    "client_id": "admin-cli",
                    "username": self.user,
                    "password": self.password,
                }
            ).encode()
            req = urllib.request.Request(
                f"{self.base}/realms/master/protocol/openid-connect/token", data=data
            )
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    self._tok = json.load(resp)["access_token"]
            except urllib.error.HTTPError as exc:
                body = exc.read().decode(errors="replace")
                if "HTTPS required" in body:
                    raise SystemExit(
                        "Admin API refused plain HTTP. Allow it with:\n"
                        "  podman exec <keycloak> /opt/keycloak/bin/kcadm.sh config "
                        "credentials --server http://localhost:8080 --realm master "
                        "--user admin --password admin\n"
                        "  podman exec <keycloak> /opt/keycloak/bin/kcadm.sh update "
                        "realms/master -s sslRequired=NONE"
                    ) from exc
                raise
            self._at = time.time()
            return self._tok

    def expire(self):
        with self._lock:
            self._at = 0.0


def client_body(client_id):
    return {
        "clientId": client_id,
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "directAccessGrantsEnabled": True,
        "protocol": "openid-connect",
        "fullScopeAllowed": False,
        "redirectUris": ["http://127.0.0.1:*"],
        "defaultClientScopes": [
            "openid",
            "profile",
            "email",
            "roles",
            GATEWAY_ROLES_SCOPE,
            "web-origins",
            "acr",
        ],
        "protocolMappers": [
            {
                "name": "aud",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.client.audience": client_id,
                    "access.token.claim": "true",
                },
            }
        ],
    }


def provision(admin, realm, count, workers):
    def create(index):
        cid = f"openshell-gw-{index:05d}"
        for attempt in range(4):
            try:
                req = urllib.request.Request(
                    f"{admin.base}/admin/realms/{realm}/clients",
                    data=json.dumps(client_body(cid)).encode(),
                    headers={
                        "Authorization": f"Bearer {admin.token()}",
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return resp.status
            except urllib.error.HTTPError as exc:
                if exc.code == 409:
                    return 409  # already exists
                if exc.code == 401:
                    admin.expire()
                    continue
                if attempt == 3:
                    return exc.code
            except OSError:
                if attempt == 3:
                    return -1
            time.sleep(0.5 * (attempt + 1))
        return -1

    start = time.time()
    errors = 0
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for status in pool.map(create, range(count)):
            done += 1
            if status not in (201, 409):
                errors += 1
            if done % 1000 == 0:
                elapsed = time.time() - start
                print(
                    f"  {done}/{count} in {elapsed:.0f}s "
                    f"({done / elapsed:.0f}/s) errors={errors}",
                    flush=True,
                )
    elapsed = time.time() - start
    print(
        f"provisioned {count} clients in {elapsed:.0f}s "
        f"({count / elapsed:.0f}/s), errors={errors}"
    )


def percentile(values, pct):
    values = sorted(v for v in values if v is not None)
    if not values:
        return float("nan")
    index = min(int(len(values) * pct / 100), len(values) - 1)
    return values[index]


def bench(base, realm, count, user, password, workers):
    def latency(index):
        cid = f"openshell-gw-{index:05d}"
        data = urllib.parse.urlencode(
            {
                "grant_type": "password",
                "client_id": cid,
                "username": user,
                "password": password,
                "scope": "openid",
            }
        ).encode()
        req = urllib.request.Request(
            f"{base}/realms/{realm}/protocol/openid-connect/token", data=data
        )
        start = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                resp.read()
            return (time.perf_counter() - start) * 1000
        except OSError:
            return None

    def sweep(label):
        start = time.time()
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(latency, range(count)))
        elapsed = time.time() - start
        ok = [r for r in results if r is not None]
        print(
            f"  {label:22s} {count} tokens in {elapsed:6.1f}s "
            f"({count / elapsed:6.0f}/s) p50={percentile(ok, 50):6.1f}ms "
            f"p95={percentile(ok, 95):7.1f}ms errors={len(results) - len(ok)}"
        )

    def sequential(label, indices):
        values = [latency(i) for i in indices]
        ok = [v for v in values if v is not None]
        if not ok:
            print(f"  {label:22s} all requests failed")
            return
        print(
            f"  {label:22s} n={len(indices):4d} p50={percentile(ok, 50):6.1f}ms "
            f"p95={percentile(ok, 95):7.1f}ms mean={statistics.mean(ok):6.1f}ms "
            f"errors={len(values) - len(ok)}"
        )

    print(f"=== token issuance against {count} clients ===")
    sweep("sweep 1 (cold)")
    sweep("sweep 2 (warmed)")
    step = max(count // 200, 1)
    sequential("spread (200 distinct)", [i * step for i in range(min(200, count))])
    sequential("hot (1 client x200)", [0] * 200)
    print(
        "\nNote: default password hashing (~150ms) dominates and hides client\n"
        "lookup cost. To isolate it, set the realm password policy to\n"
        "hashIterations(1) and re-authenticate once before benchmarking."
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["provision", "bench", "all"])
    parser.add_argument("--base", default=DEFAULT_BASE, help="Keycloak base URL")
    parser.add_argument("--realm", default=DEFAULT_REALM)
    parser.add_argument("--count", type=int, default=10000)
    parser.add_argument("--workers", type=int, default=24)
    parser.add_argument("--user", default="admin@test", help="realm user for bench")
    parser.add_argument("--password", default="admin")
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--admin-password", default="admin")
    args = parser.parse_args()

    if args.mode in ("provision", "all"):
        admin = Admin(args.base, args.admin_user, args.admin_password)
        provision(admin, args.realm, args.count, args.workers)
    if args.mode in ("bench", "all"):
        bench(
            args.base.rstrip("/"),
            args.realm,
            args.count,
            args.user,
            args.password,
            args.workers,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
