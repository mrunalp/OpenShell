#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Verify a binary is fully statically linked.
#
# The supervisor is executed from inside arbitrary sandbox images (Docker
# extraction, Podman image volumes, the Kubernetes copy-self path), so any
# dynamic linkage breaks it on musl-based images and on images whose glibc is
# older than the build host's. Both supported supervisor libc variants (musl
# and glibc-static) must therefore produce a static binary.
#
# This check exists because the failure is silent: `zig cc` accepts `-static`
# for `*-linux-gnu` targets and emits a dynamically linked binary anyway, so a
# toolchain change can quietly downgrade linkage without failing the build.
#
# Accepts both classic static and static-PIE binaries. static-PIE keeps a
# PT_DYNAMIC segment for self-relocation, so the checks are the absence of an
# interpreter (PT_INTERP) and the absence of shared library dependencies
# (DT_NEEDED) rather than the absence of a dynamic section.

usage() {
  echo "Usage: verify-static-binary.sh <binary> [binary ...]" >&2
}

if [[ $# -lt 1 ]]; then
  usage
  exit 2
fi

if ! command -v readelf >/dev/null 2>&1; then
  echo "error: readelf is required to inspect binary linkage" >&2
  exit 2
fi

failed=0

for binary in "$@"; do
  if [[ ! -f $binary ]]; then
    echo "error: binary not found: $binary" >&2
    failed=1
    continue
  fi

  echo "==> Inspecting $binary"
  if command -v file >/dev/null 2>&1; then
    file "$binary" || true
  fi

  interp=$(readelf --program-headers "$binary" 2>/dev/null | grep -c 'INTERP' || true)
  if [[ $interp -ne 0 ]]; then
    echo "error: $binary has a program interpreter (PT_INTERP); it is dynamically linked" >&2
    readelf --program-headers "$binary" 2>/dev/null | grep -A1 'INTERP' >&2 || true
    failed=1
  fi

  needed=$(readelf --dynamic "$binary" 2>/dev/null | grep -c 'NEEDED' || true)
  if [[ $needed -ne 0 ]]; then
    echo "error: $binary depends on shared libraries (DT_NEEDED); it is dynamically linked" >&2
    readelf --dynamic "$binary" 2>/dev/null | grep 'NEEDED' >&2 || true
    failed=1
  fi

  if [[ $interp -eq 0 && $needed -eq 0 ]]; then
    echo "statically linked: no PT_INTERP, no DT_NEEDED"
  fi
done

exit "$failed"
