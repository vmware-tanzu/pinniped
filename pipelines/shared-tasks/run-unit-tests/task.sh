#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
go version

COVERAGE_OUTPUT="$PWD/unit-test-coverage/coverage.txt"
export KUBE_CACHE_MUTATION_DETECTOR=true
export KUBE_PANIC_WATCH_DECODE_ERROR=true

export GOCACHE="$PWD/cache/gocache"
export GOMODCACHE="$PWD/cache/gomodcache"

cd pinniped
go test -short -timeout 20m -race -coverprofile "${COVERAGE_OUTPUT}" -covermode atomic ./...
