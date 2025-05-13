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

# Temporarily avoid using the race detector for the impersonator package due to https://github.com/kubernetes/kubernetes/issues/128548
# Note that this will exclude the impersonator package from the code coverage for now as a side effect.
# TODO: change this back to using the race detector everywhere
go test -short -timeout 15m -race -coverprofile "${COVERAGE_OUTPUT}" -covermode atomic $(go list ./... | grep -v internal/concierge/impersonator)
go test -short ./internal/concierge/impersonator
