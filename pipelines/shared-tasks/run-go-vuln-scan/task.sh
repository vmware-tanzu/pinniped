#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go version
go install golang.org/x/vuln/cmd/govulncheck@latest

cd pinniped

OPTS="-json -test"

if [[ -n "${BUILD_TAGS:-}" ]]; then
  OPTS="${OPTS} -tags ${BUILD_TAGS}"
fi

OPTS="${OPTS} ./..."

govulncheck ${OPTS}
