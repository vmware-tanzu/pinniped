#!/usr/bin/env bash

# Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"

# Print the Go version.
go version

# Install the same version of the linter that is used in the CI pipelines
# so you can get the same results when running the linter locally.
# Whenever the linter is updated in the CI pipelines, it should also be
# updated here to make local development more convenient.
go install -v github.com/golangci/golangci-lint/cmd/golangci-lint@v1.51.2
golangci-lint --version

echo "Finished. You may need to run 'rehash' in your current shell before using the new version (e.g. if you are using gvm)."
