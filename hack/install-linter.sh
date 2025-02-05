#!/usr/bin/env bash

# Copyright 2022-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"

# Print the Go version.
go version

lint_version="v$(cat hack/lib/lint-version.txt)"

# Find the toolchain version from our go.mod file. "go install" pays attention to $GOTOOLCHAIN.
GOTOOLCHAIN=$(sed -rn 's/^toolchain (go[0-9\.]+)$/\1/p' go.mod)
export GOTOOLCHAIN

echo "Installing golangci-lint@${lint_version} using toolchain ${GOTOOLCHAIN}"

# Install the same version of the linter that the pipelines will use
# so you can get the same results when running the linter locally.
go install -v "github.com/golangci/golangci-lint/cmd/golangci-lint@${lint_version}"
golangci-lint --version

echo "Finished. You may need to run 'rehash' in your current shell before using the new version (e.g. if you are using gvm)."
