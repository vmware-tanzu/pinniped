#!/usr/bin/env bash

# Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
cd "${ROOT}"

# Print the Go version.
go version

lint_version="v$(cat hack/lib/lint-version.txt)"

echo "Installing golangci-lint@${lint_version}"

# Install the same version of the linter that the pipelines will use
# so you can get the same results when running the linter locally.
go install -v "github.com/golangci/golangci-lint/cmd/golangci-lint@${lint_version}"
golangci-lint --version

echo "Finished. You may need to run 'rehash' in your current shell before using the new version (e.g. if you are using gvm)."
