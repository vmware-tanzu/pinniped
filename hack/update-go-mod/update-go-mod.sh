#!/usr/bin/env bash

# Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ROOT_DIR="$SCRIPT_DIR/../.."

GO_MOD="${ROOT_DIR}/go.mod"

pushd "${SCRIPT_DIR}" >/dev/null
script=$(go run . "${GO_MOD}" overrides.conf)
popd >/dev/null

# Print to screen for debugging purposes.
echo "$script"

pushd "${ROOT_DIR}" >/dev/null
eval "$script"
popd >/dev/null

# This script assumes that you are using the latest version of Go so it can detect its
# version and update all the go.mod files to use that version.
go_version="$(go version | cut -d ' ' -f3 | sed 's/^go//')"
echo "Using Go version $go_version to update toolchain directives in go.mod files..."

pushd "${ROOT_DIR}" >/dev/null
# Find all go.mod files that include a toolchain directive.
grep -E -l '^toolchain ' $(find . -name go.mod) | while IFS= read -r gomod_file; do
  pushd "$(dirname "$gomod_file")" >/dev/null
  echo "Updating toolchain in $gomod_file"
  # Also update toolchain directive in go.mod to match the version of Go used by this job.
  go get toolchain@"$(go version | cut -d ' ' -f3 | sed 's/^go//')"
  popd >/dev/null
done
popd >/dev/null
