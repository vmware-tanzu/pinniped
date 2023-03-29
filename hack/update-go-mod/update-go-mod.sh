#!/usr/bin/env bash

# Copyright 2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
ROOT_DIR="$SCRIPT_DIR/../.."

GO_MOD="${ROOT_DIR}/go.mod"

pushd "${SCRIPT_DIR}" > /dev/null
  script=$(go run . "${GO_MOD}")
popd > /dev/null

pushd "${ROOT_DIR}" > /dev/null
  eval "$script"
popd > /dev/null
