#!/usr/bin/env bash

# Copyright 2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

GO_MOD="${SCRIPT_DIR}/../../go.mod"

pushd "${SCRIPT_DIR}" > /dev/null
  go run . "${GO_MOD}"
popd > /dev/null
