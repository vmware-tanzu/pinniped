#!/usr/bin/env bash
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

if [ "${BASH_VERSINFO[0]}" -lt 5 ]; then
  echo "ERROR: invalid BASH version"
  echo "       using    v${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}.${BASH_VERSINFO[2]} @ ${BASH}"
  echo "       require  v5.0.0+"
  echo "brew install bash # on macOS to install a viable version"
  exit 1
fi

if [[ -z "${GOPATH:-''}" ]]; then
  export GOPATH=/tmp/go-api-repo
fi

MOD_PATH="pkg/client-go"
MOD_ROOT="${SCRIPT_ROOT}/${MOD_PATH}"

(
  cd "${MOD_ROOT}"

  CODEGEN_PKG=${CODEGEN_PKG:-$(go mod vendor && ls -d -1 vendor/k8s.io/code-generator 2>/dev/null)}

  HEADER_FILE="${SCRIPT_ROOT}/hack/boilerplate.go.txt"
  OUTPUT_DIR="${TMPDIR:-/tmp}/code_generator_output"
  mkdir -p "${OUTPUT_DIR}"

  bash "${CODEGEN_PKG}/generate-groups.sh" "client,lister,informer" \
    github.com/suzerain-io/placeholder-name/pkg/client-go/generated \
    github.com/suzerain-io/placeholder-name/pkg/api \
    "placeholder:v1alpha1" \
    --output-base "${OUTPUT_DIR}" \
    --go-header-file "${HEADER_FILE}"

  cp -a "${OUTPUT_DIR}/github.com/suzerain-io/placeholder-name/${MOD_PATH}/" "${MOD_ROOT}/"

  rm -rf "${OUTPUT_DIR}"
)
