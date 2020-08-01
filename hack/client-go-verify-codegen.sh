#!/usr/bin/env bash
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
MOD_ROOT="${SCRIPT_ROOT}/pkg/client-go"

UPDATE_CODEGEN_SCRIPT="hack/client-go-update-codegen.sh"

DIFF_ROOT="${MOD_ROOT}"
_tmp="${SCRIPT_ROOT}/_tmp"
TMP_DIFF_ROOT="${_tmp}/${MOD_ROOT}"

cleanup() {
  rm -rf "${_tmp}"
}
trap "cleanup" EXIT SIGINT

cleanup

mkdir -p "${TMP_DIFF_ROOT}"
cp -a "${DIFF_ROOT}"/* "${TMP_DIFF_ROOT}"

"${SCRIPT_ROOT}/${UPDATE_CODEGEN_SCRIPT}"
echo "diffing ${DIFF_ROOT} against freshly generated codegen"
ret=0
diff -Naupr "${DIFF_ROOT}" "${TMP_DIFF_ROOT}" || ret=$?
cp -a "${TMP_DIFF_ROOT}"/* "${DIFF_ROOT}"
if [[ $ret -eq 0 ]]
then
  echo "${DIFF_ROOT} up to date."
else
  echo "${DIFF_ROOT} is out of date. Please run ${UPDATE_CODEGEN_SCRIPT}"
  exit 1
fi
