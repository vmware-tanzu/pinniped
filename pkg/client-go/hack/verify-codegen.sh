#!/usr/bin/env bash
# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

MOD_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

UPDATE_CODEGEN_SCRIPT="${MOD_ROOT}/hack/update-codegen.sh"

TMP_DIFF_MOD_ROOT="${TMPDIR:-/tmp}/verify-codegen-${MOD_ROOT}"
cleanup() {
  rm -rf "${TMP_DIFF_MOD_ROOT}"
}
trap "cleanup" EXIT SIGINT
cleanup

mkdir -p "${TMP_DIFF_MOD_ROOT}"
cp -a "${MOD_ROOT}"/* "${TMP_DIFF_MOD_ROOT}"

"${UPDATE_CODEGEN_SCRIPT}"
echo "diffing ${MOD_ROOT} against freshly generated codegen"
ret=0
diff -Naupr "${MOD_ROOT}" "${TMP_DIFF_MOD_ROOT}" || ret=$?
cp -a "${TMP_DIFF_MOD_ROOT}"/* "${MOD_ROOT}"
if [[ $ret -eq 0 ]]
then
  echo "${MOD_ROOT} up to date."
else
  echo "${MOD_ROOT} is out of date. Please run ${UPDATE_CODEGEN_SCRIPT}"
  exit 1
fi