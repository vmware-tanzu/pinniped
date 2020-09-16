#!/usr/bin/env bash

# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KUBE_VERSIONS=("$@")

GENERATED_DIR="${ROOT}/generated"
BACKUP_DIR="${GENERATED_DIR}.bak"

# Move the originally generated directory to a backup location
mv "${GENERATED_DIR}" "${BACKUP_DIR}"
mkdir "${GENERATED_DIR}"

# At exit (even on error), copy it back
cleanup() {
    rm -r "${GENERATED_DIR}"
    mv -f "${BACKUP_DIR}" "${GENERATED_DIR}"
}
trap "cleanup" EXIT SIGINT

# Run the code generation into a new empty `./generated` directory.
"${ROOT}/hack/lib/update-codegen.sh" "${KUBE_VERSIONS[@]}"

# Diff each of the chosen Kubernetes versions (but avoid comparing any other versions).
echo "diffing ${GENERATED_DIR} against freshly generated codegen"
ret=0
for kubeVersion in "${KUBE_VERSIONS[@]}"; do
    kubeMinorVersion="$(echo "${kubeVersion}" | cut -d"." -f1-2)"
    generatedVersionDir="${GENERATED_DIR}/${kubeMinorVersion}"
    backupVersionDir="${BACKUP_DIR}/${kubeMinorVersion}"
    diff -Naupr "${backupVersionDir}" "${generatedVersionDir}" || ret=$?
done

# If any of the versions differed, exit nonzero with an error message.
if [[ $ret -eq 0 ]]
then
  echo "${GENERATED_DIR} up to date."
else
  echo "${GENERATED_DIR} is out of date. Please run hack/update.sh"
  exit 1
fi
