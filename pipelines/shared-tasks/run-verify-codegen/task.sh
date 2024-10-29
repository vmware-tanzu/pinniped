#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go version

cd pinniped

versions_file="./hack/lib/kube-versions.txt"

if [[ -x "$versions_file" ]]; then
  echo "could not find $versions_file"
  exit 1
fi

if ! grep -q -F "${KUBE_MINOR_VERSION}" "$versions_file"; then
  echo "WARNING: Could not find minor version ${KUBE_MINOR_VERSION} in $versions_file"
  echo "WARNING: This should only happen if this version was recently added or removed by a PR but this job has not been updated yet."
  echo "WARNING: Once the PR has been merged to main, please remember to add or remove the appropriate tasks from this job."
  echo "WARNING: Skipping codegen verification for this Kube minor version!!"
  exit 0
fi

KUBE_VERSION="$(grep -F "${KUBE_MINOR_VERSION}" "$versions_file")"

echo "Using patch version $KUBE_VERSION for codegen..."

CONTAINED=1 ./hack/lib/verify-codegen.sh "${KUBE_VERSION}"
