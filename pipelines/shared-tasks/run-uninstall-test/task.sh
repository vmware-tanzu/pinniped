#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

export KUBECONFIG="$PWD/cluster-pool/metadata"

# See https://github.com/concourse/registry-image-resource#in-fetch-the-images-rootfs-and-metadata
export IMAGE_DIGEST=$(cat ci-build-image/digest)
export IMAGE_REPO="$(cat ci-build-image/repository)"

# Get an absolute path to the test script.
TEST_SCRIPT="$PWD/$TEST_SCRIPT"

pushd pinniped >/dev/null
"$TEST_SCRIPT"
popd >/dev/null
