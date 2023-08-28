#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

echo "-X 'go.pinniped.dev/internal/pversion.gitVersion=$KUBE_GIT_VERSION'"
