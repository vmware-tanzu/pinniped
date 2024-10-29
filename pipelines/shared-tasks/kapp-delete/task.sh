#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export KUBECONFIG="$PWD/cluster/metadata"
kapp delete --app "${APP_SELECTOR}" --wait-timeout 2m --yes
