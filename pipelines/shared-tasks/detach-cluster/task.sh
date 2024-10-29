#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

tmc_api_token="$(cat tmc-api-token-and-tmc-cluster-name/tmc-api-token)"
tmc_cluster_name="$(cat tmc-api-token-and-tmc-cluster-name/tmc-cluster-name)"

export TMC_API_TOKEN="$tmc_api_token"

tmc login --no-configure --stg-stable --name detach-cluster-context
if ! tmc cluster list --name "$tmc_cluster_name" | grep -q 'No clusters to list'; then
  tmc cluster delete --forget "$tmc_cluster_name"
else
  echo "note: cluster '$tmc_cluster_name' does not exist, skipping detachment"
fi
