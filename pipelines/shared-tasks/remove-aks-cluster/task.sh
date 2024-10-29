#!/bin/bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

CLUSTER_NAME=$(cat aks-cluster-pool/name)
export CLUSTER_NAME
export KUBECONFIG="aks-cluster-pool/metadata"

az login \
  --service-principal \
  --tenant "$AZURE_TENANT" \
  --username "$AZURE_USERNAME" \
  --password "$AZURE_PASSWORD"

echo "Removing $CLUSTER_NAME..."
az aks delete --name "$CLUSTER_NAME" --resource-group "$AZURE_RESOURCE_GROUP" --yes
