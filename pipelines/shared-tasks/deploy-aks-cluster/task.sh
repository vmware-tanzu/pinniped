#!/bin/bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd deploy-aks-cluster-output
az login \
  --service-principal \
  --tenant "$AZURE_TENANT" \
  --username "$AZURE_USERNAME" \
  --password "$AZURE_PASSWORD"

echo
echo "Trying to use Kubernetes version $KUBE_VERSION"

# Look up the latest AKS Kubernetes version corresponding to $KUBE_VERSION.
AKS_VERSIONS="$(az aks get-versions --location "$AZURE_REGION" -o json \
  | jq -r '.values[].patchVersions|keys' \
  | jq -s flatten \
  | jq -r 'join("\n")' \
  | sort -rn)"
echo
echo "Found all versions of Kubernetes supported by AKS:"
echo "$AKS_VERSIONS"

AKS_VERSION="$(echo "$AKS_VERSIONS" | grep -F "$KUBE_VERSION" | head -1)"
echo
echo "Selected AKS version $AKS_VERSION"

# The cluster name becomes the name of the lock in the pool.
CLUSTER_NAME="aks-$(openssl rand -hex 8)"
echo "$CLUSTER_NAME" > name

# Start the cluster.
az aks create \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --kubernetes-version "$AKS_VERSION" \
  --node-count 1 \
  --generate-ssh-keys \
  --enable-managed-identity

# Get an admin kubeconfig (client cert + long-lived token), which becomes the value of the lock in the pool.
az aks get-credentials \
  --name "$CLUSTER_NAME" \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --admin \
  --file metadata
chmod 0644 metadata
