#!/usr/bin/env bash

# Copyright 2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Sometimes something goes wrong with a AKS test job's cleanup and a
# AKS cluster gets orphaned, meaning that it is still running but no
# CI job is aware to clean it up.
#
# Find and delete all orphaned AKS clusters by deleting those which:
# 1. Are running in Azure with a name that indicates that it was auto-created for testing,
# 2. And are older than some number of hours since their creation time.
#
# Params are AZURE_TENANT, AZURE_USERNAME, AZURE_PASSWORD, AZURE_SUBSCRIPTION_ID, AZURE_RESOURCE_GROUP.

set -euo pipefail

# Login.
az login \
  --service-principal \
  --tenant "$AZURE_TENANT" \
  --username "$AZURE_USERNAME" \
  --password "$AZURE_PASSWORD"

# List all resources in the subscription. Using this API because it reveals the creation timestamp of every resource,
# including the AKS clusters. Querying one specific AKS cluster does not return the creation timestamp. :(
az rest \
  --method GET \
  --url "https://management.azure.com/subscriptions/${AZURE_SUBSCRIPTION_ID}/resources" \
  --url-parameters api-version=2024-08-01 \$expand=createdTime >all-resources.json

if [[ $(jq '.value | length' all-resources.json) == "0" ]]; then
  echo "No resources were found in the subscription. Does the service account have permissions to list all resources?"
  exit 1
fi

# Filter resources by clusters in the expected resource group.
# Write another file where each line is a cluster name, followed by a space, followed by its creation time.
cat all-resources.json |
  jq -r ".value.[] | select(.type == \"Microsoft.ContainerService/managedClusters\") | select(.id | contains(\"/resourceGroups/${AZURE_RESOURCE_GROUP}/\")) | \"\(.name) \(.createdTime)\"" >all-clusters.txt

echo "Found all clusters in expected resource group:"
cat all-clusters.txt
echo

# Remove clusters with unexpected name formats. They might have been created manually for testing.
cat all-clusters.txt | grep -E '^aks-[a-f0-9]+ ' >ci-clusters.txt

echo "Only those clusters with expected naming convention:"
cat ci-clusters.txt
echo

now_in_seconds_since_epoch=$(date +"%s")
hours_ago_to_delete=2
clusters_to_remove=()

# Loop over each line in the file. Decide which clusters are too old.
while IFS="" read -r line || [ -n "$line" ]; do
  cluster_name=$(echo "$line" | cut -d ' ' -f1)
  creation_time=$(echo "$line" | cut -d ' ' -f2)
  # UTC date format example: 2025-01-03T20:13:02.5855661Z
  # Note that this date command may not work on MacOS.
  creation_time_seconds_since_epoch=$(date -u -d "$creation_time" '+%s')
  if (($((now_in_seconds_since_epoch - creation_time_seconds_since_epoch)) > $((hours_ago_to_delete * 60 * 60)))); then
    clusters_to_remove+=("$cluster_name")
    echo "$cluster_name $creation_time (older than $hours_ago_to_delete hours)"
  else
    echo "$cluster_name $creation_time (less than $hours_ago_to_delete hours old)"
  fi
done <ci-clusters.txt

# Remove any clusters that we decided are too old above.
echo
if [[ ${#clusters_to_remove[@]} -eq 0 ]]; then
  echo "No old orphaned AKS clusters found to remove."
else
  echo "Planned to remove ${#clusters_to_remove[@]} AKS clusters(s) which are older than $hours_ago_to_delete hours: ${clusters_to_remove[*]} ..."

  for cluster_name in "${clusters_to_remove[@]}"; do
    echo "Removing cluster $cluster_name ..."
    az aks delete --name "$cluster_name" --resource-group "$AZURE_RESOURCE_GROUP" --yes
  done
fi

echo
echo "Done!"
