#!/usr/bin/env bash

# Copyright 2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Sometimes something goes wrong with a GKE test job's cleanup and a
# GKE cluster gets orphaned, meaning that it is still running but no
# CI job is aware to clean it up.
#
# Find and delete all orphaned GKE clusters by deleting those which:
# 1. Are running in GCP with a name that indicates that it was auto-created for testing,
# 2. And are older than some number of hours since their creation time.
#
# Params are CLUSTER_ZONE, GCP_PROJECT, GCP_SERVICE_ACCOUNT, and GCP_JSON_KEY.

set -euo pipefail

gcloud auth activate-service-account \
  "$GCP_SERVICE_ACCOUNT" \
  --key-file <(echo "$GCP_JSON_KEY") \
  --project "$GCP_PROJECT"

all_cloud=($(gcloud container clusters list \
  --zone "$CLUSTER_ZONE" --project "$GCP_PROJECT" \
  --filter "name~gke-[a-f0-9]+-zone-${CLUSTER_ZONE}" --format 'table[no-heading](name)' | sort))

now_in_seconds_since_epoch=$(date +"%s")
hours_ago_to_delete=2
clusters_to_remove=()

echo
echo "All auto-created GKE clusters (with creation time in UTC):"
for i in "${all_cloud[@]}"; do
  creation_time=$(gcloud container clusters describe "$i" \
    --zone "$CLUSTER_ZONE" --project "$GCP_PROJECT" \
    --format 'table[no-heading](createTime.date(tz=UTC))')
  # UTC date format example: 2022-04-01T17:01:59
  if [[ "$creation_time" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
    # Note: on MacOS this date command would be: date -ju -f '%Y-%m-%dT%H:%M:%S' "$creation_time" '+%s'
    creation_time_seconds_since_epoch=$(date -u -d "$creation_time" '+%s')
    if (($((now_in_seconds_since_epoch - creation_time_seconds_since_epoch)) > $((hours_ago_to_delete * 60 * 60)))); then
      clusters_to_remove+=("$i")
      echo "$i $creation_time (older than $hours_ago_to_delete hours)"
    else
      echo "$i $creation_time (less than $hours_ago_to_delete hours old)"
    fi
  else
    echo "GKE cluster creation time not in expected time format: $creation_time"
    exit 1
  fi
done
if [[ ${#all_cloud[@]} -eq 0 ]]; then
  echo "none"
fi

echo
if [[ ${#clusters_to_remove[@]} -eq 0 ]]; then
  echo "No old orphaned GKE clusters found to remove."
else
  echo "Removing ${#clusters_to_remove[@]} GKE clusters(s) which are older than $hours_ago_to_delete hours in $CLUSTER_ZONE: ${clusters_to_remove[*]} ..."
  echo Would run command: gcloud container clusters delete --zone "${CLUSTER_ZONE}" --quiet ${clusters_to_remove[*]}
fi

echo
echo "Done!"
