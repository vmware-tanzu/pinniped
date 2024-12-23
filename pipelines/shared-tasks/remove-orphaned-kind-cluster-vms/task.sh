#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Sometimes something goes wrong with the Kind pool CI jobs and a Kind
# VM gets orphaned, meaning that it is still running but the pool repo
# is not tracking it anymore. Also, an individual test job could create
# its own Kind VM without adding it to the pool, and if that job fails
# to clean it up correctly then the VM would be orphaned.
#
# Find and delete all orphaned Kind cluster VMs by deleting VMs which:
# 1. Are running in GCP with a name that indicates that it is a kind VM,
# 1. Do not exist in the pool repo,
# 2. And are older than some number of hours since their creation time.
#
# These rules should avoid deleting Kind cluster VMs which were created
# by an individual test job without being added to the pool repo, assuming
# that those jobs always finish in less than the threshold number of hours.
#
# Params are INSTANCE_ZONE, GCP_PROJECT, GCP_USERNAME, and GCP_JSON_KEY.

set -euo pipefail

gcloud auth activate-service-account \
  "$GCP_USERNAME" \
  --key-file <(echo "$GCP_JSON_KEY") \
  --project "$GCP_PROJECT"

# The pinniped-ci-pool resource is now optional so this script can support
# cleaning up old kind VMs without knowing about any resource pools.
all_local=()
if [[ -d pinniped-ci-pool ]]; then
  pushd pinniped-ci-pool >/dev/null
  all_local=($(find . -name 'kind-worker-*' -type f -exec basename {} ';' | sort))
  popd >/dev/null
fi

all_cloud=($(gcloud compute instances list \
  --zones "$INSTANCE_ZONE" --project "$GCP_PROJECT" \
  --filter 'name~kind-worker-[a-f0-9]+' --format 'table[no-heading](name)' | sort))

exists_in_local_but_not_cloud=()
for i in "${all_local[@]}"; do
  found=
  for j in "${all_cloud[@]}"; do
    if [[ "$i" == "$j" ]]; then
      found=yes
      break
    fi
  done
  if [[ "$found" != "yes" ]]; then
    exists_in_local_but_not_cloud+=("$i")
  fi
done

exists_in_cloud_but_not_local=()
exists_in_cloud_but_not_local_relative_path=()
for i in "${all_cloud[@]}"; do
  found=
  for j in "${all_local[@]}"; do
    if [[ "$i" == "$j" ]]; then
      found=yes
      break
    fi
  done
  if [[ "$found" != "yes" ]]; then
    exists_in_cloud_but_not_local+=("$i")
  fi
done

if [[ -d pinniped-ci-pool ]]; then
  pushd pinniped-ci-pool >/dev/null
  echo
  echo "All pool repo kind cluster files which do not have a running VM instance:"
  for i in "${exists_in_local_but_not_cloud[@]}"; do
    echo -n "$i  "
    relative_path=$(find . -name "$i" -type f)
    exists_in_cloud_but_not_local_relative_path+=("$relative_path")
    git --no-pager log -n1 --pretty=format:"%h%x09%an%x09%ad%x09%s" "$relative_path"
    echo
  done
  if [[ ${#exists_in_local_but_not_cloud[@]} -eq 0 ]]; then
    echo "none"
  fi
  popd >/dev/null
fi

now_in_seconds_since_epoch=$(date +"%s")
hours_ago_to_delete=2
vms_to_remove=()

echo
echo "All VM instances with no corresponding pool repo file (with creation time in UTC):"
for i in "${exists_in_cloud_but_not_local[@]}"; do
  creation_time=$(gcloud compute instances describe "$i" \
    --zone "$INSTANCE_ZONE" --project "$GCP_PROJECT" \
    --format 'table[no-heading](creationTimestamp.date(tz=UTC))')
  # UTC date format example: 2022-04-01T17:01:59
  if [[ "$creation_time" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
    # Note: on MacOS this date command would be: date -ju -f '%Y-%m-%dT%H:%M:%S' "$creation_time" '+%s'
    creation_time_seconds_since_epoch=$(date -u -d "$creation_time" '+%s')
    if (($((now_in_seconds_since_epoch - creation_time_seconds_since_epoch)) > $((hours_ago_to_delete * 60 * 60)))); then
      vms_to_remove+=("$i")
      echo "$i $creation_time (older than $hours_ago_to_delete hours)"
    else
      echo "$i $creation_time (less than $hours_ago_to_delete hours old)"
    fi
  else
    echo "VM creation time not in expected time format: $creation_time"
    exit 1
  fi
done
if [[ ${#exists_in_cloud_but_not_local[@]} -eq 0 ]]; then
  echo "none"
fi

echo
if [[ ${#vms_to_remove[@]} -eq 0 ]]; then
  echo "No old orphaned VMs found to remove."
else
  echo "Removing ${#vms_to_remove[@]} VM(s) which are older than $hours_ago_to_delete hours in $INSTANCE_ZONE: ${vms_to_remove[*]} ..."
  gcloud compute instances delete --zone "${INSTANCE_ZONE}" --delete-disks all --quiet ${vms_to_remove[*]}
fi

echo
echo "Done!"
