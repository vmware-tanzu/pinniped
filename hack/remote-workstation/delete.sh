#!/usr/bin/env bash

# Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

instance_name="${REMOTE_INSTANCE_NAME:-${USER}}"
project="$PINNIPED_GCP_PROJECT"
zone="us-west1-b"

# Delete the instance forever. Will prompt for confirmation.
echo "Destroying VM $instance_name..."
gcloud compute instances delete "$instance_name" \
  --delete-disks="all" \
  --project="$project" --zone="$zone"
