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

# Start an instance which was previously stopped to save money.
echo "Starting VM $instance_name..."
gcloud compute instances start "$instance_name" \
  --project="$project" --zone="$zone"
