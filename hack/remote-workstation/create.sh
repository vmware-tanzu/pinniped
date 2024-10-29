#!/usr/bin/env bash

# Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

instance_name="${REMOTE_INSTANCE_NAME:-${USER}}"
instance_user="${REMOTE_INSTANCE_USERNAME:-${USER}}"
project="$PINNIPED_GCP_PROJECT"
zone="us-central1-b"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create a VM called $instance_name with some reasonable compute power and disk.
echo "Creating VM with name $instance_name..."
gcloud compute instances create "$instance_name" \
  --project="$project" --zone="$zone" \
  --machine-type="e2-standard-8" \
  --boot-disk-size="40GB" --boot-disk-type="pd-ssd" --boot-disk-device-name="$instance_name"

# Give a little time for the server to be ready.
while true; do
  sleep 5
  if ! "$here"/ssh.sh ls; then
    echo "Waiting for VM to be accessible via ssh..."
  else
    echo "VM ready!"
    break
  fi
done

# Copy the deps script to the new VM.
echo "Copying deps.sh to $instance_name..."
gcloud compute scp "$here"/lib/deps.sh "$instance_user@$instance_name":/tmp \
  --project="$project" --zone="$zone"

# Run the deps script on the new VM.
"$here"/ssh.sh /tmp/deps.sh
