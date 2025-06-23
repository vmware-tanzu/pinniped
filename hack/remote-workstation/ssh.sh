#!/usr/bin/env bash

# Copyright 2021-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

instance_name="${REMOTE_INSTANCE_NAME:-${USER}}"
instance_user="${REMOTE_INSTANCE_USERNAME:-${USER}}"
project="$PINNIPED_GCP_PROJECT"
zone="us-west1-b"

# Run ssh with identities forwarded so you can use them with git on the remote host.
# Optionally run an arbitrary command on the remote host.
# By default, start an interactive session.
gcloud compute ssh --ssh-flag=-A "$instance_user@$instance_name" \
  --project="$project" --zone="$zone" -- "$@"
