#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

gcloud auth activate-service-account \
  "$GCP_USERNAME" \
  --key-file <(echo "$GCP_JSON_KEY") \
  --project "$GCP_PROJECT"

INSTANCE_NAME=$(cat kind-cluster-pool/name)

echo "Removing $INSTANCE_NAME in $INSTANCE_ZONE..."

gcloud compute instances delete "${INSTANCE_NAME}" \
  --zone "${INSTANCE_ZONE}" \
  --delete-disks all \
  --quiet

echo "Done!"
