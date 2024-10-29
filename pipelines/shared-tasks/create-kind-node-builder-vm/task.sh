#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd create-kind-node-builder-vm-output

gcloud auth activate-service-account \
  "$GCP_USERNAME" \
  --key-file <(echo "$GCP_JSON_KEY") \
  --project "$GCP_PROJECT"

INSTANCE_NAME="kind-node-builder-$(openssl rand -hex 4)"

echo "Creating $INSTANCE_NAME in $INSTANCE_ZONE..."

# Note that --tags chooses the firewall rules to allow ssh.
gcloud compute instances create "${INSTANCE_NAME}" \
  --zone "${INSTANCE_ZONE}" \
  --machine-type=e2-standard-2 \
  --image=debian-11-bullseye-v20210916 --image-project=debian-cloud \
  --boot-disk-size=30GB --boot-disk-type=pd-ssd \
  --labels "kind-node-builder=" \
  --no-service-account --no-scopes \
  --tags=kind-node-image-builder

echo "$INSTANCE_NAME" > name

echo "Done!"
