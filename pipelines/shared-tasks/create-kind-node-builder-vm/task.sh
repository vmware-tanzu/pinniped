#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
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
  --labels "kind-node-builder=" \
  --no-service-account --no-scopes \
  --network-interface=stack-type=IPV4_ONLY,subnet=projects/"$SHARED_VPC_PROJECT"/regions/"${SUBNET_REGION}"/subnetworks/"${SUBNET_NAME}",no-address \
  --create-disk=auto-delete=yes,boot=yes,device-name="${INSTANCE_NAME}",image=projects/"${DISK_IMAGES_PROJECT}"/global/images/labs-saas-gcp-debian11-packer-latest,mode=rw,size=30,type=pd-ssd \
  --tags=kind-node-image-builder

echo "$INSTANCE_NAME" > name

echo "Done!"
