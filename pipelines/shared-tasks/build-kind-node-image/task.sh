#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

instance_name=$(cat instance/name)

local_build_script="pinniped-ci/pipelines/shared-tasks/build-kind-node-image/build-image.sh"
remote_build_script="/tmp/build-image.sh"

gcloud auth activate-service-account \
  "$GCP_USERNAME" \
  --key-file <(echo "$GCP_JSON_KEY") \
  --project "$GCP_PROJECT"

# Create a temporary username because we can't ssh as root. Note that this username must be 32 character or less.
ssh_user="kind-node-builder-$(openssl rand -hex 4)"
ssh_dest="${ssh_user}@${instance_name}"
echo "ssh user@dest will be ${ssh_dest}"

# gcloud scp/ssh commands will interactively prompt to create an ssh key unless one already exists, so create one.
mkdir -p "$HOME/.ssh"
ssh_key_file="$HOME/.ssh/kind-node-builder-key"
ssh-keygen -t rsa -b 4096 -q -N "" -f "$ssh_key_file"

# Copy the build script to the VM.
echo "Copying $local_build_script to $instance_name as $remote_build_script..."
gcloud compute scp --zone "$INSTANCE_ZONE" --project "$GCP_PROJECT" \
  --ssh-key-file "$ssh_key_file" --ssh-key-expire-after 1h --strict-host-key-checking no \
  "$local_build_script" "$ssh_dest":"$remote_build_script"

# Run the script that was copied to the server above.
# Note that this assumes that there is no single quote character inside the values of PUSH_TO_IMAGE_REPO,
# DOCKER_USERNAME, and DOCKER_PASSWORD, which would cause quoting problems in the command below.
echo "Running $remote_build_script on $instance_name..."
gcloud compute ssh --zone "$INSTANCE_ZONE" --project "$GCP_PROJECT" "$ssh_dest" \
  --ssh-key-file "$ssh_key_file" --ssh-key-expire-after 1h --strict-host-key-checking no \
  --command "chmod 755 $remote_build_script && export PUSH_TO_IMAGE_REGISTRY='${PUSH_TO_IMAGE_REGISTRY}' && export PUSH_TO_IMAGE_REPO='${PUSH_TO_IMAGE_REPO}' && export DOCKER_USERNAME='${DOCKER_USERNAME}' && export DOCKER_PASSWORD='${DOCKER_PASSWORD}' && $remote_build_script"

echo
echo "Done!"
