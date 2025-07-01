#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
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
echo "ssh user will be ${ssh_user}"

# Make a private key for ssh.
mkdir -p "$HOME/.ssh"
ssh_key_file="$HOME/.ssh/kind-node-builder-key"
ssh-keygen -t rsa -b 4096 -q -N "" -f "$ssh_key_file"

# When run in CI, the service account should not have permission to create project-wide keys, so explicitly add the
# key only to the specific VM instance (as VM metadata). We don't want to pollute the project-wide keys with these.
# See https://cloud.google.com/compute/docs/connect/add-ssh-keys#after-vm-creation for explanation of these commands.
# Note that this overwrites all ssh keys in the metadata. At the moment, these VMs have no ssh keys in the metadata
# upon creation, so it should always be okay to overwrite the empty value. However, if someday they need to have some
# initial ssh keys in the metadata for some reason, and if those keys need to be preserved for some reason, then
# these commands could be enhanced to instead read the keys, add to them, and write back the new list.
future_time="$(date --utc --date '+3 hours' '+%FT%T%z')"
echo \
  "${ssh_user}:$(cat "${ssh_key_file}.pub") google-ssh {\"userName\":\"${ssh_user}\",\"expireOn\":\"${future_time}\"}" \
  > /tmp/ssh-key-values
gcloud compute instances add-metadata "$instance_name" \
  --metadata-from-file ssh-keys=/tmp/ssh-key-values \
  --zone "$INSTANCE_ZONE" --project "$GCP_PROJECT"

# Get the IP so we can use regular ssh (not gcloud ssh), now that it has been set up.
gcloud_instance_ip=$(gcloud compute instances describe \
  --zone "$INSTANCE_ZONE" --project "$GCP_PROJECT" "${instance_name}" \
  --format='get(networkInterfaces[0].networkIP)')

ssh_dest="${ssh_user}@${gcloud_instance_ip}"

# Copy the build script to the VM.
echo "Copying $local_build_script to $instance_name as $remote_build_script..."
scp -i "$ssh_key_file" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$local_build_script" "$ssh_dest":"$remote_build_script"

# Run the script that was copied to the server above.
# Note that this assumes that there is no single quote character inside the values of PUSH_TO_IMAGE_REPO,
# DOCKER_USERNAME, and DOCKER_PASSWORD, which would cause quoting problems in the command below.
echo "Running $remote_build_script on $instance_name..."
ssh -i "$ssh_key_file" \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$ssh_dest" \
  "chmod 755 $remote_build_script && export PUSH_TO_IMAGE_REGISTRY='${PUSH_TO_IMAGE_REGISTRY}' && export PUSH_TO_IMAGE_REPO='${PUSH_TO_IMAGE_REPO}' && export DOCKER_USERNAME='${DOCKER_USERNAME}' && export DOCKER_PASSWORD='${DOCKER_PASSWORD}' && $remote_build_script"

echo
echo "Done!"
