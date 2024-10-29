#!/usr/bin/env bash

# Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This is similar to rsync.sh, but with the src and dest flipped at the end.
# It will copy all changes from the remote workstation back to your local machine (overwriting your local changes).

set -euo pipefail

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

SRC_DIR=${SRC_DIR:-"$HOME/workspace/pinniped"}
src_dir_parent=$(dirname "$SRC_DIR")
dest_dir="./workspace/pinniped"
instance_name="${REMOTE_INSTANCE_NAME:-${USER}}"
instance_user="${REMOTE_INSTANCE_USERNAME:-${USER}}"
project="$PINNIPED_GCP_PROJECT"
zone="us-central1-b"
config_file="/tmp/gcp-ssh-config"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$SRC_DIR" ]]; then
  echo "ERROR: $SRC_DIR does not exist"
  exit 1
fi

# Get the ssh fingerprints of all the GCP VMs.
gcloud compute config-ssh --ssh-config-file="$config_file" \
  --project="$project" >/dev/null

cd "$SRC_DIR"
local_commit=$(git rev-parse --short HEAD)
remote_commit=$("$here"/ssh.sh "cd $dest_dir; git rev-parse --short HEAD" 2>/dev/null | tr -dc '[:print:]')

if [[ -z "$local_commit" || -z "$remote_commit" ]]; then
  echo "ERROR: Could not determine currently checked out git commit sha"
  exit 1
fi

if [[ "$local_commit" != "$remote_commit" ]]; then
  echo "ERROR: Local and remote repos are not on the same commit. This is usually a mistake."
  echo "Local was $SRC_DIR at *${local_commit}*"
  echo "Remote was ${instance_name}:${dest_dir} at *${remote_commit}*"
  exit 1
fi

# Skip large files because they are probably compiled binaries.
# Also skip other common filenames that we wouldn't need to sync.
echo "Starting rsync from remote to local for $SRC_DIR..."
rsync \
  --progress --delete --archive --compress --human-readable \
  --max-size 200K \
  --exclude .git/ --exclude .idea/ --exclude .DS_Store --exclude '*.test' --exclude '*.out' \
  --rsh "ssh -F $config_file" \
  "${instance_user}@${instance_name}.${zone}.${project}:$dest_dir" "$src_dir_parent"
