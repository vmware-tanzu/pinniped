#!/bin/sh

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

export TMPDIR=${TMPDIR:-/tmp}

load_pubkey() {
  local private_key_path=$TMPDIR/git-resource-private-key

  (jq -r '.source.private_key // empty' < "$1") > "$private_key_path"

  if [ -s "$private_key_path" ]; then
    chmod 0600 "$private_key_path"

    eval "$(ssh-agent)" >/dev/null 2>&1
    trap 'kill $SSH_AGENT_PID' 0

    ssh-add "$private_key_path" >/dev/null 2>&1

    mkdir -p ~/.ssh
    cat > ~/.ssh/config <<EOF
StrictHostKeyChecking no
LogLevel quiet
EOF
    chmod 0600 ~/.ssh/config
  fi
}
