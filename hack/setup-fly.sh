#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Define some env vars
source "$script_dir/fly-helpers.sh"

# Install the fly cli if needed
if [[ ! -f "$FLY_CLI" ]]; then
  curl -fL "$CONCOURSE_URL/api/v1/cli?arch=amd64&platform=darwin" -o "$FLY_CLI"
  chmod 755 "$FLY_CLI"
fi

if $FLY_CLI targets | grep ^"$CONCOURSE_TARGET" | grep -q 'https://ci\.pinniped\.dev'; then
  # The user has the old ci.pinniped.dev target. Remove it so we can replace it.
  $FLY_CLI delete-target --target "$CONCOURSE_TARGET"
fi

if ! $FLY_CLI targets | tr -s ' ' | cut -f1 -d ' ' | grep -q "$CONCOURSE_TARGET"; then
  # Create the target if needed
  $FLY_CLI --target "$CONCOURSE_TARGET" login \
    --team-name "$CONCOURSE_TEAM" --concourse-url "$CONCOURSE_URL"
else
  # Login if needed
  if ! $FLY_CLI --target "$CONCOURSE_TARGET" status; then
    $FLY_CLI --target "$CONCOURSE_TARGET" login
  fi
fi

# Upgrade fly if needed
$FLY_CLI --target "$CONCOURSE_TARGET" sync
