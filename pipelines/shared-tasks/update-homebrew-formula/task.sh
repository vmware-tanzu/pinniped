#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -xeuo pipefail

# Get current revision from 'revision: "abc123"'.
current_revision="$(awk '/revision:/ { gsub(/"/, "", $2); print($2); }' homebrew-pinniped-in/pinniped-cli.rb)"

# Get current version components from 'tag: "vx.y.z",'.
current_version="$(awk '/tag:/ { sub(/"v/, "", $2); sub(/",/, "", $2); print($2); }' homebrew-pinniped-in/pinniped-cli.rb)"

new_tag="$(cat github-release/tag)"
new_revision="$(cat github-release/commit_sha)"

# Get new version components from 'vx.y.z'.
new_version="$(echo "$new_tag" | sed -e 's/^v//')"

# Update formula, if necessary.
cp -a homebrew-pinniped-in/* homebrew-pinniped-in/.git homebrew-pinniped-out
if [[ "$current_revision" != "$new_revision" ]]; then
  sed \
    -e "s/$current_version/$new_version/" \
    -e "s/$current_revision/$new_revision/" \
    homebrew-pinniped-in/pinniped-cli.rb \
    > homebrew-pinniped-out/pinniped-cli.rb

  cd homebrew-pinniped-out
  apt update >/dev/null
  apt install git -y >/dev/null
  git config user.email "pinniped-ci-bot@users.noreply.github.com"
  git config user.name "Pinny"
  git commit -a -m "pinniped-cli.rb: update to $new_version"
fi
