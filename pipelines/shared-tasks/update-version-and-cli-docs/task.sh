#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

pinniped_tag="$(cat github-final-release/tag)"

# Copy everything to output.
git clone ./pinniped-in ./pinniped-out

# The target file within the Pinniped repo.
clidoc="site/content/docs/reference/cli.md"

# Run the hidden pinniped CLI command for this latest release.
chmod +x github-final-release/pinniped-cli-linux-amd64
github-final-release/pinniped-cli-linux-amd64 generate-markdown-help >"pinniped-out/$clidoc"

configdoc="site/config.yaml"

kube_version="$(cat ./pinniped-in/hack/lib/kube-versions.txt | grep -v '^#' | head -1 | cut -d"." -f1-2)"
if ! echo "$kube_version" | grep -Eq '^[0-9]+\.[0-9]+$'; then
  echo "bad version format, should be X.Y: $kube_version"
  exit 1
fi

echo "Installing yq..."
curl --retry-connrefused --retry 5 -fLo /usr/local/bin/yq https://github.com/mikefarah/yq/releases/download/v4.40.4/yq_linux_amd64
chmod +x /usr/local/bin/yq

# cd to the output repo.
cd pinniped-out

# Edit the config.yaml file in the output repo.
pinniped_tag="$pinniped_tag" yq eval '.params.latest_version = env(pinniped_tag)' --inplace "$configdoc"
kube_version="$kube_version" yq eval '.params.latest_codegen_version = env(kube_version)' --inplace "$configdoc"

# Prepare to commit in the output repo.
git config user.email "pinniped-ci-bot@users.noreply.github.com"
git config user.name "Pinny"

# Only add the files that we think should have changed, just in case other files changed somehow.
git add "$clidoc"
git add "$configdoc"

# Print the current status to the log.
git status

# Did we just stage any changes?
staged=$(git --no-pager diff --staged)
if [[ "$staged" == "" ]]; then
  # Nothing to commit.
  echo "No changes to $clidoc or $configdoc found. Skipping git commit."
else
  # Show diff for the log.
  echo "Found changes for $clidoc or $configdoc:"
  echo
  echo "$staged"
  echo
  # Commit.
  echo "Committing changes."
  git commit -m "Updated versions in docs for $pinniped_tag release"
fi
