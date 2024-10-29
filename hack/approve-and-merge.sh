#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo=vmware-tanzu/pinniped
current_branch_name=$(git rev-parse --abbrev-ref HEAD)

if [[ "$current_branch_name" != "ci" ]]; then
  echo "error: this script should only be used on the ci branch"
  exit 1
fi

# Print the list of PRs to the screen.
PAGER='' gh pr list --base ci  --repo $repo --limit 1000

# Exit if there are no PRs found.
count_prs=$(gh pr list --base ci --repo $repo --jq ". | length" --json "number")
if [[ "${count_prs}" == "0" ]]; then
  exit 0
fi

read -p "Do you wish to approve and merge these PRs for the ci branch? y/n: " yn
case $yn in
    [Yy]* );;
    * ) exit 0;;
esac

gh pr list --base ci --repo $repo --json="number" --jq ".[] | .number" \
  | xargs -I{} gh pr review {} --approve

gh pr list --base ci --repo $repo --json="number" --jq ".[] | .number" \
  | xargs -I{} gh pr merge {} --merge --delete-branch

echo "now pulling the merged commits"
git pull --rebase --autostash
