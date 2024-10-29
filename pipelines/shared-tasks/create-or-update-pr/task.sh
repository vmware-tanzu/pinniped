#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

branch="${BRANCH:-"pinny/bump-deps"}"

cd pinniped

# Print the current status to the log.
git status

# Copied from https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
github_hosts='
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=
'

# Prepare to be able to do commits and pushes.
ssh_dir="$HOME"/.ssh/
mkdir "$ssh_dir"
echo "$github_hosts" >"$ssh_dir"/known_hosts
echo "${DEPLOY_KEY}" >"$ssh_dir"/id_rsa
chmod 600 "$ssh_dir"/id_rsa
git config user.email "pinniped-ci-bot@users.noreply.github.com"
git config user.name "Pinny"
git remote add ssh_origin "git@github.com:vmware-tanzu/pinniped.git"

# Add all the changed files.
git add .

# Print the current status to the log.
git status

# Did we just stage any changes?
staged=$(git --no-pager diff --staged)
if [[ "$staged" == "" ]]; then
  # Nothing to commit. We are done.
  echo "No changes to any files detected. Done."
  exit 0
fi

# Check if the branch already exists on the remote.
new_branch="no"
if [[ -z "$(git ls-remote ssh_origin "$branch")" ]]; then
  echo "The branch does not already exist, so create it."
  git checkout -b "$branch"
  git status
  new_branch="yes"
else
  echo "The branch already exists, so pull it."
  # Stash our changes before using git checkout and git reset, which both can throw away local changes.
  git status
  git stash
  # Fetch all the remote branches so we can use one of them.
  git fetch ssh_origin
  # The branch already exists, so reuse it.
  git checkout "$branch"
  # Pull to sync up commits with the remote branch.
  git pull --rebase --autostash
  # Throw away all previous commits on the branch and set it up to look like main again.
  git reset --hard main
  # Bring back our changes and stage them again.
  git stash pop
  git add .
  git status
fi

# Show diff for the log.
echo "Found changes to commit:"
echo
git --no-pager diff --staged
echo

# Commit.
echo "Committing changes to branch $branch. New branch? $new_branch."
git commit -m "Bump dependencies"

# Push.
if [[ "$new_branch" == "yes" ]]; then
  # Push the new branch to the remote.
  echo "Pushing the new branch."
  git push --set-upstream ssh_origin "$branch"
else
  # Force push the existing branch to the remote.
  echo "Force pushing the existing branch."
  git push --force-with-lease
fi

# Now check if there is already a PR open for our branch.
# If there is already an open PR, then we just updated it by force pushing the branch.
# Note that using the gh CLI without login depends on setting the GH_TOKEN env var.
open_pr=$(gh pr list --head "$branch" --json title --jq '. | length')
if [[ "$open_pr" == "0" ]]; then
  # There is no currently open PR for this branch, so open a new PR for this branch
  # against main, and set the title and body.
  echo "Creating PR."
  gh pr create --head "$branch" --base main \
    --title "Bump dependencies" --body "Automatically bumped all go.mod direct dependencies and/or images in dockerfiles."
fi
