#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -e

if [ -z "$1" ]; then
    echo "usage: $0 SECRET_NAME"
    exit 1
fi

set -u
if ! command -v yq &> /dev/null; then
    echo "Please install the yq CLI"
    exit 1
fi
if ! command -v delta &> /dev/null; then
    echo "Please install the delta CLI (brew install git-delta)"
    exit 1
fi
if ! command -v gcloud &> /dev/null; then
    echo "Please install the gcloud CLI"
    exit 1
fi
if [[ -z "$(gcloud config list account --format "value(core.account)")" ]]; then
  echo "Please run \`gcloud auth login\`"
  exit 1
fi

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

# Create a temporary directory for secrets, cleaned up at the end of this script.
trap 'rm -rf "$TEMP_DIR"' EXIT
TEMP_DIR=$(mktemp -d) || exit 1

# Grab the current version.
echo "Downloading the latest version of '$1'..."
gcloud secrets versions access latest --secret="$1" --project "$PINNIPED_GCP_PROJECT" > "$TEMP_DIR/$1.yaml"

# Use yq to format the YAML into a consistent style.
# TODO: there is a bug in yq that strips leading comments on the first lines of a file when -P is used.
# For now, we'll skip the pretty-printing.
# yq eval -i -P '.' "$TEMP_DIR/$1.yaml"
yq eval -i '.' "$TEMP_DIR/$1.yaml"
cp "$TEMP_DIR/$1.yaml" "$TEMP_DIR/$1-original.yaml"

# Invoke $EDITOR to modify the file.
${EDITOR:-vim} "$TEMP_DIR/$1.yaml"

# Format the output from the editor just as we did before the edit.

# TODO: there is a bug in yq that strips leading comments on the first lines of a file when -P is used.
# For now, we'll skip the pretty-printing.
# yq eval -i -P '.' "$TEMP_DIR/$1.yaml"
yq eval -i '.' "$TEMP_DIR/$1.yaml"

# Dump the diff using git-delta.
( cd "$TEMP_DIR" && delta "$1-original.yaml" "$1.yaml" || true )

read -p "Save as new version of '$1' [yN]: " -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    gcloud secrets versions add "$1" --data-file "$TEMP_DIR/$1.yaml" --project "$PINNIPED_GCP_PROJECT"
fi
