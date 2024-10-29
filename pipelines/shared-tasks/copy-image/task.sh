#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SOURCE_REPOSITORY="$(cat ci-build-image/repository)"
SOURCE_DIGEST="$(cat ci-build-image/digest)"
SOURCE_IMAGE="${SOURCE_REPOSITORY}@${SOURCE_DIGEST}"

SOURCE_REGISTRY="$(echo "$SOURCE_REPOSITORY" | cut -d / -f 1)"
DESTINATION_REGISTRY="$(echo "$DESTINATION_REPOSITORY" | cut -d / -f 1)"

# Login to both the source and the dest.
echo "Logging in to $SOURCE_REPOSITORY_USERNAME ..."
crane auth login -u "$SOURCE_REGISTRY" -p "$SOURCE_REPOSITORY_PASSWORD" "$SOURCE_REGISTRY"
echo "Logging in to $DESTINATION_REGISTRY ..."
crane auth login -u "$DESTINATION_REPOSITORY_USERNAME" -p "$DESTINATION_REPOSITORY_PASSWORD" "$DESTINATION_REGISTRY"

# Create an array of all desired tags.
echo "Collecting desired tags ..."
DESTINATION_TAGS=()

# Add the destination tag, if one was specified.
if [[ -n "$DESTINATION_TAG" ]]; then
  echo "Saw desired tag $DESTINATION_TAG"
  DESTINATION_TAGS+=("$DESTINATION_TAG")
fi

# Add each tag from input file release-info/image-tags.
while IFS="" read -r tag || [ -n "$tag" ]; do
  echo "Saw desired tag $tag"
  DESTINATION_TAGS+=("$tag")
done <release-info/image-tags

# Check that we have at least one tag.
if [[ ${#DESTINATION_TAGS[@]} -eq 0 ]]; then
  echo "ERROR: Inputs must specify at least one tag."
  exit 1
fi

# Copy.
for ((i = 0; i < ${#DESTINATION_TAGS[@]}; i++)); do
  tag="${DESTINATION_TAGS[$i]}"
  if [[ $i -eq 0 ]]; then
    # Copy from source to dest with the first tag in the list.
    copy_dest="${DESTINATION_REPOSITORY}:${tag}"
    echo "Copying $SOURCE_IMAGE to $copy_dest ..."
    crane copy "$SOURCE_IMAGE" "$copy_dest"
  else
    # Add a tag to the destination for each remaining desired tags.
    echo "Tagging $copy_dest with additional tag $tag ..."
    crane tag "$copy_dest" "$tag"
  fi
done

echo "Checking source and destination digests are the same ..."
found_dest_digest="$(crane digest "$copy_dest")"
if [[ "$found_dest_digest" != "$SOURCE_DIGEST" ]]; then
  echo "Destination digest $found_dest_digest and source digest $SOURCE_DIGEST were not equal"
  exit 1
fi

echo "Checking that destination image is a multi-arch image with all desired platforms included ..."
desired_dest_platforms="linux/amd64,linux/arm64"
found_dest_platforms="$(crane manifest "$copy_dest" | yq -o csv '[.manifests[].platform | .os + "/" + .architecture] | sort')"
if [[ "$found_dest_platforms" != "$desired_dest_platforms" ]]; then
  echo "Destination platforms $found_dest_platforms did not equal desired platforms $desired_dest_platforms"
  exit 1
fi

echo "Successfully copied image with platforms $found_dest_platforms"
echo "Done!"
