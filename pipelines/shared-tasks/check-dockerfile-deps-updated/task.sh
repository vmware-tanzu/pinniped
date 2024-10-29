#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

golang="golang"
distroless="gcr.io/distroless/static"
distroless_tag="nonroot"

new_golang="${golang}:$(cat golang-image/tag)@$(cat golang-image/digest)"

# Because we were having trouble getting the concourse registry-image resource to check this container image
# without auth errors, we get its latest digest here by using crane instead.
new_distroless="${distroless}:${distroless_tag}@$(crane digest "${distroless}:${distroless_tag}")"

echo "FOUND LATEST VERSIONS:"
echo "$new_golang"
echo "$new_distroless"
echo

if [[ "$(cat golang-image/tag)" == "latest" ]]; then
  echo "ERROR: The tag for the golang-image resource is 'latest'."
  echo "This means we are experiencing the Concourse bug https://github.com/concourse/registry-image-resource/issues/351."
  echo "Refusing to continue. We do not want to put the 'latest' tag into our Dockerfiles."
  echo
  echo "WORKAROUND: Please visit the Concourse UI page for the golang-image resource"
  echo "in this pipeline and disable the resource version with the 'latest' tag by clicking its checkbox"
  echo "to toggle it to the disabled state. Then trigger this job again."
  exit 1
fi

# Copy everything to output.
# Don't use git clone because that would throw away uncommitted changes from previous tasks.
# Be careful to include the .git directory too.
cp -r pinniped-in/. pinniped-out

cd pinniped-out

dockerfile_list=("Dockerfile" "hack/Dockerfile_fips")

for dockerfile in "${dockerfile_list[@]}"; do

  # Replace all golang:anything
  sed -E -i "s/${golang}:\\S+/${new_golang}/g" "$dockerfile"

  # Replace all golang@anything
  # Do this second so it does not replace the results of the above sed, which will be golang:new_value
  sed -E -i "s/${golang}@\\S+/${new_golang}/g" "$dockerfile"

  # Replace all gcr.io/distroless/static:anything
  sed -E -i "s#${distroless}:\\S+#${new_distroless}#g" "$dockerfile"

  # Replace all gcr.io/distroless/static@anything
  # Do this second so it does not replace the results of the above sed
  sed -E -i "s#${distroless}@\\S+#${new_distroless}#g" "$dockerfile"

  # Print diff output to the screen so it is shown in the job output.
  echo
  git --no-pager diff "$dockerfile"

done
