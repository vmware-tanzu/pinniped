#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

go version

export GOCACHE="$PWD/cache/gocache"
export GOMODCACHE="$PWD/cache/gomodcache"

if [[ "$DRY_RUN" == "yes" ]]; then
  # Dry run with a fake version number. Not intended for use when building a final release of the CLI!
  export KUBE_GIT_VERSION="v1.2.3"
else
  # Ensure that the input was given in this case, since it is an optional input to the task.
  if [[ ! -f release-info/version-with-v ]]; then
    echo 'Did not find release-info/version-with-v'
    exit 1
  fi

  # This env var is used by hack/get-ldflags.sh below
  export KUBE_GIT_VERSION="$(cat release-info/version-with-v)"
fi

echo "Building using version number $KUBE_GIT_VERSION ..."

pushd pinniped >/dev/null
  ldflags="$(hack/get-ldflags.sh)"
popd >/dev/null

pushd pinniped/cmd/pinniped >/dev/null

# Make a temp directory for the CLI binaries
output_dir="$(mktemp -d)"

target_os_list=(linux darwin windows)
target_platform_list=(amd64 arm64)
for target_os in "${target_os_list[@]}"; do
  for target_platform in "${target_platform_list[@]}"; do
    echo "Building CLI for OS $target_os / platform $target_platform ..."

    name="pinniped"
    output="pinniped-cli-${target_os}-${target_platform}"

    if [[ "$target_os" == "windows" ]]; then
      name="${name}.exe"
      output="${output}.exe"
    fi

    # Cross-compile the executable binary (CGO_ENABLED=0 means static linking)
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_platform" go build -trimpath -ldflags "$ldflags" -o "$output_dir" ./...

    mv "${output_dir}/${name}" "../../../cli-binaries/${output}"
  done
done

popd >/dev/null

linux_cli="cli-binaries/pinniped-cli-linux-amd64"
chmod 755 "$linux_cli"
echo "checking to see if 'pinniped version' has an '--output' flag"
success=0
output=$("$linux_cli" version --output json 2>&1) || success=$?

if [[ $success -eq 0 ]]; then
  echo "pinniped version has an --output flag"
  echo "result of version command: $output"
  echo ""
  echo "running grep:"

  # Make sure that `pinniped version` reports the version number that we just tried to bake in to the binaries.
  if ! echo "$output" | grep "\"gitVersion\"\: \"$KUBE_GIT_VERSION\","; then
    echo "Running 'pinniped version' did not output the expected version number!"
    echo "Actual: $("$linux_cli" version -o json)"
    echo "Expected to include '\"gitVersion\"\: \"$KUBE_GIT_VERSION\",'"
    exit 1
  else
    echo "✅"
  fi

  # Make sure that `pinniped version` reports a clean git state.
  chmod 755 "$linux_cli"
  if ! echo "$output" | grep "\"gitTreeState\"\: \"clean\","; then
    echo "Running 'pinniped version' did not have a clean gitTreeState!"
    echo "Actual: $("$linux_cli" version -o json)"
    exit 1
  else
    echo "✅"
  fi
else
  echo "pinniped version does not have an --output flag"
  output=$("$linux_cli" version)
  echo "result of version command: $output"
  echo ""
  echo "running grep:"

  # Make sure that `pinniped version` reports the version number that we just tried to bake in to the binaries.
  if ! echo "$output" | grep ", GitVersion:\"$KUBE_GIT_VERSION\","; then
    echo "Running 'pinniped version' did not output the expected version number!"
    echo "Actual: $("$linux_cli" version)"
    echo "Expected to include ', GitVersion:\"$KUBE_GIT_VERSION\",'"
    exit 1
  else
    echo "✅"
  fi
fi
