#!/usr/bin/env bash

# Copyright 2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
ROOT_DIR="$SCRIPT_DIR/../.."

GO_MOD="${ROOT_DIR}/go.mod"

modules=$(grep -v ' // indirect' "$GO_MOD" |
  grep -v '^//' |
  grep -v '^replace ' |
  grep '/v[0-9]' |
  tr -d '\t' |
  cut -d ' ' -f 1)

# Print to screen for debugging purposes.
echo "Found current modules using major versions above v1..."
echo "$modules"

pushd "$ROOT_DIR" >/dev/null

echo
echo "Checking for new major versions..."
for m in $modules; do
  if [[ "$m" == "github.com/go-jose/go-jose/v3" ]]; then
    # Skip github.com/go-jose/go-jose/v3 because we are using both v3 and v4.
    continue
  fi
  next_version=$(echo "$m" | awk -F '/v' '{ printf("%s/v%d\n", $1, $2 + 1) }')
  set +e
  go get "${next_version}@latest"
  found_new_version=$?
  if [[ $found_new_version == 0 ]]; then
    echo "Found new version $next_version. Replacing imports..."
    find . -name './.*' -prune -o \
      -path ./generated -prune -o \
      -type f -name '*.go' -print0 |
      xargs -0 sed -i '' "s#${m}#${next_version}#g"
  fi
  set -e
done

go mod tidy

if git diff --quiet; then
  echo
  echo "No changes."
else
  echo
  echo "Showing resulting diffs..."
  git --no-pager diff

  echo
  echo "Running unit tests..."
  ./hack/module.sh units
fi

popd >/dev/null

echo
echo "Done!"
