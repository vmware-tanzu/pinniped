#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

# Generate code, running each Kube version as a separate process, with up to 8 parallel processes at a time.
cat "${ROOT}/hack/lib/kube-versions.txt" | grep -v '^#' | xargs -n 1 -P 8 "$ROOT/hack/lib/update-codegen.sh"

# Copy the latest version into a ./generated/latest directory so we can depend on it without nested modules.
LATEST_MINOR_VERSION="$(cat "${ROOT}/hack/lib/kube-versions.txt" | grep -v '^#' | cut -d"." -f1-2 | head -1)"
LATEST_ROOT="$ROOT/generated/latest"
rm -rf "$LATEST_ROOT"
cp -r "$ROOT/generated/$LATEST_MINOR_VERSION/" "$LATEST_ROOT"

# Delete the go.mod and go.sum because we do not want latest to be a nested module.
# Don't delete the README.adoc file so we can share GitHub URLs to it, like a permalink.
find "$LATEST_ROOT" \( -name "go.mod" -or -name "go.sum" \) -delete
# Delete the CRDs because latest is a go package, so it only needs the go files.
rm -r "$LATEST_ROOT/crds"

# Update the import statements in the latest package to make them refer to itself.
if [[ "$(uname -s)" == "Linux" ]]; then
  # docker on linux preserves the root ownership of the output files of update-codegen.sh,
  # so chown the files before editing them.
  sudo chown -R "$(id --user)" generated
  sudo chgrp -R "$(id --group)" generated
  # sed on Linux uses -i'' (no space in between).
  find "$LATEST_ROOT" -type f -print0 | xargs -0 sed -i'' -e "s|go.pinniped.dev/generated/$LATEST_MINOR_VERSION|go.pinniped.dev/generated/latest|g"
else
  # sed on MacOS uses -i '' (with space in between).
  find "$LATEST_ROOT" -type f -print0 | xargs -0 sed -i '' -e "s|go.pinniped.dev/generated/$LATEST_MINOR_VERSION|go.pinniped.dev/generated/latest|g"
fi

# Copy each generated CRD yaml to the app which should cause it to be installed.
cp "$ROOT"/generated/"$LATEST_MINOR_VERSION"/crds/*.supervisor.*.yaml "$ROOT/deploy/supervisor"
cp "$ROOT"/generated/"$LATEST_MINOR_VERSION"/crds/*.concierge.*.yaml "$ROOT/deploy/concierge"

# Tidy.
"$ROOT/hack/module.sh" tidy
