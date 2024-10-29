#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

cd pinniped

if [[ "${SKIP_INSTALL_GOLANGCI_LINT:-false}" != "true" ]]; then
  golangci_lint_version=$(cat ./hack/lib/lint-version.txt)
  curl -sfLo /tmp/golangci-lint.tar.gz \
      https://github.com/golangci/golangci-lint/releases/download/v${golangci_lint_version}/golangci-lint-${golangci_lint_version}-linux-amd64.tar.gz

  tar -C /tmp --strip-components=1 -xzvf /tmp/golangci-lint.tar.gz

  mv /tmp/golangci-lint /usr/local/bin/golangci-lint
  chmod +x /usr/local/bin/golangci-lint
fi

if grep --extended-regexp '\.Focus\(' --include '*_test.go' --recursive .; then
  echo "ERROR: Found focused unit test(s) committed to git. This is almost certainly a mistake."
  exit 1
fi

./hack/module.sh lint

echo "finished"
