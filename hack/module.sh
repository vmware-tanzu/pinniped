#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

function usage() {
  echo "Error: <task> must be specified"
  echo "       module.sh <task> [tidy, lint, test, unittest]"
  exit 1
}

function main() {
  pushd "${ROOT}" >/dev/null

  # start the cache mutation detector by default so that cache mutators will be found
  local kube_cache_mutation_detector="${KUBE_CACHE_MUTATION_DETECTOR:-true}"

  # panic the server on watch decode errors since they are considered coder mistakes
  local kube_panic_watch_decode_error="${KUBE_PANIC_WATCH_DECODE_ERROR:-true}"

  case "${1:-invalid}" in
  'tidy')
    local version="$(cat "${ROOT}/go.mod" | grep '^go ' | cut -f 2 -d ' ')"
    go mod tidy -v -go=${version} -compat=${version}
    ;;
  'lint' | 'linter' | 'linters')
    golangci-lint --version
    go version
    golangci-lint run --modules-download-mode=readonly --timeout=30m
    ;;
  'lint_in_docker')
    local lint_version
    lint_version="${2:-latest}"
    docker run --rm \
      --volume "${ROOT/..}":/pinniped \
      --volume "$(go env GOCACHE):/gocache" \
      --volume "$(go env GOMODCACHE):/gomodcache" \
      --env GOCACHE=/gocache \
      --env GOMODCACHE=/gomodcache \
      --workdir /pinniped \
      golangci/golangci-lint:$lint_version \
      ./hack/module.sh lint
    ;;
  'unittest' | 'unittests' | 'units' | 'unit')
    # Temporarily avoid using the race detector for the impersonator package due to https://github.com/kubernetes/kubernetes/issues/128548
    KUBE_CACHE_MUTATION_DETECTOR=${kube_cache_mutation_detector} \
      KUBE_PANIC_WATCH_DECODE_ERROR=${kube_panic_watch_decode_error} \
      go test -short -race $(go list ./... | grep -v internal/concierge/impersonator)
    # TODO: change this back to using the race detector everywhere
    KUBE_CACHE_MUTATION_DETECTOR=${kube_cache_mutation_detector} \
      KUBE_PANIC_WATCH_DECODE_ERROR=${kube_panic_watch_decode_error} \
      go test -short ./internal/concierge/impersonator
    ;;
  'generate')
    go generate ./internal/mocks/...
    ;;
  *)
    usage
    ;;
  esac

  echo "=> "
  echo "   \"module.sh $1\" Finished successfully."

  popd >/dev/null
}

main "$@"
