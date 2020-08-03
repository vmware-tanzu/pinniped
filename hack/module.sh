#!/usr/bin/env bash
set -euo pipefail

root_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

function tidy_cmd() {
  echo 'go mod tidy'
}

function lint_cmd() {
  if [ -x "$(command -v golangci-lint)" ]; then
    cmd='golangci-lint'
  else
    cmd='go run github.com/golangci/golangci-lint/cmd/golangci-lint'
  fi
  echo "${cmd} run --modules-download-mode=readonly --timeout=10m"
}

function test_cmd() {
  if [ -x "$(command -v gotest)" ]; then
    cmd='gotest'
  else
    cmd='go test'
  fi
  echo "${cmd} -race ./..."
}

function with_modules() {
  local cmd_function="${1}"
  cmd="$(${cmd_function})"

  pushd "${root_dir}"
  for mod_file in $(find . -maxdepth 3 -name go.mod); do
    mod_dir="$(dirname "${mod_file}")"
    (
      echo "=> " && \
      echo "   cd ${mod_dir} && ${cmd}" && \
      cd "${mod_dir}" && ${cmd}
    )
  done
  popd
}

function usage() {
  echo "Error: <task> must be specified"
  echo "       do.sh <task> [tidy, lint, test]"
  exit 1
}

function main() {
  case "${1:-invalid}" in
    'tidy') with_modules 'tidy_cmd' ;;
    'lint') with_modules 'lint_cmd' ;;
    'test') with_modules 'test_cmd' ;;
    *) usage ;;
  esac
}

main "$@"