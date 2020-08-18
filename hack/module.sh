#!/usr/bin/env bash
set -euo pipefail
ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

function tidy_cmd() {
  echo 'go mod tidy -v'
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

function unittest_cmd() {
  if [ -x "$(command -v gotest)" ]; then
    cmd='gotest'
  else
    cmd='go test'
  fi
  echo "${cmd} -short -race ./..."
}

function codegen_cmd() {
  echo "${ROOT}/hack/codegen.sh codegen::generate"
}

function codegen_verify_cmd() {
  echo "${ROOT}/hack/codegen.sh codegen::verify"
}

# The race detector is slow, so sometimes you don't want to use it
function unittest_no_race_cmd() {
  if [ -x "$(command -v gotest)" ]; then
    cmd='gotest'
  else
    cmd='go test'
  fi
  echo "${cmd} -short ./..."
}

function with_modules() {
  local cmd_function="${1}"
  cmd="$(${cmd_function})"

  pushd "${ROOT}"
  for mod_file in $(find . -maxdepth 4 -name go.mod | sort); do
    mod_dir="$(dirname "${mod_file}")"
    (
      export MOD_DIR
      echo "=> "
      echo "   cd ${mod_dir} && ${cmd}"
      cd "${mod_dir}" && MOD_DIR="$(pwd)" && ${cmd}
    )
  done
  popd
}

function usage() {
  echo "Error: <task> must be specified"
  echo "       do.sh <task> [tidy, lint, test, unittest, unittest_no_race, codegen, codegen_verify]"
  exit 1
}

function main() {
  case "${1:-invalid}" in
    'tidy') with_modules 'tidy_cmd' ;;
    'lint') with_modules 'lint_cmd' ;;
    'test') with_modules 'test_cmd' ;;
    'unittest') with_modules 'unittest_cmd' ;;
    'unittest_no_race') with_modules 'unittest_no_race_cmd' ;;
    'codegen') with_modules 'codegen_cmd' ;;
    'codegen_verify') with_modules 'codegen_verify_cmd' ;;
    *) usage ;;
  esac
}

main "$@"
