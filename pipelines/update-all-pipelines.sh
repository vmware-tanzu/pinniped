#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -eu

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

failed_scripts=()

for update_pipeline_script in $(find "$script_dir" -name update-pipeline.sh); do
  echo "Running $update_pipeline_script..."
  set +e
  $update_pipeline_script
  if [[ $? -ne 0 ]]; then
    failed_scripts+="$update_pipeline_script"
  fi
  set -e
  echo
done

for failed_script in ${failed_scripts:-}; do
  echo "FAILED: ${failed_script}"
done

if [ ${#failed_scripts[@]} -ne 0 ]; then
  exit 1
fi
