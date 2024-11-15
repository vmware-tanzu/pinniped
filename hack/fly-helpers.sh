# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# Some global fly config.
#
export FLY_CLI=/usr/local/bin/fly
export CONCOURSE_URL=https://ci.pinniped.dev
export CONCOURSE_TEAM=main
export CONCOURSE_TARGET=pinniped
export ROOT_DIR
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.."

#
# Some helper functions for the update-pipeline scripts to use.
#
function set_pipeline() {
  # Ensure that fly is installed/upgraded/configured.
  "$ROOT_DIR"/hack/setup-fly.sh

  # Ensure that the user is authenticated with gcloud.
  if ! gcloud auth print-access-token &>/dev/null; then
    echo "Please run \`gcloud auth login\` and try again."
    exit 1
  fi

  if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
    echo "PINNIPED_GCP_PROJECT env var must be set"
    exit 1
  fi

  # Local vars.
  local pipeline_name=$1
  local pipeline_file=$2
  local gcloud_project="$PINNIPED_GCP_PROJECT"
  local gcloud_secret_name=concourse-secrets

  # Create/update the pipeline.
  $FLY_CLI --target "$CONCOURSE_TARGET" set-pipeline \
    --pipeline "$pipeline_name" \
    --config "$pipeline_file" \
    --load-vars-from <(gcloud secrets versions access latest \
      --secret="$gcloud_secret_name" \
      --project "$gcloud_project")
}

function ensure_time_resource_has_at_least_one_version() {
  local pipeline_name=$1
  local resource_name=$2

  # Force the specified time resource to have at least one version. Idempotent.
  # For a new pipeline, a time resource will have no versions until the specified time has occurred.
  # For example, a once-per-night time resource will have no versions until that time
  # has passed on the first night.
  $FLY_CLI --target "$CONCOURSE_TARGET" check-resource \
    --resource "$pipeline_name/$resource_name" \
    --from "time:2000-01-01T00:00:00Z" >/dev/null
}
