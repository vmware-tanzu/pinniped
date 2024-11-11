#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script deploys the concourse worker component into our GKE environment using Helm
# and secrets from GCP and Terraform.

HELM_RELEASE_NAME="concourse-workers"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! command -v gcloud &>/dev/null; then
  echo "Please install the gcloud CLI"
  exit
fi
if ! command -v yq &>/dev/null; then
  echo "Please install the yq CLI"
  exit
fi
if ! command -v kubectl &>/dev/null; then
  echo "Please install the kubectl CLI"
  exit
fi
if ! command -v helm &>/dev/null; then
  echo "Please install the helm CLI"
  exit
fi
if ! command -v ytt &>/dev/null; then
  echo "Please install the ytt CLI"
  exit
fi
if ! command -v terraform &>/dev/null; then
  echo "Please install the terraform CLI"
  exit
fi
if [[ -z "$(gcloud config list account --format "value(core.account)")" ]]; then
  echo "Please run \`gcloud auth login\`"
  exit 1
fi

# Add/update the concourse helm repository.
helm repo add concourse https://concourse-charts.storage.googleapis.com/
helm repo update concourse

# Create a temporary directory for secrets, cleaned up at the end of this script.
trap 'rm -rf "$DEPLOY_TEMP_DIR"' EXIT
DEPLOY_TEMP_DIR=$(mktemp -d) || exit 1

TERRAFORM_OUTPUT_FILE="$DEPLOY_TEMP_DIR/terraform-outputs.yaml"

# Get the output values from terraform.
pushd "$script_dir/../terraform/gcloud" >/dev/null
terraform output --json >"$TERRAFORM_OUTPUT_FILE"
popd >/dev/null

CLUSTER_NAME=$(yq eval '.cluster-name.value' "$TERRAFORM_OUTPUT_FILE")
PROJECT=$(yq eval '.project.value' "$TERRAFORM_OUTPUT_FILE")
ZONE=$(yq eval '.zone.value' "$TERRAFORM_OUTPUT_FILE")

# Download the admin kubeconfig for the cluster.
export KUBECONFIG="$DEPLOY_TEMP_DIR/kubeconfig.yaml"
gcloud container clusters get-credentials "$CLUSTER_NAME" --project "$PROJECT" --zone "$ZONE"
chmod 0600 "$KUBECONFIG"

# Download some secrets. These were created once by bootstrap-secrets.sh.
BOOTSTRAP_SECRETS_FILE="$DEPLOY_TEMP_DIR/concourse-install-bootstrap.yaml"
gcloud secrets versions access latest --secret="concourse-install-bootstrap" --project "$PROJECT" >"$BOOTSTRAP_SECRETS_FILE"

TSA_HOST_KEY_PUB=$(yq eval '.secrets.hostKeyPub' "$BOOTSTRAP_SECRETS_FILE")
WORKER_PRIVATE_KEY=$(yq eval '.secrets.workerKey' "$BOOTSTRAP_SECRETS_FILE")

# Dump out the cluster info for diagnostic purposes.
kubectl cluster-info

# Some of the configuration options used below were inspired by how HushHouse runs on GKE.
# See https://github.com/concourse/hush-house/blob/master/deployments/with-creds/workers/values.yaml

# Install/upgrade the helm chart.
# These settings are documented in https://github.com/concourse/concourse-chart/blob/master/values.yaml
# Note that `--version` chooses the version of the concourse/concourse chart. Each version of the chart
# chooses which version of Concourse to install by defaulting the value for `imageTag` in its values.yaml file.
helm upgrade "$HELM_RELEASE_NAME" concourse/concourse \
  --version 17.3.1 \
  --debug \
  --install \
  --wait \
  --create-namespace \
  --namespace concourse-worker \
  --values "$script_dir/internal-workers/values-workers.yaml" \
  --set concourse.worker.tsa.publicKey="$TSA_HOST_KEY_PUB" \
  --set concourse.worker.tsa.workerPrivateKey="$WORKER_PRIVATE_KEY" \
  --set secrets.workerKey="$WORKER_PRIVATE_KEY" \
  --set secrets.hostKeyPub="$TSA_HOST_KEY_PUB" \
  --post-renderer "$script_dir/internal-workers/ytt-helm-postrender-workers.sh"

# By default, it will not be possible for the autoscaler to scale down to one node.
# The autoscaler logs will show that the kube-dns pod cannot be moved. See
# https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-autoscaler-visibility#debugging_scenarios
# for how to view and interpret the autoscaler logs.
# This seems to be the workaround for the "no.scale.down.node.pod.kube.system.unmovable" error
# that we were getting for the kube-dns pod in the logs.
kubectl create poddisruptionbudget kube-dns-pdb \
  --namespace=kube-system \
  --selector k8s-app=kube-dns \
  --max-unavailable 1 \
  --dry-run=client -o yaml | kubectl apply -f -