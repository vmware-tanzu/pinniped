#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# This script deploys the concourse web component into our GKE environment using Helm
# and secrets from GCP and Terraform.

HELM_RELEASE_NAME="concourse-web"

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
# This is needed for running gcloud commands.
if ! gcloud auth print-access-token &>/dev/null; then
  echo "Please run \`gcloud auth login\` and try again."
  exit 1
fi
# This is needed for running terraform commands.
if ! gcloud auth application-default print-access-token --quiet &>/dev/null; then
  echo "Please run \`gcloud auth application-default login\` and try again."
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
WEB_IP_ADDRESS=$(yq eval '.web-ip.value' "$TERRAFORM_OUTPUT_FILE")
WEB_HOSTNAME=$(yq eval '.web-hostname.value' "$TERRAFORM_OUTPUT_FILE")
DB_IP_ADDRESS=$(yq eval '.database-ip.value' "$TERRAFORM_OUTPUT_FILE")
DB_USERNAME=$(yq eval '.database-username.value' "$TERRAFORM_OUTPUT_FILE")
DB_PASSWORD=$(yq eval '.database-password.value' "$TERRAFORM_OUTPUT_FILE")
DB_CA_CERT=$(yq eval '.database-ca-cert.value' "$TERRAFORM_OUTPUT_FILE")
DB_CLIENT_CERT=$(yq eval '.database-cert.value' "$TERRAFORM_OUTPUT_FILE")
DB_CLIENT_KEY=$(yq eval '.database-private-key.value' "$TERRAFORM_OUTPUT_FILE")

# Download the admin kubeconfig for the cluster.
export KUBECONFIG="$DEPLOY_TEMP_DIR/kubeconfig.yaml"
gcloud container clusters get-credentials "$CLUSTER_NAME" --project "$PROJECT" --zone "$ZONE"
chmod 0600 "$KUBECONFIG"

# Download some secrets. These were created once by bootstrap-secrets.sh.
BOOTSTRAP_SECRETS_FILE="$DEPLOY_TEMP_DIR/concourse-install-bootstrap.yaml"
gcloud secrets versions access latest --secret="concourse-install-bootstrap" --project "$PROJECT" >"$BOOTSTRAP_SECRETS_FILE"

# Dump out the cluster info for diagnostic purposes.
kubectl cluster-info

# Some of the configuration options used below were inspired by how HushHouse runs on GKE.
# See https://github.com/concourse/hush-house/blob/master/deployments/with-creds/hush-house/values.yaml

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
  --namespace concourse-web \
  --values "$script_dir/web/values-web.yaml" \
  --values "$BOOTSTRAP_SECRETS_FILE" \
  --set web.service.api.loadBalancerIP="$WEB_IP_ADDRESS" \
  --set web.service.workerGateway.loadBalancerIP="$WEB_IP_ADDRESS" \
  --set concourse.web.externalUrl="https://$WEB_HOSTNAME" \
  --set concourse.web.postgres.host="$DB_IP_ADDRESS" \
  --set secrets.postgresUser="$DB_USERNAME" \
  --set secrets.postgresPassword="$DB_PASSWORD" \
  --set secrets.postgresCaCert="$DB_CA_CERT" \
  --set secrets.postgresClientCert="$DB_CLIENT_CERT" \
  --set secrets.postgresClientKey="$DB_CLIENT_KEY" \
  --post-renderer "$script_dir/web/ytt-helm-postrender-web.sh"

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
