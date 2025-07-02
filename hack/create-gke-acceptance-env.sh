#!/usr/bin/env bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

if ! [ -x "$(command -v gcloud)" ]; then
  echo 'Error: Google Cloud SDK (gcloud) is not installed (see https://cloud.google.com/sdk/docs/quickstarts).' >&2
  exit 1
fi

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

if [[ -z "${SHARED_VPC_PROJECT:-}" ]]; then
  echo "SHARED_VPC_PROJECT env var must be set"
  exit 1
fi
if [[ -z "${SHARED_VPC_NAME:-}" ]]; then
  echo "SHARED_VPC_NAME env var must be set"
  exit 1
fi
if [[ -z "${SUBNET_NAME:-}" ]]; then
  echo "SUBNET_NAME env var must be set"
  exit 1
fi

CLUSTER_ZONE="us-west1-c"
SUBNET_REGION="us-west1"

# Create (or recreate) a GKE acceptance cluster.
# Pro tip: The GCP Console UI can help you build this command.
# The following fields were customized, and all of the others are left as the GCP Console's defaults:
#  - Cluster name
#  - Cluster version - newest at the time
#  - Num nodes - sized smaller to be cheaper
#  - Maintenance window start and recurrence - to avoid downtime during business hours
#  - Issue client certificate - to make it possible to use an admin kubeconfig without the GKE auth plugin
#  - tags, authorized networks, private nodes, private endpoint, network, subnet, and secondary ranges
gcloud container --project "$PINNIPED_GCP_PROJECT" clusters create "gke-acceptance-cluster" \
  --zone "$CLUSTER_ZONE" \
  --no-enable-basic-auth \
  --cluster-version "1.33.1-gke.1584000" \
  --release-channel "regular" \
  --machine-type "e2-medium" \
  --image-type "COS_CONTAINERD" --disk-type "pd-balanced" --disk-size "100" --metadata disable-legacy-endpoints=true \
  --scopes "https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append" \
  --num-nodes "1" \
  --logging=SYSTEM,WORKLOAD --monitoring=SYSTEM,STORAGE,POD,DEPLOYMENT,STATEFULSET,DAEMONSET,HPA,CADVISOR,KUBELET \
  --no-enable-intra-node-visibility \
  --default-max-pods-per-node "110" \
  --security-posture=standard --workload-vulnerability-scanning=disabled \
  --addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver \
  --enable-autoupgrade --enable-autorepair --max-surge-upgrade 1 --max-unavailable-upgrade 0 \
  --binauthz-evaluation-mode=DISABLED --enable-managed-prometheus --enable-shielded-nodes --node-locations "$CLUSTER_ZONE" \
  --maintenance-window-start "2020-07-01T03:00:00Z" --maintenance-window-end "2020-07-01T11:00:00Z" \
  --maintenance-window-recurrence "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR,SA,SU" \
  --issue-client-certificate \
  --tags "gke-broadcom" \
  --enable-master-authorized-networks \
  --master-authorized-networks "10.0.0.0/8" \
  --enable-private-nodes \
  --enable-private-endpoint \
  --enable-ip-alias \
  --network "projects/${SHARED_VPC_PROJECT}/global/networks/${SHARED_VPC_NAME}" \
  --subnetwork "projects/${SHARED_VPC_PROJECT}/regions/${SUBNET_REGION}/subnetworks/${SUBNET_NAME}" \
  --cluster-secondary-range-name "services" \
  --services-secondary-range-name "pods"
