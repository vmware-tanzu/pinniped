#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
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

# Create (or recreate) a GKE acceptance cluster.
# Pro tip: The GCP Console UI can help you build this command.
# The following fields were customized, and all of the others are left as the GCP Console's defaults:
#  - Cluster name
#  - Cluster version - newest at the time
#  - Num nodes - sized smaller to be cheaper
#  - Maintenance window start and recurrence - to avoid downtime during business hours
#  - Issue client certificate - to make it possible to use an admin kubeconfig without the GKE auth plugin
gcloud container --project "$PINNIPED_GCP_PROJECT" clusters create "gke-acceptance-cluster" \
  --zone "us-central1-c" --no-enable-basic-auth --cluster-version "1.30.4-gke.1348000" --release-channel "regular" \
  --machine-type "e2-medium" \
  --image-type "COS_CONTAINERD" --disk-type "pd-balanced" --disk-size "100" --metadata disable-legacy-endpoints=true \
  --scopes "https://www.googleapis.com/auth/devstorage.read_only","https://www.googleapis.com/auth/logging.write","https://www.googleapis.com/auth/monitoring","https://www.googleapis.com/auth/servicecontrol","https://www.googleapis.com/auth/service.management.readonly","https://www.googleapis.com/auth/trace.append" \
  --num-nodes "1" \
  --logging=SYSTEM,WORKLOAD --monitoring=SYSTEM,STORAGE,POD,DEPLOYMENT,STATEFULSET,DAEMONSET,HPA,CADVISOR,KUBELET \
  --enable-ip-alias \
  --network "projects/$PINNIPED_GCP_PROJECT/global/networks/default" \
  --subnetwork "projects/$PINNIPED_GCP_PROJECT/regions/us-central1/subnetworks/default" \
  --no-enable-intra-node-visibility \
  --default-max-pods-per-node "110" \
  --security-posture=standard --workload-vulnerability-scanning=disabled --no-enable-master-authorized-networks \
  --addons HorizontalPodAutoscaling,HttpLoadBalancing,GcePersistentDiskCsiDriver \
  --enable-autoupgrade --enable-autorepair --max-surge-upgrade 1 --max-unavailable-upgrade 0 \
  --binauthz-evaluation-mode=DISABLED --enable-managed-prometheus --enable-shielded-nodes --node-locations "us-central1-c" \
  --maintenance-window-start "2020-07-01T03:00:00Z" --maintenance-window-end "2020-07-01T11:00:00Z" \
  --maintenance-window-recurrence "FREQ=WEEKLY;BYDAY=MO,TU,WE,TH,FR,SA,SU" \
  --issue-client-certificate
