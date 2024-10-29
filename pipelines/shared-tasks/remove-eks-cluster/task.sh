#!/bin/bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Set up our AWS service account in the AWS CLI.
aws configure set credential_source Environment --profile service-account
aws configure set role_arn "$AWS_ROLE_ARN" --profile service-account

CLUSTER_NAME="$(cat eks-cluster-pool/name)"
export CLUSTER_NAME
export ADMIN_USERNAME="$CLUSTER_NAME-admin"
export AWS_PAGER=""  # prevent aws CLI hang with "WARNING: terminal is not fully functional"
export KUBECONFIG="$PWD/eks-cluster-pool/metadata"

echo "Removing $CLUSTER_NAME..."
eksctl delete cluster "$CLUSTER_NAME" --profile service-account --disable-nodegroup-eviction

# eksctl leaves these behind which leads to us running out of IPs
echo "Removing NAT for ${CLUSTER_NAME}"
aws ec2 describe-nat-gateways --profile service-account \
  --filter "Name=tag:eksctl.cluster.k8s.io/v1alpha1/cluster-name,Values=${CLUSTER_NAME}" \
  | jq -r '.NatGateways[0].NatGatewayId' \
  | xargs aws ec2 delete-nat-gateway --profile service-account --nat-gateway-id
