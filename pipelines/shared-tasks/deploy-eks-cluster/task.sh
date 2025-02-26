#!/bin/bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

echo "Using Kubernetes version $KUBE_VERSION"
cd deploy-eks-cluster-output

# Set up our AWS service account in the AWS CLI.
aws configure set credential_source Environment --profile service-account
aws configure set role_arn "$AWS_ROLE_ARN" --profile service-account

# Set some variables.
CLUSTER_NAME="eks-$(python -c 'import os,binascii; print binascii.b2a_hex(os.urandom(8))')"
ADMIN_USERNAME="$CLUSTER_NAME-admin"
export CLUSTER_NAME
export ADMIN_USERNAME
export AWS_PAGER=""  # prevent aws CLI hang with "WARNING: terminal is not fully functional"
ADMIN_KUBECONFIG="admin-kubeconfig"
SERVICE_ACCOUNT_NAME=test-admin-service-account
SERVICE_ACCOUNT_NAMESPACE=default
SECRET_NAME="${SERVICE_ACCOUNT_NAME}-secret"
NEW_KUBECONFIG_FILE="metadata"
NEW_CONTEXT=default
NEW_KUBECONFIG_USER="admin-service-account"

# The cluster name becomes the name of the lock in the pool.
echo "$CLUSTER_NAME" > name

# The kubeconfig file becomes the value of the lock in the pool.
echo "Creating $CLUSTER_NAME in $AWS_DEFAULT_REGION..."

# Note that the AWS account being used to run this command needs to have certain permissions.
# See https://eksctl.io/usage/minimum-iam-policies/ for permissions.
# See https://eksctl.io/usage/schema/ for documentation of this yaml.
cat <<EOF | eksctl create cluster -f - --kubeconfig "$ADMIN_KUBECONFIG" --profile service-account
apiVersion: eksctl.io/v1alpha5
kind: ClusterConfig

metadata:
  name: "$CLUSTER_NAME"
  region: "$AWS_DEFAULT_REGION"
  version: "$KUBE_VERSION"

nodeGroups:
  - name: ng-1
    instanceType: t3a.large
    desiredCapacity: 1

cloudWatch:
  clusterLogging:
    enableTypes: ["audit"]
EOF

# Do not keep audit logs forever
aws logs put-retention-policy --log-group-name "/aws/eks/${CLUSTER_NAME}/cluster" --retention-in-days 7  --profile service-account

# Add the service account's assumed role into the kubeconfig. I have no idea why eksctl did not do this for us.
# Because the cluster was created using this identity, this identity was automatically added to system:masters to make
# it an admin of the cluster. Even though the kubeconfig contains the AWS_PROFILE env var, and the profile should
# automatically assume this role, it does not seem to work unless we explicitly tell it to assume the role.
yq eval ".users[0].user.exec.args += [ \"--role\", \"$AWS_ROLE_ARN\" ]" -i "$ADMIN_KUBECONFIG"

# Verify that the cluster came online.
kubectl version --kubeconfig "$ADMIN_KUBECONFIG"

echo "create service account named ${SERVICE_ACCOUNT_NAME}..."
kubectl apply --kubeconfig "$ADMIN_KUBECONFIG" -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${SERVICE_ACCOUNT_NAME}
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
EOF

echo "granting cluster admin to service account..."
kubectl apply --kubeconfig "$ADMIN_KUBECONFIG" -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: cluster-admin-${SERVICE_ACCOUNT_NAME}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: ${SERVICE_ACCOUNT_NAME}
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
EOF

echo "create secret named ${SECRET_NAME}..."
kubectl apply --kubeconfig "$ADMIN_KUBECONFIG" -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${SECRET_NAME}
  namespace: ${SERVICE_ACCOUNT_NAMESPACE}
  annotations:
    kubernetes.io/service-account.name: ${SERVICE_ACCOUNT_NAME}
type: kubernetes.io/service-account-token
EOF

ADMIN_CONTEXT=$(kubectl config current-context --kubeconfig "$ADMIN_KUBECONFIG")

echo "getting service account token..."
TOKEN=$(kubectl --kubeconfig "$ADMIN_KUBECONFIG" get secret ${SECRET_NAME} \
  --context "${ADMIN_CONTEXT}" \
  --namespace ${SERVICE_ACCOUNT_NAMESPACE} \
  --output jsonpath='{.data.token}' | base64 --decode)

echo "create kubeconfig file for service account..."
# Make a copy.
cp "$ADMIN_KUBECONFIG" "$NEW_KUBECONFIG_FILE"

# Rename context
kubectl config --kubeconfig ${NEW_KUBECONFIG_FILE} rename-context "${ADMIN_CONTEXT}" ${NEW_CONTEXT}

# Create token user
kubectl config --kubeconfig ${NEW_KUBECONFIG_FILE} set-credentials "$NEW_KUBECONFIG_USER" --token "${TOKEN}"

# Set context to use token user
kubectl config --kubeconfig ${NEW_KUBECONFIG_FILE} set-context ${NEW_CONTEXT} --user "$NEW_KUBECONFIG_USER"

# Flatten/minify kubeconfig tp remove the old user
kubectl config --kubeconfig ${NEW_KUBECONFIG_FILE} view --flatten --minify > ${NEW_KUBECONFIG_FILE}.minified
mv ${NEW_KUBECONFIG_FILE}.minified ${NEW_KUBECONFIG_FILE}

# Check that the new kubeconfig file works
kubectl get namespaces --kubeconfig "${NEW_KUBECONFIG_FILE}"

# Set the permissions on the file.
chmod 0644 "${NEW_KUBECONFIG_FILE}"
