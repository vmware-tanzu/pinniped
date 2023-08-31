#!/usr/bin/env bash

# Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

#
# This script can be used to prepare a kind cluster and deploy the app.
# You can call this script again to redeploy the app.
# It will also output instructions on how to run the integration.
#

set -euo pipefail


# deploy the Carvel packages for Pinniped & Supervisor.
# - Deploy the PackageRepository
# - Create PackageInstalls for Supervisor, Concierge
#   - deploy these
# - then after, run hack/prepare-supervisor-on-kind.sh
#   - ideally this configures the Supervisor


# need a directory for our yamls for deployment
echo ""
PACKAGE_INSTALL_DIR="temp_actual_deploy_resources"
rm -rf "./${PACKAGE_INSTALL_DIR}"
mkdir "./${PACKAGE_INSTALL_DIR}"


log_note "Deploying Pinniped PackageRepository on kind cluster..."
# Now, gotta make this work.  It'll be interesting if we can...
kapp deploy --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" --file "${PINNIPED_PACKGE_REPOSITORY_FILE}" -y
kapp inspect --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" --tree




log_note "Generating RBAC for use with pinniped PackageInstall..."

# TODO: obviously a mega-role that can do everything is not good. we need to scope this down to appropriate things.
declare -a arr=("supervisor" "concierge")
for resource_name in "${arr[@]}"
do

  NAMESPACE="${resource_name}-ns"
  PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
  PINNIPED_PACKAGE_RBAC_FILE="./${PACKAGE_INSTALL_DIR}/${PINNIPED_PACKAGE_RBAC_PREFIX}-${resource_name}-rbac.yml"

  echo -n "" > "${PINNIPED_PACKAGE_RBAC_FILE}"
  cat <<EOF >> "${PINNIPED_PACKAGE_RBAC_FILE}"
# ---
# apiVersion: v1
# kind: Namespace
# metadata:
#  name: "${NAMESPACE}" <--- "supervisor-ns" will cause other package install errors.
---
# ServiceAccount details from the file linked above
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  # namespace: "${NAMESPACE}"
  namespace: default # --> sticking to default for everything for now.
---
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-superadmin-dangerous"
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-binding-superadmin-dangerous"
subjects:
- kind: ServiceAccount
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  # namespace: "${NAMESPACE}"
  namespace: default # --> sticking to default for everything for now.
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-superadmin-dangerous"

EOF

  kapp deploy --app "${PINNIPED_PACKAGE_RBAC_PREFIX}" --file "${PINNIPED_PACKAGE_RBAC_FILE}" -y
done



log_note "Deploying PackageInstall resources for pinniped supervisor and concierge packages..."
for resource_name in "${arr[@]}"
do

  NAMESPACE="${resource_name}-ns"
  PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
  RESOURCE_PACKGE_VERSION="${resource_name}.pinniped.dev"
  PACKAGE_INSTALL_FILE_NAME="./${PACKAGE_INSTALL_DIR}/${resource_name}-pkginstall.yml"
  SECRET_NAME="${resource_name}-package-install-secret"
  cat > "${PACKAGE_INSTALL_FILE_NAME}" << EOF
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
    # name, does not have to be versioned, versionSelection.constraints below will handle
    name: "${resource_name}-package-install"
    # namespace: "${NAMESPACE}"
    namespace: default # --> sticking to default for everything for now.
spec:
  serviceAccountName: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  packageRef:
    refName: "${RESOURCE_PACKGE_VERSION}"
    versionSelection:
      constraints: "${PINNIPED_PACKAGE_VERSION}"
  values:
  - secretRef:
      name: "${SECRET_NAME}"
---
apiVersion: v1
kind: Secret
metadata:
  name: "${SECRET_NAME}"
stringData:
  values.yml: |
    ---
    namespace: "${NAMESPACE}"
    app_name: "${resource_name}-app-awesomeness"
    replicas: 3
EOF

  KAPP_CONTROLLER_APP_NAME="${resource_name}-pkginstall"
  log_note "deploying ${KAPP_CONTROLLER_APP_NAME}..."
  kapp deploy --app "${KAPP_CONTROLLER_APP_NAME}" --file "${PACKAGE_INSTALL_FILE_NAME}" -y

done
