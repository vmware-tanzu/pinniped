#!/usr/bin/env bash

# https://gist.github.com/mohanpedala/1e2ff5661761d3abd0385e8223e16425
set -e # immediately exit
set -u # error if variables undefined
set -o pipefail # prevent masking errors in a pipeline
# set -x # print all executed commands to terminal


RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
DEFAULT='\033[0m'

echo_yellow() {
    echo -e "${YELLOW}>> $@${DEFAULT}\n"
    # printf "${GREEN}$@${DEFAULT}"
}

echo_green() {
    echo -e "${GREEN}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_red() {
    echo -e "${RED}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}
echo_blue() {
    echo -e "${BLUE}>> $@${DEFAULT}\n"
    # printf "${BLUE}$@${DEFAULT}"
}

# got a cluster?
echo_yellow "Verify you have a functional kind cluster, otherwise this will fail....."
# ./kind-with-registry.sh
# got kapp-controller bits?
kubectl get customresourcedefinitions
kapp deploy --app kapp-controller --file https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml -y
kubectl get customresourcedefinitions

# this argument is given to kapp-controller by default
# in the above deployment manfiest:
#   -packaging-global-namespace=kapp-controller-packaging-global
# which means, PackageRepos and Packages ought be installed in this
# namespace to be globally available by default, since
# PackageRepos and Packages are namespaced resources.
KAPP_CONTROLLER_GLOBAL_NAMESPACE="kapp-controller-packaging-global"

# TODO: since I removed the deployments there is not much in the ./imgpkg/images.yaml output
#
# build images found in these directories.
# make use of build.yaml files to specify how builds should work,
# if we need it to be done.
# kbld --file ./concierge/config --imgpkg-lock-output ./concierge/.imgpkg/images.yml

# this is used in the package-template.yml file for declaring where the package will live.
# we need to know where these package images should live :)
# REPO_HOST="1.2.3.4.fake.repo.host:5000"
# PACKAGE_REPO_HOST="projects.registry.vmware.com/pinniped/pinniped-server"
# PACKAGE_REPO_HOST="docker.io/benjaminapetersen/pinniped-package-repo"
PACKAGE_REPO_HOST="benjaminapetersen/pinniped-package-repo"
PINNIPED_PACKAGE_VERSION="0.25.0"

# TODO: cp ./deploy/supervisor.... into ./deploy_carvel/supervisor/config...
# TODO: cp ./deploy/concierge.... into ./deploy_carvel/concierge/config...
# -- we should copy this over, yeah?
#   NOTE: I did make changes to values.yaml to turn it into a values schema....

echo ""
echo_yellow "cleaning ./package-repository..."
PACKAGE_REPOSITORY_DIR="package-repository"
rm -rf "./${PACKAGE_REPOSITORY_DIR}"
mkdir -p "./${PACKAGE_REPOSITORY_DIR}/.imgpkg"
mkdir -p "./${PACKAGE_REPOSITORY_DIR}/packages/concierge.pinniped.dev"
mkdir -p "./${PACKAGE_REPOSITORY_DIR}/packages/supervisor.pinniped.dev"

PACKAGE_INSTALL_DIR="temp_actual_deploy_resources"
rm -rf "./${PACKAGE_INSTALL_DIR}"

## TODO:
## "${resource_name}/deployment.yml" vs "${resource_name}/deployment-HACKED.yml"
## the real one has images.
## - CURRENTLY the deployment.yaml files don't work, there is some error with pushing images.
##   come back to this later?
declare -a arr=("supervisor" "concierge")
for resource_name in "${arr[@]}"
do
  echo ""
  echo_yellow "handling ${resource_name}..."

  # just simple templating
  # ytt --file "./${resource_name}}/config/"
  # template, but process with kbld to update the yaml files with image digests such as
  #    image: index.docker.io/<repo>/<image>@sha256:<hash>
  # ytt --file "./${resource_name}}/config/" | kbld --file -

  echo_yellow "generating ${resource_name}/.imgpkg/images.yaml"
  # there are bits for image substitution in some of the ytt commands
  kbld --file "./${resource_name}/config/" --imgpkg-lock-output "./${resource_name}/.imgpkg/images.yml"

  # generate a schema in each package directory
  echo_yellow "generating ./${resource_name}/schema-openapi.yaml"
  ytt \
    --file "${resource_name}/config/values.yaml" \
    --data-values-schema-inspect --output openapi-v3 > "${resource_name}/schema-openapi.yml"

  # TODO:
  # push each package to the repository
  # note that I am hacking at this pattern to just get them to my dockerhub
  # this may or may not be the pattern we want when we push to a formal repository location
  # package_push_repo_location="${PACKAGE_REPO_HOST}/packages/${resource_name}:${PINNIPED_PACKAGE_VERSION}"
  package_push_repo_location="${PACKAGE_REPO_HOST}-package-${resource_name}:${PINNIPED_PACKAGE_VERSION}"
  echo_yellow "pushing package image: ${package_push_repo_location} ..."
  imgpkg push --bundle "${package_push_repo_location}" --file "./${resource_name}"

  resource_package_version="${resource_name}.pinniped.dev"
  echo_yellow "generating ./${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/${PINNIPED_PACKAGE_VERSION}.yml"
  ytt \
    --file "${resource_name}/package-template.yml" \
    --data-value-file openapi="$(pwd)/${resource_name}/schema-openapi.yml" \
    --data-value package_version="${PINNIPED_PACKAGE_VERSION}" \
    --data-value namespace="${KAPP_CONTROLLER_GLOBAL_NAMESPACE}" \
    --data-value package_image_repo="${package_push_repo_location}" > "${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/${PINNIPED_PACKAGE_VERSION}.yml"

  echo_yellow "generating ./${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/metadata.yml"
  ytt \
    --file "${resource_name}/metadata.yml" \
    --data-value-file openapi="$(pwd)/${resource_name}/schema-openapi.yml" \
    --data-value package_version="${PINNIPED_PACKAGE_VERSION}" \
    --data-value namespace="${KAPP_CONTROLLER_GLOBAL_NAMESPACE}" \
    --data-value package_image_repo="${package_push_repo_location}" > "${PACKAGE_REPOSITORY_DIR}/packages/${resource_package_version}/metadata.yml"

done

echo_yellow "generating ./${PACKAGE_REPOSITORY_DIR}/.imgpkg/images.yml"
kbld --file "./${PACKAGE_REPOSITORY_DIR}/packages/" --imgpkg-lock-output "${PACKAGE_REPOSITORY_DIR}/.imgpkg/images.yml"
package_repository_push_repo_location="${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
echo_yellow "pushing package repository image: ${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}..."
imgpkg push --bundle "${package_repository_push_repo_location}" --file "./${PACKAGE_REPOSITORY_DIR}"

echo_yellow "validating imgpkg package bundle contents..."
imgpkg pull --bundle "${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}" --output "/tmp/${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
ls -la "/tmp/${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"


echo_yellow "deploying PackageRepository..."
PINNIPED_PACKGE_REPOSITORY_NAME="pinniped-package-repository"
PINNIPED_PACKGE_REPOSITORY_FILE="packagerepository.${PINNIPED_PACKAGE_VERSION}.yml"
echo -n "" > "${PINNIPED_PACKGE_REPOSITORY_FILE}"
# kapp-controller's packaging-global-namespace does not apply to PackageRepository
cat <<EOT >> "${PINNIPED_PACKGE_REPOSITORY_FILE}"
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageRepository
metadata:
  name: "${PINNIPED_PACKGE_REPOSITORY_NAME}"
spec:
  fetch:
    imgpkgBundle:
      image: "${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
EOT


# Now, gotta make this work.  It'll be interesting if we can...
kapp deploy --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" --file "${PINNIPED_PACKGE_REPOSITORY_FILE}" -y
kapp inspect --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" --tree

sleep 2 # TODO: remove

# this is just a note to break this up, probably should use a separate ./deploy_stuff.sh file.
# at this point, we are "consumers".
# above we are packaging.
# this would be separated out into another script or potentially
# be on the user to craft (though we should likely provide something)
echo_green "Package Installation...."

echo_yellow "deploying RBAC for use with pinniped PackageInstall..."

# TODO: obviously a mega-role that can do everything is not good. we need to scope this down to appropriate things.
declare -a arr=("supervisor" "concierge")
for resource_name in "${arr[@]}"
do

NAMESPACE="${resource_name}-ns"
PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
PINNIPED_PACKAGE_RBAC_FILE="./${PACKAGE_INSTALL_DIR}/${PINNIPED_PACKAGE_RBAC_PREFIX}-${resource_name}-rbac.yml"

echo -n "" > "${PINNIPED_PACKAGE_RBAC_FILE}"
cat <<EOF >> "${PINNIPED_PACKAGE_RBAC_FILE}"
---
apiVersion: v1
kind: Namespace
metadata:
  name: "${NAMESPACE}"
---
# ServiceAccount details from the file linked above
apiVersion: v1
kind: ServiceAccount
metadata:
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-sa-superadmin-dangerous"
  namespace: "${NAMESPACE}"
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
  namespace: "${NAMESPACE}"
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: "${PINNIPED_PACKAGE_RBAC_PREFIX}-role-superadmin-dangerous"

EOF

kapp deploy --app "${PINNIPED_PACKAGE_RBAC_PREFIX}" --file "${PINNIPED_PACKAGE_RBAC_FILE}" -y
done

#FOOBAR="pinniped-package-rbac"
#PINNIPED_PACKAGE_RBAC_FILE="./${PACKAGE_INSTALL_DIR}/${PINNIPED_PACKAGE_RBAC_PREFIX}-rbac.yml"
## TODO: obviously a mega-role that can do everything is not good.
#echo -n "" > "${PINNIPED_PACKAGE_RBAC_FILE}"
#cat <<EOF >> "${PINNIPED_PACKAGE_RBAC_FILE}"
#
echo_yellow "deploying PackageInstall resources for pinniped supervisor and concierge packages..."
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
    namespace: "${NAMESPACE}"                     # TODO: ---????? is this namespace ok?
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
echo_yellow "deploying ${KAPP_CONTROLLER_APP_NAME}..."
kapp deploy --app "${KAPP_CONTROLLER_APP_NAME}" --file "${PACKAGE_INSTALL_FILE_NAME}" -y

done

echo_yellow "verifying PackageInstall resources..."
kubectl get PackageInstall -A | grep pinniped
kubectl get secret -A | grep pinniped

echo_yellow "listing all package resources (PackageRepository, Package, PackageInstall)..."
kubectl get pkgi && kubectl get pkgr && kubectl get pkg

echo_yellow "listing all kapp cli apps..."
# list again what is installed so we can ensure we have everything
kapp ls --all-namespaces

# these are fundamentally different than what kapp cli understands, unfortunately.
# the term "app" is overloaded in Carvel and can mean two different things, based on
# the use of kapp cli and kapp-controller on cluster
echo_yellow "listing all kapp-controller apps..."
kubectl get app --all-namespaces

# TODO:
# update the deployment.yaml and remove the deployment-HACKED.yaml files
# both are probably hacked a bit, so delete them and just get fresh from the ./deploy directory
# then make sure REAL PINNIPED actually deploys.


# In the end we should have:
# docker pull benjaminapetersen/pinniped-package-repo:latest
# docker pull benjaminapetersen/pinniped-package-repo-package-supervisor:0.25.0
# docker pull benjaminapetersen/pinniped-package-repo-package-concierge:0.25.0

# echo_yellow "verifying RBAC resources created (namespace, serviceaccount, clusterrole, clusterrolebinding)..."
# kubectl get ns -A | grep pinniped
# kubectl get sa -A | grep pinniped
# kubectl get ClusterRole -A | grep pinniped
# kubectl get clusterrolebinding -A | grep pinniped


# stuff
kubectl get PackageRepository -A
kubectl get Package -A
kubectl get PackageInstall -A
