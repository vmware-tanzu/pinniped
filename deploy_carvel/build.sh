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
kapp deploy --app kapp-controller --file https://github.com/vmware-tanzu/carvel-kapp-controller/releases/latest/download/release.yml # -y
kubectl get customresourcedefinitions

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

echo ""
echo_yellow "cleaning ./package-repository..."
rm -rf "./package-repository"
mkdir -p "./package-repository/.imgpkg"
mkdir -p "./package-repository/packages/concierge.pinniped.dev"
mkdir -p "./package-repository/packages/supervisor.pinniped.dev"

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
  echo_yellow "generating ./package-repository/packages/${resource_package_version}/${PINNIPED_PACKAGE_VERSION}.yml"
  ytt \
    --file "${resource_name}/package-template.yml" \
    --data-value-file openapi="$(pwd)/${resource_name}/schema-openapi.yml" \
    --data-value package_version="${PINNIPED_PACKAGE_VERSION}" \
    --data-value package_image_repo="${package_push_repo_location}" > "package-repository/packages/${resource_package_version}/${PINNIPED_PACKAGE_VERSION}.yml"

  echo_yellow "copying ${resource_name}/metadata.yml to ./package-repository/packages/${resource_name}"
  cp "./${resource_name}/metadata.yml" "./package-repository/packages/${resource_package_version}/metadata.yml"

done


echo_yellow "generating ./package-repository/.imgpkg/images.yml"
kbld --file ./package-repository/packages/ --imgpkg-lock-output package-repository/.imgpkg/images.yml
package_repository_push_repo_location="${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
echo_yellow "pushing package repository image: ${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}..."
imgpkg push --bundle "${package_repository_push_repo_location}" --file ./package-repository

echo_yellow "validating imgpkg package bundle contents..."
imgpkg pull --bundle "${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}" --output "/tmp/${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"
ls -la "/tmp/${PACKAGE_REPO_HOST}:${PINNIPED_PACKAGE_VERSION}"

PINNIPED_PACKGE_REPOSITORY_NAME="pinniped-package-repository"
PINNIPED_PACKGE_REPOSITORY_FILE="packagerepository.${PINNIPED_PACKAGE_VERSION}.yml"
echo -n "" > "${PINNIPED_PACKGE_REPOSITORY_FILE}"
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
kapp deploy --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" --file "${PINNIPED_PACKGE_REPOSITORY_FILE}"
kapp inspect --app "${PINNIPED_PACKGE_REPOSITORY_NAME}" --tree


# this is just a note to break this up, probably should use a separate ./deploy_stuff.sh file.
echo_green "CONSUMPTION OF PACKAGE HERE"
echo_green "CONSUMPTION OF PACKAGE HERE"
echo_green "CONSUMPTION OF PACKAGE HERE"

echo_yellow "deploying RBAC for use with pinniped PackageInstall..."

# TODO: obviously a mega-role that can do everything is not good.
declare -a arr=("supervisor" "concierge")
for resource_name in "${arr[@]}"
do

NAMESPACE="${resource_name}-ns"
PINNIPED_PACKAGE_RBAC_PREFIX="pinniped-package-rbac-${resource_name}"
PINNIPED_PACKAGE_RBAC_FILE="./temp_actual_deploy_resources/${PINNIPED_PACKAGE_RBAC_PREFIX}-${resource_name}-rbac.yml"

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
  namespace: default # this is default on purpose so the PackageInstall can find it
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
# kapp deploy --app pkg-demo --file pkginstall.yml -y

done

#FOOBAR="pinniped-package-rbac"
#PINNIPED_PACKAGE_RBAC_FILE="./temp_actual_deploy_resources/${PINNIPED_PACKAGE_RBAC_PREFIX}-rbac.yml"
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
PACKAGE_INSTALL_FILE_NAME="./temp_actual_deploy_resources/${resource_name}-pkginstall.yml"
SECRET_NAME="${resource_name}-package-install-secret"
cat > "${PACKAGE_INSTALL_FILE_NAME}" << EOF
---
apiVersion: packaging.carvel.dev/v1alpha1
kind: PackageInstall
metadata:
    name: "${resource_name}-package-install"
    namespace: default # this is default on purpose so the ServiceAccount can be found
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

echo_yellow "listing all package resources.."
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
