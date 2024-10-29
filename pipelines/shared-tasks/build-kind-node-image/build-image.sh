#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This procedure is inspired from https://github.com/aojea/kind-images/blob/master/.circleci/config.yml

set -euo pipefail

# Choose the tag for the new image that we will build below.
full_repo="${PUSH_TO_IMAGE_REGISTRY}/${PUSH_TO_IMAGE_REPO}"
image_tag="${full_repo}:latest"

# Make sure some basic build tools are installed.
sudo apt-get update && sudo sudo apt-get install build-essential procps curl file git rsync -y

# Install kubectl.
curl -fLO https://storage.googleapis.com/kubernetes-release/release/"$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)"/bin/linux/amd64/kubectl
chmod +x kubectl
sudo mv kubectl /usr/local/bin/

# Install docker according to procedure from https://docs.docker.com/engine/install/debian/
sudo apt-get install apt-transport-https ca-certificates curl gnupg lsb-release -y
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io -y
sudo systemctl enable docker.service
sudo systemctl enable containerd.service
# Docker is only available for use by the root user in a default install, so run docker commands as root.
sudo docker run hello-world

echo
echo "Installing Docker and dev tools succeeded."
echo

# Clone kind and k/k.
git clone https://github.com/kubernetes-sigs/kind.git kind
kind_version=$(git -C kind log -1 --pretty='%h')
# Clone as root because we are going to run the Kubernetes build scripts as root,
# and the file ownerships need to match the user who runs the scripts.
sudo git clone https://github.com/kubernetes/kubernetes.git /tmp/kubernetes
kube_version=$(sudo git -C /tmp/kubernetes log -1 --pretty='%h')

echo
echo "Cloning repos succeeded. Kind @ ${kind_version} and Kube @ ${kube_version}."
echo

# Build kind. This make command will install Go if needed.
cd kind
make build

echo
echo "Building kind succeeded."
echo

# Use kind to build a node image using the latest k/k.
sudo ./bin/kind build node-image --image "${image_tag}" /tmp/kubernetes -v=3

echo
echo "Building node image succeeded."
echo

# Test that the new kind image can be used to successfully create a kind cluster.
# In case of cluster creation failure, maybe it would be interesting to export the logs? `./bin/kind export logs /tmp/kind`
sudo ./bin/kind create cluster --image "${image_tag}" -v=3 --wait 1m --retain

# Make sure we can query some basic stuff from the new cluster.
sudo kubectl get nodes -o wide
sudo kubectl get pods --all-namespaces -o wide
sudo kubectl get services --all-namespaces -o wide

echo
echo "Creating cluster with new node image succeeded."
echo

echo "$DOCKER_PASSWORD" | sudo docker login "${PUSH_TO_IMAGE_REGISTRY}" -u "$DOCKER_USERNAME" --password-stdin
sudo docker push "${image_tag}"

version_tag="${full_repo}:kind${kind_version}_k8s${kube_version}"
sudo docker tag "${image_tag}" "${version_tag}"
sudo docker push "${version_tag}"

echo
echo "Image push succeeded."
