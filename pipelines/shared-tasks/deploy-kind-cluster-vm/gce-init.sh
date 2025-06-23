#!/bin/bash

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# This is the script that runs at startup to launch Kind on GCE.
# A log of the output of this script can be viewed by running this command on the VM:
# sudo journalctl -u google-startup-scripts.service

set -euo pipefail

function cleanup() {
  # Upon exit, try to save the log of everything that happened to make debugging errors easier.
  curl --retry-all-errors --retry 5 -X PUT --data "$(journalctl -u google-startup-scripts.service)" \
    http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/kind/init_log -H "Metadata-Flavor: Google"
}
trap "cleanup" EXIT SIGINT

INTERNAL_IP="$(curl --retry-all-errors --retry 5 http://metadata/computeMetadata/v1/instance/network-interfaces/0/ip -H "Metadata-Flavor: Google")"
KIND_VERSION="$(curl --retry-all-errors --retry 5 http://metadata.google.internal/computeMetadata/v1/instance/attributes/kind_version -H "Metadata-Flavor: Google")"
K8S_VERSION="$(curl --retry-all-errors --retry 5 http://metadata.google.internal/computeMetadata/v1/instance/attributes/k8s_version -H "Metadata-Flavor: Google")"
KIND_NODE_IMAGE="$(curl --retry-all-errors --retry 5 http://metadata.google.internal/computeMetadata/v1/instance/attributes/kind_node_image -H "Metadata-Flavor: Google")"

if [[ "$(uname -m)" = x86_64 ]]; then
  ARCH=amd64
elif [[ "$(uname -m)" = aarch64 ]]; then
  ARCH=arm64
else
  echo "Error determining architecture from uname -m = $(uname -m)"
  exit 1
fi

# Install kind
curl --retry-all-errors --retry 10 -Lo /var/lib/google/kind "https://github.com/kubernetes-sigs/kind/releases/download/${KIND_VERSION}/kind-linux-${ARCH}"
chmod +x /var/lib/google/kind

# Install kubectl
curl --retry-all-errors --retry 10 -Lo /var/lib/google/kubectl "https://dl.k8s.io/release/$(curl -fL -s https://dl.k8s.io/release/stable.txt)/bin/linux/${ARCH}/kubectl"
chmod +x /var/lib/google/kubectl

# Starting in Kind v0.12.0, it seems that we must use kubeadm.k8s.io/v1beta3 *only* for Kube 1.23+.
KIND_MAJOR_VERSION=$(echo "$KIND_VERSION" | cut -c2- | cut -d"." -f1) # also cuts off the leading "v"
KIND_MINOR_VERSION=$(echo "$KIND_VERSION" | cut -d"." -f2)
K8S_MAJOR_VERSION=$(echo "$K8S_VERSION" | cut -c2- | cut -d"." -f1) # also cuts off the leading "v"
K8S_MINOR_VERSION=$(echo "$K8S_VERSION" | cut -d"." -f2)
KUBE_ADM_VERSION="kubeadm.k8s.io/v1beta2"
if [[ "$KIND_MAJOR_VERSION" -gt "0" || ( "$KIND_MAJOR_VERSION" == "0" && "$KIND_MINOR_VERSION" -ge "12" ) ]]; then
  if [[ "$K8S_VERSION" == "k8s-main" || "$K8S_MAJOR_VERSION" -gt "1" || ( "$K8S_MAJOR_VERSION" == "1" && "$K8S_MINOR_VERSION" -ge "23" ) ]]; then
    KUBE_ADM_VERSION="kubeadm.k8s.io/v1beta3"
  fi
fi
echo "Selected kubeadm config version $KUBE_ADM_VERSION based on Kind version $KIND_VERSION and K8s version $K8S_VERSION"

# create a reasonable baseline audit config that only logs metadata
mkdir -p "/tmp/audit-config"
cat <<EOF > /tmp/audit-config/audit-config.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
# Don't generate audit events for all requests in RequestReceived stage.
omitStages:
- "RequestReceived"
rules:
# Don't log requests for events
- level: None
  resources:
  - group: ""
    resources: ["events"]
# Don't log authenticated requests to certain non-resource URL paths.
- level: None
  userGroups: ["system:authenticated", "system:unauthenticated"]
  nonResourceURLs:
  - "/api*" # Wildcard matching.
  - "/version"
  - "/healthz"
  - "/readyz"
# A catch-all rule to log all other requests at the Metadata level.
- level: Metadata
  # Long-running requests like watches that fall under this rule will not
  # generate an audit event in RequestReceived.
  omitStages:
  - "RequestReceived"
EOF

cat <<EOF > /tmp/kind.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  apiServerAddress: "0.0.0.0"
  apiServerPort: 6443
kubeadmConfigPatches:
- |
  apiVersion: ${KUBE_ADM_VERSION}
  kind: ClusterConfiguration
  # ControlPlaneEndpoint sets a stable IP address or DNS name for the control plane.
  controlPlaneEndpoint: "${INTERNAL_IP}:6443"
  # mount the kind extraMounts into the API server static pod so we can use the audit config
  apiServer:
    extraVolumes:
    - name: audit-config
      hostPath: /audit-config/audit-config.yaml
      mountPath: /audit-config/audit-config.yaml
      readOnly: true
      pathType: File
    extraArgs:
      audit-policy-file: /audit-config/audit-config.yaml
      audit-log-path: "-"  # log to standard out so that it gets captured by export-cluster-diagnostics
      v: "4"
      # To make sure the endpoints on our service are correct (this mostly matters for kubectl based
      # installs where kapp is not doing magic changes to the deployment and service selectors).
      # Setting this field to true makes it so that the API service will do the service cluster IP
      # to endpoint IP translations internally instead of relying on the network stack (i.e. kube-proxy).
      # The logic inside the API server is very straightforward - randomly pick an IP from the list
      # of available endpoints.  This means that over time, all endpoints associated with the service
      # are exercised.  For whatever reason, leaving this as false (i.e. use kube-proxy) appears to
      # hide some network misconfigurations when used internally by the API server aggregation layer.
      enable-aggregator-routing: "true"
  controllerManager:
    extraArgs:
      v: "4"
  scheduler:
    extraArgs:
      v: "4"
nodes:
- role: control-plane
  extraPortMappings:
  - protocol: TCP
    # This same port number is hardcoded in the integration test setup
    # when creating a Service on a kind cluster. It is used to talk to
    # the supervisor app via HTTPS.
    containerPort: 31243
    hostPort: 12344
    listenAddress: 127.0.0.1
  - protocol: TCP
    # This same port number is hardcoded in the integration test setup
    # when creating a Service on a kind cluster. It is used to talk to
    # the supervisor app via HTTP.
    # This is retained for the release-0.12 pipeline's use. The HTTP port
    # cannot be exposed anymore on main. When the release-0.12 pipeline
    # is not longer needed, then this port mapping can be removed.
    containerPort: 31234
    hostPort: 12345
    listenAddress: 127.0.0.1
  - protocol: TCP
    # This same port number is used for the second Pinniped deployment's
    # supervisor HTTPS port, when there are multiple Pinnipeds deployed.
    containerPort: 30243
    hostPort: 11344
    listenAddress: 127.0.0.1
  - protocol: TCP
    # This same port number is used for the second Pinniped deployment's
    # supervisor HTTP port, when there are multiple Pinnipeds deployed.
    # This is retained for the release-0.12 pipeline's use. The HTTP port
    # cannot be exposed anymore on main. When the release-0.12 pipeline
    # is not longer needed, then this port mapping can be removed.
    containerPort: 30234
    hostPort: 11345
    listenAddress: 127.0.0.1
  - protocol: TCP
    # This same port number is hardcoded in the integration test setup
    # when creating a Service on a kind cluster. It is used to talk to
    # the Dex app.
    containerPort: 31235
    hostPort: 12346
    listenAddress: 127.0.0.1
  # mount the audit config dir into kind
  extraMounts:
  - hostPath: /tmp/audit-config/
    containerPath: /audit-config
EOF

# When KIND_NODE_IMAGE is specified, then use it. Otherwise choose the official kind image for the specified version of K8s.
if [[ "$KIND_NODE_IMAGE" != "" ]]; then
  image="$KIND_NODE_IMAGE"
else
  image="kindest/node:${K8S_VERSION}"
fi

/var/lib/google/kind create cluster --wait 5m --kubeconfig /tmp/kubeconfig.yaml --image "$image" --config /tmp/kind.yaml |& tee /tmp/kind-cluster-create.log

# Change the kubeconfig to make the server address match the IP configured as controlPlaneEndpoint above.
sed -i "s/0\\.0\\.0\\.0/${INTERNAL_IP}/" /tmp/kubeconfig.yaml

# The above YAML config file specifies one node, and Kind should never put the "control-plane"
# taint on the node for single-node clusters. Due to the issue described in
# https://github.com/kubernetes-sigs/kind/issues/1699#issuecomment-1048269832
# we may not be able to rely on Kind automatically removing that taint, depending on which
# version of Kind and which version of the Kubernetes node image we're using, so to keep things
# simple we'll always remove that taint here.
node_name=$(/var/lib/google/kubectl get nodes -o jsonpath='{.items[0].metadata.name}' --kubeconfig /tmp/kubeconfig.yaml)
if [[ "$node_name" == "" ]]; then
  echo "ERROR: Did not find any nodes in the new cluster."
  exit 1
fi
# Check if there are any taints. Normally there should be none for single-node clusters,
# unless we are running into the problem described above.
node_taints=$(/var/lib/google/kubectl get nodes -o jsonpath='{.items[0].spec.taints[?(@.key=="node-role.kubernetes.io/control-plane")]}' --kubeconfig /tmp/kubeconfig.yaml)
if [[ "$node_taints" != "" ]]; then
  echo "Found taint node-role.kubernetes.io/control-plane Kind node: ${node_taints}"
  # Remove the taint that is causing us trouble.
  # Putting a minus sign at the end of the key name means remove all taints with that key.
  /var/lib/google/kubectl taint nodes "$node_name" "node-role.kubernetes.io/control-plane-" --kubeconfig /tmp/kubeconfig.yaml
fi

# Success! Save the kubeconfig file.
curl --retry-all-errors --retry 5 -X PUT --data "$(cat /tmp/kubeconfig.yaml)" \
  http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/kind/kubeconfig -H "Metadata-Flavor: Google"
