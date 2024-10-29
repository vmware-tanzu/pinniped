#!/usr/bin/env bash

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# Install and configure cert-manager to generate letsencrypt TLS certs for the supervisor
# which can be used for manual testing on the cluster. In order to use it, create a
# FederationDomain which specifies an issuer with the same name DNS name as the certificate
# and also specifies the same secretName as used below in the Certificate CR.
# The DNS record for the DNS name use here should be manually created elsewhere to point
# to the Supervisor's load balancer IP address.
#
# See sample-federation-domain.yaml in this directory for an example FederationDomain
# which will use these letsencrypt certs, which you can apply to the acceptance cluster.

if [[ -z "${PINNIPED_GCP_PROJECT:-}" ]]; then
  echo "PINNIPED_GCP_PROJECT env var must be set"
  exit 1
fi

# Use the kubeconfig from the task inputs.
export KUBECONFIG="$(pwd)/kubeconfig/kubeconfig"

# Load some deployment related env vars, like PINNIPED_TEST_SUPERVISOR_NAMESPACE, from the task inputs.
source integration-test-env-vars/integration-test-env

# Install or update cert-manager. This will create a "cert-manager" namespace.
kapp deploy --yes --app cert-manager --diff-changes \
  --file "https://github.com/cert-manager/cert-manager/releases/download/v1.10.1/cert-manager.yaml"

# Configure a DNS admin account for cert-manager to use.
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: cert-manager-credentials
  namespace: cert-manager
type: Opaque
data:
  cert-manager-dns-admin.json: $(echo "$CERT_MANAGER_DNS_ADMIN_JSON_KEY" | base64 -w 0)
EOF

# Configure cert-manager to use letsencrypt.
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    email: tanzu-user-authentication@groups.vmware.com
    privateKeySecretRef:
      name: letsencrypt-prod
    server: https://acme-v02.api.letsencrypt.org/directory
    solvers:
    - dns01:
        cloudDNS:
          project: "$PINNIPED_GCP_PROJECT"
          serviceAccountSecretRef:
            key: cert-manager-dns-admin.json
            name: cert-manager-credentials
EOF

# Configure cert-manager to create a serving cert for the Supervisor.
# Save it into a Secret (secretName below) that can be used for manual testing.
cat <<EOF | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: supervisor-letsencrypt-tls-certificate
  namespace: ${PINNIPED_TEST_SUPERVISOR_NAMESPACE}
spec:
  dnsNames:
  # This name can be set up as a DNS A record in our DNS account
  # to point at the IP of the Supervisor load balancer Service.
  - le.test.pinniped.dev
  issuerRef:
    kind: ClusterIssuer
    name: letsencrypt-prod
  privateKey:
    algorithm: ECDSA
    size: 256
  secretName: supervisor-letsencrypt-tls-certificate
EOF
