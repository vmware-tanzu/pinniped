# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# For deploying apps onto Kubernetes clusters (including GKE)

FROM google/cloud-sdk:521.0.0-slim

# Install apache2-utils (for htpasswd to bcrypt passwords for the
# local-user-authenticator) and jq.
RUN apt-get update && apt-get install -y apache2-utils jq wget zip procps dnsutils google-cloud-sdk-gke-gcloud-auth-plugin && rm -rf /var/lib/apt/lists/*

# Print version of gke-gcloud-auth-plugin
RUN gke-gcloud-auth-plugin --version

# Install Carvel tools.
RUN bash -c "set -eo pipefail; curl -fsL https://carvel.dev/install.sh | bash" && \
    ytt version && kapp version && kbld version && kwt version && imgpkg version && vendir version

# Install latest kubectl.
RUN curl -sfL "https://dl.k8s.io/release/$(curl -sfL https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    -o /bin/kubectl && chmod u+x /bin/kubectl

# Install aws-iam-authenticator
RUN curl -sfL  \
    https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v0.6.14/aws-iam-authenticator_0.6.14_linux_amd64 \
    -o /bin/aws-iam-authenticator \
    && chmod u+x /bin/aws-iam-authenticator

# Install TMC CLI.
# Update: The TMC CLI has been deprecated and replaced by the tanzu CLI. Commenting this out for now.
#RUN curl -sfL https://tanzuuserauthentication.stable.tmc-dev.cloud.vmware.com/v1alpha/system/binaries \
#    | jq -r .versions[].linuxX64 \
#    | xargs curl -sfL -o /bin/tmc && chmod +x /bin/tmc && \
#    tmc version
