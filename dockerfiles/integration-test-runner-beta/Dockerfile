# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# For running the integration tests as a client to a k8s cluster

FROM mikefarah/yq:4.44.3 AS yq

# We need gcloud for running integration tests against GKE
# because the kubeconfig uses gcloud as an `auth-provider`.
# Use FROM gcloud-sdk instead of FROM golang because its
# a lot easier to install Go than to install gcloud in the
# subsequent commands below.
FROM google/cloud-sdk:501.0.0-slim

# Install apache2-utils (for htpasswd to bcrypt passwords for the
# local-user-authenticator) and jq.
RUN apt-get update && apt-get install -y apache2-utils jq wget zip procps alien google-cloud-sdk-gke-gcloud-auth-plugin && rm -rf /var/lib/apt/lists/*

# Print version of gke-gcloud-auth-plugin
RUN gke-gcloud-auth-plugin --version

# Create a non-root user account that can be used to run the tests.
RUN useradd --create-home testrunner

# Install latest beta chrome.
RUN \
    chown root:root /tmp && \
    chmod 1777 /tmp && \
    curl -fsSL -o - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add && \
    echo "deb https://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list  && \
    apt-get -y update && \
    apt-get -y install google-chrome-beta

# Output Chrome version used
RUN google-chrome --version

# Install Go. The download URL that can be used below for any version of Go can be found on https://go.dev/dl/
ENV PATH /usr/local/go/bin:$PATH
RUN curl -fsSL https://go.dev/dl/go1.23.3.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz && \
    go version
ENV GOPATH /go
ENV PATH $GOPATH/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
WORKDIR $GOPATH

# Install go tools gotestsum and test2json to record the test output in a nice format.
RUN go install gotest.tools/gotestsum@latest
RUN env GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o test2json -ldflags="-s -w" cmd/test2json && \
    mv test2json /usr/local/bin/test2json

# Install Carvel tools.
RUN bash -c "set -eo pipefail; curl -fsSL https://carvel.dev/install.sh | bash" && \
    ytt version && kapp version && kbld version && kwt version && imgpkg version && vendir version

# Install the latest kubectl as documented here: https://kubernetes.io/docs/tasks/tools/install-kubectl-linux/
RUN curl -fsSL "https://dl.k8s.io/release/$(curl -fsSL "https://dl.k8s.io/release/stable.txt")/bin/linux/amd64/kubectl" \
    -o /bin/kubectl && chmod 0755 /bin/kubectl

# Install aws-iam-authenticator
RUN curl -fsSL  \
    https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v0.6.14/aws-iam-authenticator_0.6.14_linux_amd64 \
    -o /bin/aws-iam-authenticator \
    && chmod 0755 /bin/aws-iam-authenticator

# Install TMC CLI.
# Update: The TMC CLI has been deprecated and replaced by the tanzu CLI. Commenting this out for now.
#RUN curl -fsSL https://tanzuuserauthentication.stable.tmc-dev.cloud.vmware.com/v1alpha/system/binaries \
#    | jq -r .versions[].linuxX64 \
#    | xargs curl -fsSL -o /bin/tmc && chmod 0755 /bin/tmc && \
#    tmc version

# Install yq.
COPY --from=yq /usr/bin/yq /usr/local/bin/yq

# install latest nmap
RUN wget https://nmap.org/dist/nmap-7.92-1.x86_64.rpm &&\
    alien nmap-7.92-1.x86_64.rpm &&\
    dpkg -i nmap_7.92-2_amd64.deb
