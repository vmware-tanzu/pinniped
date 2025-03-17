# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# For deploying an EKS cluster and setting it up to run our tests.

FROM weaveworks/eksctl:v0.198.0 AS eksctl
FROM mikefarah/yq:4.45.1 AS yq
FROM amazon/aws-cli:2.24.24
RUN yum update -y && yum install -y jq && yum install -y perl-Digest-SHA && yum clean all
COPY --from=eksctl /usr/local/bin /usr/local/bin
COPY --from=yq /usr/bin/yq /usr/local/bin/yq

# Install Carvel tools.
RUN bash -c "set -eo pipefail; curl -fsL https://carvel.dev/install.sh | bash" && \
    ytt version && kapp version && kbld version && kwt version && imgpkg version && vendir version

# Install aws-iam-authenticator.
# This gets installed automatically via eksctl, but currently it downloads v0.5.2,
# which will give us a v1alpha1 execcredential rather than a v1beta1 which we want.
# When this has changed, we can delete this:
# https://github.com/weaveworks/eksctl/blob/main/build/docker/Dockerfile#L49
RUN curl -sfL  \
    https://github.com/kubernetes-sigs/aws-iam-authenticator/releases/download/v0.6.14/aws-iam-authenticator_0.6.14_linux_amd64 \
    -o /usr/local/bin/aws-iam-authenticator \
    && chmod u+x /usr/local/bin/aws-iam-authenticator
