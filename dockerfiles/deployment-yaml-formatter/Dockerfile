# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM mikefarah/yq:4.45.2 AS yq

FROM debian:12.10-slim

# Note: libdigest-sha-perl is to get shasum, which is used when installing Carvel tools below.
RUN apt-get update && apt-get install -y ca-certificates jq curl libdigest-sha-perl && rm -rf /var/lib/apt/lists/*

# Install Carvel tools.
RUN bash -c "set -eo pipefail; curl -fsL https://carvel.dev/install.sh | bash" && \
    ytt version && kapp version && kbld version && kwt version && imgpkg version && vendir version

# Install yq.
COPY --from=yq /usr/bin/yq /usr/local/bin/yq
