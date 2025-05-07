# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM gcr.io/go-containerregistry/crane as crane
FROM mikefarah/yq:4.45.1 AS yq

FROM golang:1.24.3
COPY --from=yq /usr/bin/yq /usr/local/bin
COPY --from=crane /ko-app/crane /usr/local/bin
ENTRYPOINT ["bash"]
