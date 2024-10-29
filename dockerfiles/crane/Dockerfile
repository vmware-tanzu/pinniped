# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM gcr.io/go-containerregistry/crane as crane
FROM mikefarah/yq:4.44.3 AS yq

FROM golang:1.23
COPY --from=yq /usr/bin/yq /usr/local/bin
COPY --from=crane /ko-app/crane /usr/local/bin
ENTRYPOINT ["bash"]
