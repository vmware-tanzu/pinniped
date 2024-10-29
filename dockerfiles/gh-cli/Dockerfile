# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# For running the GitHub CLI.
FROM debian:12.7-slim AS builder

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

RUN curl \
    -sfLo /tmp/gh.tar.gz \
    https://github.com/cli/cli/releases/download/v2.40.0/gh_2.40.0_linux_amd64.tar.gz \
    && tar -C /tmp --strip-components=1 -xzvf /tmp/gh.tar.gz

FROM golang:1.23.2
COPY --from=builder /tmp/bin/gh /usr/local/bin/gh
