# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# For running Go linters
FROM debian:12.10-slim AS builder

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

RUN curl -sfLo /tmp/codecov https://uploader.codecov.io/latest/linux/codecov
RUN chmod +x /tmp/codecov

FROM golang:1.24.2
RUN apt-get update -y && apt-get dist-upgrade -y
COPY --from=builder /tmp/codecov /usr/local/bin/codecov
