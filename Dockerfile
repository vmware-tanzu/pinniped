# syntax = docker/dockerfile:1.0-experimental

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.16.0 as build-env

WORKDIR /work
COPY . .
ARG GOPROXY

# Build the executable binary (CGO_ENABLED=0 means static linking)
# Pass in GOCACHE (build cache) and GOMODCACHE (module cache) so they
# can be re-used between image builds.
RUN \
  --mount=type=cache,target=/cache/gocache \
  --mount=type=cache,target=/cache/gomodcache \
  mkdir out && \
  GOCACHE=/cache/gocache \
  GOMODCACHE=/cache/gomodcache \
  CGO_ENABLED=0 \
  GOOS=linux \
  GOARCH=amd64 \
  go build -v -ldflags "$(hack/get-ldflags.sh)" -o out \
    ./cmd/pinniped-concierge/... \
    ./cmd/pinniped-supervisor/... \
    ./cmd/local-user-authenticator/...

# Use a Debian slim image to grab a reasonable default CA bundle.
FROM debian:10.8-slim AS get-ca-bundle-env
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* /var/cache/debconf/*

# Use a runtime image based on Debian slim.
FROM debian:10.8-slim
COPY --from=get-ca-bundle-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Copy the binaries from the build-env stage.
COPY --from=build-env /work/out/ /usr/local/bin/

# Document the ports
EXPOSE 8080 8443

# Run as non-root for security posture
USER 1001:1001

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-concierge"]
