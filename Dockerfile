# syntax = docker/dockerfile:1.0-experimental

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.16.7 as build-env

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
  export GOCACHE=/cache/gocache GOMODCACHE=/cache/gomodcache CGO_ENABLED=0 GOOS=linux GOARCH=amd64 && \
  go build -v -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-concierge-kube-cert-agent ./cmd/pinniped-concierge-kube-cert-agent/main.go && \
  go build -v -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-server ./cmd/pinniped-server/main.go && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-concierge && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-supervisor && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/local-user-authenticator

# Use a distroless runtime image with CA certificates, timezone data, and not much else.
FROM gcr.io/distroless/static:nonroot@sha256:c9f9b040044cc23e1088772814532d90adadfa1b86dcba17d07cb567db18dc4e

# Copy the server binary from the build-env stage.
COPY --from=build-env /usr/local/bin /usr/local/bin

# Document the ports
EXPOSE 8080 8443

# Run as non-root for security posture
USER 1001:1001

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
