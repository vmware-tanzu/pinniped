# syntax = docker/dockerfile:1.0-experimental

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.17.3 as build-env

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
  go build -v -trimpath -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-concierge-kube-cert-agent ./cmd/pinniped-concierge-kube-cert-agent/... && \
  go build -v -trimpath -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-server ./cmd/pinniped-server/... && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-concierge && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-supervisor && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/local-user-authenticator

# Use a distroless runtime image with CA certificates, timezone data, and not much else.
FROM gcr.io/distroless/static:nonroot@sha256:bca3c203cdb36f5914ab8568e4c25165643ea9b711b41a8a58b42c80a51ed609

# Copy the server binary from the build-env stage.
COPY --from=build-env /usr/local/bin /usr/local/bin

# Document the ports
EXPOSE 8080 8443

# Run as non-root for security posture
# Use the same non-root user as https://github.com/GoogleContainerTools/distroless/blob/fc3c4eaceb0518900f886aae90407c43be0a42d9/base/base.bzl#L9
# This is a workaround for https://github.com/GoogleContainerTools/distroless/issues/718
USER 65532:65532

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
