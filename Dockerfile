# syntax = docker/dockerfile:1.0-experimental

# Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM goboring/golang:1.16.7b7 as build-env

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
  export GOCACHE=/cache/gocache GOMODCACHE=/cache/gomodcache CGO_ENABLED=1 GOOS=linux GOARCH=amd64 && \
  go build -v -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-concierge-kube-cert-agent ./cmd/pinniped-concierge-kube-cert-agent/... && \
  go build -v -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-server ./cmd/pinniped-server/... && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-concierge && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-supervisor && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/local-user-authenticator

# Use a distroless runtime image with CA certificates, timezone data, and not much else.
FROM gcr.io/distroless/base:nonroot@sha256:56d73a61ea1135c28f2be9afe2be88fc360e5fa1a892d600512a10eb2e028fa5

# Copy the server binary from the build-env stage.
COPY --from=build-env /usr/local/bin /usr/local/bin

# Document the ports
EXPOSE 8080 8443

# Run as non-root for security posture
USER 1001:1001

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
