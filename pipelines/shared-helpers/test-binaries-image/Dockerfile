# syntax = docker/dockerfile:experimental

# Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Using bullseye (debian 11) until google/cloud-sdk starts using bookworm (debian 12) because the
# test binaries built by this dockerfile are run in a container built by dockerfiles/integration-test-runner/Dockerfile
# which uses google/cloud-sdk as the base image. Mismatching debian versions causes the pinniped-integration-test
# built below to error upon execution complaining that the expected version of GLIBC is not found.
FROM golang:1.24.3-bullseye as build-env
WORKDIR /work
COPY . .
ARG GOPROXY
RUN \
  --mount=type=cache,target=/cache/gocache \
  --mount=type=cache,target=/cache/gomodcache \
  mkdir out && \
  export GOCACHE=/cache/gocache && \
  export GOMODCACHE=/cache/gomodcache && \
  export GOOS=linux && \
  export GOARCH=amd64 && \
  CGO_ENABLED=0 go build -v -ldflags "$(hack/get-ldflags.sh)" -o out/pinniped ./cmd/pinniped/main.go && \
  CGO_ENABLED=1 go test -c -vet=off -race ./test/integration -o out/pinniped-integration-test  # need cgo for race detector

FROM scratch
COPY --from=build-env /work/out/ /usr/local/bin/
