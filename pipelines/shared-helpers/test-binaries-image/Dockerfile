# syntax = docker/dockerfile:experimental

# Copyright 2020-2026 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.27.3-bookworm as build-env
WORKDIR /work
COPY . .
ARG GOPROXY

# Set this if you would like to enable Go's built-in FIPS compliance module.
# E.g. GOFIPS140=certified or GOFIPS140=v1.0.0
# See https://go.dev/doc/security/fips140 for details.
ARG GOFIPS140=off

RUN \
  --mount=type=cache,target=/cache/gocache \
  --mount=type=cache,target=/cache/gomodcache \
  mkdir out && \
  export GOCACHE=/cache/gocache && \
  export GOMODCACHE=/cache/gomodcache && \
  export GOOS=linux && \
  export GOARCH=amd64 && \
  CGO_ENABLED=0 GOFIPS140=$GOFIPS140 go build -v -ldflags "$(hack/get-ldflags.sh)" -o out/pinniped ./cmd/pinniped/main.go && \
  CGO_ENABLED=1 GOFIPS140=$GOFIPS140 go test -c -vet=off -race ./test/integration -o out/pinniped-integration-test  # need cgo for race detector

FROM scratch
COPY --from=build-env /work/out/ /usr/local/bin/
