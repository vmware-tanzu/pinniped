# syntax=docker/dockerfile:1

# Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

ARG BUILD_IMAGE=golang:1.24.0@sha256:a14c5a656f220b7067734beebef6362b0858a61d766ccaf320e0553329e1f34e
ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:6ec5aa99dc335666e79dc64e4a6c8b89c33a543a1967f20d360922a80dd21f02

# Prepare to cross-compile by always running the build stage in the build platform, not the target platform.
FROM --platform=$BUILDPLATFORM $BUILD_IMAGE AS build-env

WORKDIR /work

ARG GOPROXY

ARG KUBE_GIT_VERSION
ENV KUBE_GIT_VERSION=$KUBE_GIT_VERSION

# These will be set by buildkit automatically, e.g. TARGETOS set to "linux" and TARGETARCH set to "amd64" or "arm64".
# Useful for building multi-arch container images.
ARG TARGETOS
ARG TARGETARCH

# If provided, must be a comma-separated list of Go build tags.
ARG ADDITIONAL_BUILD_TAGS

# Build the statically linked (CGO_ENABLED=0) binary.
# Mount source, build cache, and module cache for performance reasons.
# See https://www.docker.com/blog/faster-multi-platform-builds-dockerfile-cross-compilation-guide/
RUN \
  --mount=target=. \
  --mount=type=cache,target=/cache/gocache \
  --mount=type=cache,target=/cache/gomodcache \
  export GOCACHE=/cache/gocache GOMODCACHE=/cache/gomodcache CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH && \
  go build -tags $ADDITIONAL_BUILD_TAGS -v -trimpath -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-concierge-kube-cert-agent ./cmd/pinniped-concierge-kube-cert-agent/... && \
  go build -tags $ADDITIONAL_BUILD_TAGS -v -trimpath -ldflags "$(hack/get-ldflags.sh) -w -s" -o /usr/local/bin/pinniped-server ./cmd/pinniped-server/... && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-concierge && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/pinniped-supervisor && \
  ln -s /usr/local/bin/pinniped-server /usr/local/bin/local-user-authenticator

# Use a distroless runtime image with CA certificates, timezone data, and not much else.
# Note that we are not using --platform here, so it will choose the base image for the target platform, not the build platform.
# By using "distroless/static" instead of "distroless/static-debianXX" we can float on the latest stable version of debian.
# See https://github.com/GoogleContainerTools/distroless#base-operating-system
FROM $BASE_IMAGE

# Copy the server binary from the build-env stage.
COPY --from=build-env /usr/local/bin /usr/local/bin

# Document the default server ports for the various server apps
EXPOSE 8443 8444 10250

# Run as non-root for security posture
# Use the same non-root user as https://github.com/GoogleContainerTools/distroless/blob/fc3c4eaceb0518900f886aae90407c43be0a42d9/base/base.bzl#L9
# This is a workaround for https://github.com/GoogleContainerTools/distroless/issues/718
USER 65532:65532

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
