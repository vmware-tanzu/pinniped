# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.15.1 as build-env

WORKDIR /work
# Get dependencies first so they can be cached as a layer
COPY go.* ./
COPY generated/1.19/apis/go.* ./generated/1.19/apis/
COPY generated/1.19/client/go.* ./generated/1.19/client/
RUN go mod download

# Copy only the production source code to avoid cache misses when editing other files
COPY generated ./generated
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY tools ./tools
COPY hack ./hack

# Build the executable binary (CGO_ENABLED=0 means static linking)
RUN mkdir out \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(hack/get-ldflags.sh)" -o out ./cmd/pinniped-server/... \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o out ./cmd/test-webhook/...

# Use a runtime image based on Debian slim
FROM debian:10.5-slim

# Copy the binaries from the build-env stage
COPY --from=build-env /work/out/pinniped-server /usr/local/bin/pinniped-server
COPY --from=build-env /work/out/test-webhook /usr/local/bin/test-webhook

# Document the port
EXPOSE 443

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
