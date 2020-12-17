# Copyright 2020 the Pinniped contributors. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.15.6 as build-env

WORKDIR /work
# Get dependencies first so they can be cached as a layer
COPY go.* ./
COPY generated/1.19/apis/go.* ./generated/1.19/apis/
COPY generated/1.19/client/go.* ./generated/1.19/client/
RUN go mod download

# Copy only the production source code to avoid cache misses when editing other files
COPY generated ./generated
COPY cmd ./cmd
COPY pkg ./pkg
COPY internal ./internal
COPY hack ./hack

# Build the executable binary (CGO_ENABLED=0 means static linking)
RUN mkdir out \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(hack/get-ldflags.sh)" -o out ./cmd/pinniped-concierge/... \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(hack/get-ldflags.sh)" -o out ./cmd/pinniped-supervisor/... \
  && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o out ./cmd/local-user-authenticator/...

# Use a runtime image based on Debian slim
FROM debian:10.7-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binaries from the build-env stage
COPY --from=build-env /work/out/pinniped-concierge /usr/local/bin/pinniped-concierge
COPY --from=build-env /work/out/pinniped-supervisor /usr/local/bin/pinniped-supervisor
COPY --from=build-env /work/out/local-user-authenticator /usr/local/bin/local-user-authenticator

# Document the ports
EXPOSE 8080 8443

# Run as non-root for security posture
USER 1001:1001

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-concierge"]
