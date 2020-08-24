# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.15.0 as build-env

# It is important that these ARG's are defined after the FROM statement
ARG ACCESS_TOKEN_USR="nothing"
ARG ACCESS_TOKEN_PWD="nothing"

# Create a netrc file using the credentials specified using --build-arg
RUN printf "machine github.com\n\
    login ${ACCESS_TOKEN_USR}\n\
    password ${ACCESS_TOKEN_PWD}\n\
    \n\
    machine api.github.com\n\
    login ${ACCESS_TOKEN_USR}\n\
    password ${ACCESS_TOKEN_PWD}\n"\
    >> /root/.netrc && chmod 600 /root/.netrc && mkdir /work && mkdir /work/out
WORKDIR /work
# Get dependencies first so they can be cached as a layer
COPY go.* ./
COPY pkg/client/go.* ./pkg/client/
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
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(hack/get-ldflags.sh)" -o out ./cmd/pinniped-server/...


# Use a runtime image based on Debian slim
FROM debian:10.5-slim

# Copy the binary from the build-env stage
COPY --from=build-env /work/out/pinniped-server /usr/local/bin/pinniped-server

# Document the port
EXPOSE 443

# Set the entrypoint
ENTRYPOINT ["/usr/local/bin/pinniped-server"]
