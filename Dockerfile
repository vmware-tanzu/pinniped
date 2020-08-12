# Copyright 2020 VMware, Inc.
# SPDX-License-Identifier: Apache-2.0

FROM golang:1.15.0-alpine as build-env

# It is important that these ARG's are defined after the FROM statement
ARG ACCESS_TOKEN_USR="nothing"
ARG ACCESS_TOKEN_PWD="nothing"

# git is required to fetch go dependencies
RUN apk add --no-cache ca-certificates git bash

# Create a netrc file using the credentials specified using --build-arg
RUN printf "machine github.com\n\
    login ${ACCESS_TOKEN_USR}\n\
    password ${ACCESS_TOKEN_PWD}\n\
    \n\
    machine api.github.com\n\
    login ${ACCESS_TOKEN_USR}\n\
    password ${ACCESS_TOKEN_PWD}\n"\
    >> /root/.netrc
RUN chmod 600 /root/.netrc

RUN mkdir /work
RUN mkdir /work/out
WORKDIR /work
# Get dependencies first so they can be cached as a layer
COPY go.mod go.sum ./
COPY pkg/client/go.mod pkg/client/go.sum ./pkg/client/
COPY kubernetes/1.19/api/go.mod kubernetes/1.19/api/go.sum ./kubernetes/1.19/api/
COPY kubernetes/1.19/client-go/go.mod kubernetes/1.19/client-go/go.sum ./kubernetes/1.19/client-go/

RUN go mod download
# Copy only the production source code to avoid cache misses when editing other files
COPY kubernetes ./kubernetes
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY tools ./tools
COPY hack ./hack
# Build the executable binary (CGO_ENABLED=0 means static linking)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(hack/get-ldflags.sh)" -o out ./cmd/placeholder-name-server/...

FROM alpine:latest
# Install CA certs and some tools for debugging
RUN apk --update --no-cache add ca-certificates bash curl
WORKDIR /root/
# Copy the binary from the build-env stage
COPY --from=build-env /work/out/placeholder-name-server placeholder-name-server
# Document the port
EXPOSE 443
# Set the command
CMD ["./placeholder-name-server"]
