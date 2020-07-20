FROM golang:1.14-alpine as build-env

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
COPY go.mod .
COPY go.sum .
RUN go mod download
# Copy only the production source code to avoid cache misses when editing other files
COPY cmd ./cmd
COPY internal ./internal
COPY pkg ./pkg
COPY tools ./tools
COPY hack ./hack
# Build the executable binary
RUN GOOS=linux GOARCH=amd64 go build -ldflags "$(hack/get-ldflags.sh)" -o out ./...

FROM alpine:latest
# Install CA certs and some tools for debugging
RUN apk --update --no-cache add ca-certificates bash curl
WORKDIR /root/
# Copy the binary from the build-env stage
COPY --from=build-env /work/out/placeholder-name placeholder-name
# Document the port
EXPOSE 443
# Set the command
CMD ["./placeholder-name"]
