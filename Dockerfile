FROM golang:1.14-alpine as build-env
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
# Build the executable binary
RUN GOOS=linux GOARCH=amd64 go build -o out ./...

FROM alpine:latest
# Install CA certs and some tools for debugging
RUN apk --update --no-cache add ca-certificates bash curl
WORKDIR /root/
# Copy the binary from the build-env stage
COPY --from=build-env /work/out/placeholder-name app
# Document the port
EXPOSE 443
# Set the command
CMD ["./app"]
