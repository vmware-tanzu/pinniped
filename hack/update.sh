#!/bin/bash
set -e

go mod tidy
go run github.com/golangci/golangci-lint/cmd/golangci-lint run ./... --fix
