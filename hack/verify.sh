#!/bin/bash
set -e

go run github.com/golangci/golangci-lint/cmd/golangci-lint run ./... --modules-download-mode=readonly
