#!/usr/bin/env bash

set -euo pipefail

go run github.com/golangci/golangci-lint/cmd/golangci-lint run ./... --modules-download-mode=readonly --timeout=10m
