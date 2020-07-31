#!/bin/bash
set -e

go test -race ./...
( cd pkg/client && go test -race ./... )
