// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockkeyset

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockkeyset.go -package=mockkeyset -copyright_file=../../../hack/header.txt github.com/coreos/go-oidc/v3/oidc KeySet
