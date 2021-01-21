// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockkeyset

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mockkeyset.go -package=mockkeyset -copyright_file=../../../hack/header.txt github.com/coreos/go-oidc/v3/oidc KeySet
