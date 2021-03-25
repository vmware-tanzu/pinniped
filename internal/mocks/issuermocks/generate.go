// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuermocks

//go:generate go run -v github.com/golang/mock/mockgen  -destination=issuermocks.go -package=issuermocks -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/issuer ClientCertIssuer
