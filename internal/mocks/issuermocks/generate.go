// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package issuermocks

//go:generate go run -v go.uber.org/mock/mockgen  -destination=issuermocks.go -package=issuermocks -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/clientcertissuer ClientCertIssuer
