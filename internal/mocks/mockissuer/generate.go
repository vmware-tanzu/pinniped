// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockissuer

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockissuer.go -package=mockissuer -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/clientcertissuer ClientCertIssuer
