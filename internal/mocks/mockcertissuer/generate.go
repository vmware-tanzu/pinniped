// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockcertissuer

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mockcertissuer.go -package=mockcertissuer -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/registry/credentialrequest CertIssuer
