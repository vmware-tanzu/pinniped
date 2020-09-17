// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockcertissuer

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mockcertissuer.go -package=mockcertissuer -copyright_file=../../../hack/header.txt github.com/vmware-tanzu/pinniped/internal/registry/credentialrequest CertIssuer
