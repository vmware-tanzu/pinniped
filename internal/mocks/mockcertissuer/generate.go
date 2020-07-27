/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package mockcertissuer

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mockcertissuer.go -package=mockcertissuer -copyright_file=../../../hack/header.txt github.com/suzerain-io/placeholder-name/pkg/registry/loginrequest CertIssuer
