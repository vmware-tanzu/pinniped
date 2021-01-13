// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockroundtripper

//go:generate go run -v github.com/golang/mock/mockgen  -destination=mockroundtripper.go -package=mockroundtripper -copyright_file=../../../hack/header.txt net/http RoundTripper
