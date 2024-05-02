// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockoidcclientoptions

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockoidcclientoptions.go -package=mockoidcclientoptions -copyright_file=../../../hack/header.txt go.pinniped.dev/cmd/pinniped/cmd OIDCClientOptions
