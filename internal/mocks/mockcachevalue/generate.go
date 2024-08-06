// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockcachevalue

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockcachevalue.go -package=mockcachevalue -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/controller/authenticator/authncache Value
