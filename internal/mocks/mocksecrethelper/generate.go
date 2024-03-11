// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mocksecrethelper

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mocksecrethelper.go -package=mocksecrethelper -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/controller/supervisorconfig/generator SecretHelper
