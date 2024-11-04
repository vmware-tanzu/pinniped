// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockresponsewriter

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockresponsewriter.go -package=mockresponsewriter -copyright_file=../../../hack/header.txt net/http ResponseWriter
