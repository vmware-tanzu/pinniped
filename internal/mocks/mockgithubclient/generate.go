// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mockgithubclient

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockgithubclient.go -package=mockgithubclient -copyright_file=../../../hack/header.txt go.pinniped.dev/internal/githubclient GitHubInterface
