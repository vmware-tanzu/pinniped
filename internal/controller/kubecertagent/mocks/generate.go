// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package mocks

//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockpodcommandexecutor.go -package=mocks -copyright_file=../../../../hack/header.txt go.pinniped.dev/internal/controller/kubecertagent PodCommandExecutor
//go:generate go run -v go.uber.org/mock/mockgen  -destination=mockdynamiccert.go -package=mocks -copyright_file=../../../../hack/header.txt -mock_names Private=MockDynamicCertPrivate go.pinniped.dev/internal/dynamiccert Private
