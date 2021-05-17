// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package upstreamwatchers

import "go.pinniped.dev/internal/constable"

const (
	ReasonNotFound         = "SecretNotFound"
	ReasonWrongType        = "SecretWrongType"
	ReasonMissingKeys      = "SecretMissingKeys"
	ReasonSuccess          = "Success"
	ReasonInvalidTLSConfig = "InvalidTLSConfig"

	ErrNoCertificates = constable.Error("no certificates found")
)
