// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package stateparam

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorizeID(t *testing.T) {
	// $ echo -n "foo" | shasum -a 256
	// 2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
	require.Equal(t, "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		Encoded("foo").AuthorizeID())

	// $ echo -n "" | shasum -a 256
	// e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	require.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Encoded("").AuthorizeID())
}
