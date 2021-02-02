// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package csrftoken

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCSRFToken(t *testing.T) {
	tok, err := Generate()
	require.NoError(t, err)
	require.Len(t, tok, 64)

	var empty bytes.Buffer
	tok, err = generate(&empty)
	require.EqualError(t, err, "could not generate CSRFToken: EOF")
	require.Empty(t, tok)
}
