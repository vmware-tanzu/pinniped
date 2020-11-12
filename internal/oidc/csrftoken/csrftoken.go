// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package csrftoken

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
)

// Generate generates a new random CSRF token value.
func Generate() (CSRFToken, error) { return generate(rand.Reader) }

func generate(rand io.Reader) (CSRFToken, error) {
	var buf [32]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate CSRFToken: %w", err)
	}
	return CSRFToken(hex.EncodeToString(buf[:])), nil
}

type CSRFToken string
