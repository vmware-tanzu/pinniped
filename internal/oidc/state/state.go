// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"io"

	"github.com/pkg/errors"
)

// Generate generates a new random state parameter of an appropriate size.
func Generate() (State, error) { return generate(rand.Reader) }

func generate(rand io.Reader) (State, error) {
	var buf [16]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", errors.WithMessage(err, "could not generate random state")
	}
	return State(hex.EncodeToString(buf[:])), nil
}

// State implements some utilities for working with OAuth2 state parameters.
type State string

// String returns the string encoding of this state value.
func (s *State) String() string {
	return string(*s)
}

// Validate the returned state (from a callback parameter). Returns true iff the state is valid.
func (s *State) Valid(returnedState string) bool {
	return subtle.ConstantTimeCompare([]byte(returnedState), []byte(*s)) == 1
}
