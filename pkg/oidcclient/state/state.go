// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package state

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

// Generate generates a new random state parameter of an appropriate size.
func Generate() (State, error) { return generate(rand.Reader) }

func generate(rand io.Reader) (State, error) {
	// From https://tools.ietf.org/html/rfc6749#section-10.12:
	//   The binding value used for CSRF
	//   protection MUST contain a non-guessable value (as described in
	//   Section 10.10), and the user-agent's authenticated state (e.g.,
	//   session cookie, HTML5 local storage) MUST be kept in a location
	//   accessible only to the client and the user-agent (i.e., protected by
	//   same-origin policy).
	var buf [16]byte
	if _, err := io.ReadFull(rand, buf[:]); err != nil {
		return "", fmt.Errorf("could not generate random state: %w", err)
	}
	return State(hex.EncodeToString(buf[:])), nil
}

// State implements some utilities for working with OAuth2 state parameters.
type State string

// String returns the string encoding of this state value.
func (s *State) String() string {
	return string(*s)
}

// Validate the returned state (from a callback parameter).
func (s *State) Validate(returnedState string) error {
	if subtle.ConstantTimeCompare([]byte(returnedState), []byte(*s)) != 1 {
		return InvalidStateError{Expected: *s, Got: State(returnedState)}
	}
	return nil
}

// InvalidStateError is returned by Validate when the returned state is invalid.
type InvalidStateError struct {
	Expected State
	Got      State
}

func (e InvalidStateError) Error() string {
	return fmt.Sprintf("invalid state (expected %q, got %q)", e.Expected.String(), e.Got.String())
}
