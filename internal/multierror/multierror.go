// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package multierror provides a type that can translate multiple errors into a Go error interface.
//
// A common use of this package is as follows.
//   errs := multierror.New()
//   for i := range stuff {
//     err := doThing(i)
//     errs.Add(err)
//   }
//   return errs.ErrOrNil()
package multierror

import (
	"fmt"
	"strings"
)

// MultiError holds a list of error's, that could potentially be empty.
//
// Use New() to create a MultiError.
type MultiError []error

// New returns an empty MultiError.
func New() MultiError {
	return make([]error, 0)
}

// Add adds an error to the MultiError. The provided err must not be nil.
func (m *MultiError) Add(err error) {
	*m = append(*m, err)
}

// Error implements the error.Error() interface method.
func (m MultiError) Error() string {
	sb := strings.Builder{}
	_, _ = fmt.Fprintf(&sb, "%d error(s):", len(m))
	for _, err := range m {
		_, _ = fmt.Fprintf(&sb, "\n- %s", err.Error())
	}
	return sb.String()
}

// ErrOrNil returns either nil, if there are no errors in this MultiError, or an error, otherwise.
func (m MultiError) ErrOrNil() error {
	if len(m) > 0 {
		return m
	}
	return nil
}
