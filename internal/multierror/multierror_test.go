// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package multierror

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultierror(t *testing.T) {
	errs := New()

	require.Nil(t, errs.ErrOrNil())

	errs.Add(errors.New("some error 1"))
	require.EqualError(t, errs.ErrOrNil(), "1 error(s):\n- some error 1")

	errs.Add(errors.New("some error 2"))
	errs.Add(errors.New("some error 3"))
	require.EqualError(t, errs.ErrOrNil(), "3 error(s):\n- some error 1\n- some error 2\n- some error 3")
}
