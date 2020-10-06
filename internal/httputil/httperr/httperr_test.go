// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package httperr

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHTTPErrs(t *testing.T) {
	t.Run("new", func(t *testing.T) {
		err := New(http.StatusBadRequest, "bad request error")
		require.EqualError(t, err, "bad request error")
	})

	t.Run("newf", func(t *testing.T) {
		err := Newf(http.StatusMethodNotAllowed, "expected method %s", "POST")
		require.EqualError(t, err, "expected method POST")
	})

	t.Run("wrap", func(t *testing.T) {
		wrappedErr := fmt.Errorf("some internal error")
		err := Wrap(http.StatusInternalServerError, "unexpected error", wrappedErr)
		require.EqualError(t, err, "unexpected error: some internal error")
		require.True(t, errors.Is(err, wrappedErr), "expected error to be wrapped")
	})

	t.Run("respond", func(t *testing.T) {
		err := Wrap(http.StatusForbidden, "boring public bits", fmt.Errorf("some secret internal bits"))
		require.Implements(t, (*Responder)(nil), err)
		rec := httptest.NewRecorder()
		err.(Responder).Respond(rec)
		require.Equal(t, http.StatusForbidden, rec.Code)
		require.Equal(t, "Forbidden: boring public bits\n", rec.Body.String())
		require.Equal(t, http.Header{
			"Content-Type":           []string{"text/plain; charset=utf-8"},
			"X-Content-Type-Options": []string{"nosniff"},
		}, rec.Header())
	})
}

func TestHandlerFunc(t *testing.T) {
	t.Run("success", func(t *testing.T) {

	})
}
