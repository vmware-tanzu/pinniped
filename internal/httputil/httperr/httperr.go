// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package httperr contains some helpers for nicer error handling in http.Handler implementations.
package httperr

import (
	"fmt"
	"net/http"
)

// Responder represents an error that can emit a useful HTTP error response to an http.ResponseWriter.
type Responder interface {
	error
	Respond(http.ResponseWriter)
}

// New returns a Responder that emits the given HTTP status code and message.
func New(code int, msg string) error {
	return httpErr{code: code, msg: msg}
}

// Newf returns a Responder that emits the given HTTP status code and fmt.Sprintf formatted message.
func Newf(code int, format string, args ...interface{}) error {
	return httpErr{code: code, msg: fmt.Sprintf(format, args...)}
}

// Wrap returns a Responder that emits the given HTTP status code and message, and also wraps an internal error.
func Wrap(code int, msg string, cause error) error {
	return httpErr{code: code, msg: msg, cause: cause}
}

type httpErr struct {
	code  int
	msg   string
	cause error
}

func (e httpErr) Error() string {
	if e.cause != nil {
		return fmt.Sprintf("%s: %v", e.msg, e.cause)
	}
	return e.msg
}

func (e httpErr) Respond(w http.ResponseWriter) {
	// http.Error is important here because it prevents content sniffing by forcing text/plain.
	http.Error(w, http.StatusText(e.code)+": "+e.msg, e.code)
}

func (e httpErr) Unwrap() error {
	return e.cause
}

// HandlerFunc is like http.HandlerFunc, but with a function signature that allows easier error handling.
type HandlerFunc func(http.ResponseWriter, *http.Request) error

func (f HandlerFunc) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch err := f(w, r).(type) {
	case nil:
		return
	case Responder:
		err.Respond(w)
	default:
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}
