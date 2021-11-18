// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package roundtripper

import (
	"net/http"

	"k8s.io/apimachinery/pkg/util/net"
)

var _ http.RoundTripper = Func(nil)

type Func func(*http.Request) (*http.Response, error)

func (f Func) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

var _ net.RoundTripperWrapper = &wrapper{}

type wrapper struct {
	delegate http.RoundTripper
	f        Func
}

func (w *wrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	return w.f.RoundTrip(req)
}

func (w *wrapper) WrappedRoundTripper() http.RoundTripper {
	return w.delegate
}

func WrapFunc(delegate http.RoundTripper, f Func) net.RoundTripperWrapper {
	return &wrapper{delegate: delegate, f: f}
}
