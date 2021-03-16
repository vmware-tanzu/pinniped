// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package roundtripper

import "net/http"

var _ http.RoundTripper = Func(nil)

type Func func(*http.Request) (*http.Response, error)

func (f Func) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
