// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phttp

import (
	"net/http"
	"net/url"

	"k8s.io/client-go/transport"

	"go.pinniped.dev/internal/httputil/roundtripper"
)

func safeDebugWrappers(rt http.RoundTripper, f transport.WrapperFunc, shouldLog func() bool) http.RoundTripper {
	return roundtripper.WrapFunc(rt, func(req *http.Request) (*http.Response, error) {
		// minor optimization to avoid the cleaning logic when the debug wrappers are unused
		// note: do not make this entire wrapper conditional on shouldLog() - the output is allowed to change at runtime
		if !shouldLog() {
			return rt.RoundTrip(req)
		}

		var (
			resp *http.Response
			err  error
		)
		debugRT := f(roundtripper.Func(func(_ *http.Request) (*http.Response, error) {
			// this call needs to be inside this closure so that the debug wrappers can time it
			// note also that it takes the original (real) request
			resp, err = rt.RoundTrip(req)

			cleanedResp := cleanResp(resp) // do not leak the user's password during the password grant

			return cleanedResp, err
		}))

		// run the debug wrappers for their side effects (i.e. logging)
		// the output is ignored because the input is not the real request
		cleanedReq := cleanReq(req) // do not leak the user's password during the password grant
		_, _ = debugRT.RoundTrip(cleanedReq)

		return resp, err
	})
}

func cleanReq(req *http.Request) *http.Request {
	// only pass back things we know to be safe to log
	return &http.Request{
		Method: req.Method,
		URL:    cleanURL(req.URL),
		Header: cleanHeader(req.Header),
	}
}

func cleanResp(resp *http.Response) *http.Response {
	if resp == nil {
		return nil
	}

	// only pass back things we know to be safe to log
	return &http.Response{
		Status: resp.Status,
		Header: cleanHeader(resp.Header),
	}
}

func cleanURL(u *url.URL) *url.URL {
	var user *url.Userinfo
	if len(u.User.Username()) > 0 {
		user = url.User("masked_username")
	}

	var opaque string
	if len(u.Opaque) > 0 {
		opaque = "masked_opaque_data"
	}

	var fragment string
	if len(u.Fragment) > 0 || len(u.RawFragment) > 0 {
		fragment = "masked_fragment"
	}

	// only pass back things we know to be safe to log
	return &url.URL{
		Scheme:     u.Scheme,
		Opaque:     opaque,
		User:       user,
		Host:       u.Host,
		Path:       u.Path,
		RawPath:    u.RawPath,
		ForceQuery: u.ForceQuery,
		RawQuery:   cleanQuery(u.Query()),
		Fragment:   fragment,
	}
}

func cleanQuery(query url.Values) string {
	if len(query) == 0 {
		return ""
	}

	out := url.Values(cleanHeader(http.Header(query))) // cast so we can re-use logic
	return out.Encode()
}

func cleanHeader(header http.Header) http.Header {
	if len(header) == 0 {
		return nil
	}

	mask := []string{"masked_value"}
	out := make(http.Header, len(header))
	for key := range header {
		out[key] = mask // only copy the keys
	}

	return out
}
