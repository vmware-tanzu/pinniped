// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phttp

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/httputil/roundtripper"
)

func Test_safeDebugWrappers_shouldLog(t *testing.T) {
	t.Parallel()

	var rtFuncCalled, wrapFuncCalled, innerRTCalled int
	var shouldLog, skipInnerRT bool

	shouldLogFunc := func() bool { return shouldLog }

	rtFunc := roundtripper.Func(func(_ *http.Request) (*http.Response, error) {
		rtFuncCalled++
		return nil, nil
	})

	wrapFunc := func(rt http.RoundTripper) http.RoundTripper {
		wrapFuncCalled++
		return roundtripper.Func(func(r *http.Request) (*http.Response, error) {
			innerRTCalled++
			if skipInnerRT {
				return nil, nil
			}
			return rt.RoundTrip(r)
		})
	}

	r := testReq(t, nil, nil)

	out := safeDebugWrappers(rtFunc, wrapFunc, shouldLogFunc)

	// assert that shouldLogFunc is dynamically honored

	_, _ = out.RoundTrip(r) //nolint:bodyclose

	require.Equal(t, 1, rtFuncCalled)
	require.Equal(t, 0, wrapFuncCalled)
	require.Equal(t, 0, innerRTCalled)

	shouldLog = true

	_, _ = out.RoundTrip(r) //nolint:bodyclose

	require.Equal(t, 2, rtFuncCalled)
	require.Equal(t, 1, wrapFuncCalled)
	require.Equal(t, 1, innerRTCalled)

	shouldLog = false

	_, _ = out.RoundTrip(r) //nolint:bodyclose

	require.Equal(t, 3, rtFuncCalled)
	require.Equal(t, 1, wrapFuncCalled)
	require.Equal(t, 1, innerRTCalled)

	shouldLog = true

	_, _ = out.RoundTrip(r) //nolint:bodyclose

	require.Equal(t, 4, rtFuncCalled)
	require.Equal(t, 2, wrapFuncCalled)
	require.Equal(t, 2, innerRTCalled)

	// assert that wrapFunc controls rtFunc being called

	skipInnerRT = true

	_, _ = out.RoundTrip(r) //nolint:bodyclose

	require.Equal(t, 4, rtFuncCalled)
	require.Equal(t, 3, wrapFuncCalled)
	require.Equal(t, 3, innerRTCalled)

	skipInnerRT = false

	_, _ = out.RoundTrip(r) //nolint:bodyclose

	require.Equal(t, 5, rtFuncCalled)
	require.Equal(t, 4, wrapFuncCalled)
	require.Equal(t, 4, innerRTCalled)
}

func Test_safeDebugWrappers_clean(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		shouldLog        bool
		inReq, wantReq   *http.Request
		inResp, wantResp *http.Response
		inErr            error
	}{
		{
			name:      "header cleaned",
			shouldLog: true,
			inReq:     testReq(t, http.Header{"hello": {"from", "earth"}}, nil),
			wantReq:   testCleanReq(http.Header{"hello": {"masked_value"}}, nil),
			inResp:    testResp(t, http.Header{"bye": {"for", "now"}}),     //nolint:bodyclose
			wantResp:  testCleanResp(http.Header{"bye": {"masked_value"}}), //nolint:bodyclose
			inErr:     nil,
		},
		{
			name:      "header cleaned error",
			shouldLog: true,
			inReq:     testReq(t, http.Header{"see": {"from", "mars"}}, nil),
			wantReq:   testCleanReq(http.Header{"see": {"masked_value"}}, nil),
			inResp:    testResp(t, http.Header{"bear": {"is", "a"}}),        //nolint:bodyclose
			wantResp:  testCleanResp(http.Header{"bear": {"masked_value"}}), //nolint:bodyclose
			inErr:     constable.Error("some error"),
		},
		{
			name:      "header cleaned error nil resp",
			shouldLog: true,
			inReq:     testReq(t, http.Header{"see": {"from", "mars"}}, nil),
			wantReq:   testCleanReq(http.Header{"see": {"masked_value"}}, nil),
			inResp:    nil,
			wantResp:  nil,
			inErr:     constable.Error("some other error"),
		},
		{
			name:      "header cleaned no log",
			shouldLog: false,
			inReq:     testReq(t, http.Header{"sky": {"is", "blue"}}, nil),
			wantReq:   nil,
			inResp:    testResp(t, http.Header{"night": {"is", "dark"}}), //nolint:bodyclose
			wantResp:  nil,
			inErr:     nil,
		},
		{
			name:      "url cleaned, all fields",
			shouldLog: true,
			inReq: testReq(t, nil, &url.URL{
				Scheme:      "sc",
				Opaque:      "op",
				User:        url.UserPassword("us", "pa"),
				Host:        "ho",
				Path:        "pa",
				RawPath:     "rap",
				ForceQuery:  true,
				RawQuery:    "key1=val1&key2=val2",
				Fragment:    "fra",
				RawFragment: "rawf",
			}),
			wantReq: testCleanReq(nil, &url.URL{
				Scheme:      "sc",
				Opaque:      "masked_opaque_data",
				User:        url.User("masked_username"),
				Host:        "ho",
				Path:        "pa",
				RawPath:     "rap",
				ForceQuery:  true,
				RawQuery:    "key1=masked_value&key2=masked_value",
				Fragment:    "masked_fragment",
				RawFragment: "",
			}),
			inResp:   testResp(t, http.Header{"sun": {"yellow"}}),         //nolint:bodyclose
			wantResp: testCleanResp(http.Header{"sun": {"masked_value"}}), //nolint:bodyclose
			inErr:    nil,
		},
		{
			name:      "url cleaned, some fields",
			shouldLog: true,
			inReq: testReq(t, nil, &url.URL{
				Scheme:      "sc",
				Opaque:      "",
				User:        nil,
				Host:        "ho",
				Path:        "pa",
				RawPath:     "rap",
				ForceQuery:  false,
				RawQuery:    "key3=val3&key4=val4",
				Fragment:    "",
				RawFragment: "",
			}),
			wantReq: testCleanReq(nil, &url.URL{
				Scheme:      "sc",
				Opaque:      "",
				User:        nil,
				Host:        "ho",
				Path:        "pa",
				RawPath:     "rap",
				ForceQuery:  false,
				RawQuery:    "key3=masked_value&key4=masked_value",
				Fragment:    "",
				RawFragment: "",
			}),
			inResp:   testResp(t, http.Header{"sun": {"yellow"}}),         //nolint:bodyclose
			wantResp: testCleanResp(http.Header{"sun": {"masked_value"}}), //nolint:bodyclose
			inErr:    nil,
		},
		{
			name:      "header and url cleaned, all fields with error",
			shouldLog: true,
			inReq: testReq(t, http.Header{"zone": {"of", "the", "enders"}, "welcome": {"home"}}, &url.URL{
				Scheme:      "sc2",
				Opaque:      "op2",
				User:        url.UserPassword("us2", "pa2"),
				Host:        "ho2",
				Path:        "pa2",
				RawPath:     "rap2",
				ForceQuery:  true,
				RawQuery:    "a=b&c=d&e=f&a=1&a=2",
				Fragment:    "fra2",
				RawFragment: "rawf2",
			}),
			wantReq: testCleanReq(http.Header{"zone": {"masked_value"}, "welcome": {"masked_value"}}, &url.URL{
				Scheme:      "sc2",
				Opaque:      "masked_opaque_data",
				User:        url.User("masked_username"),
				Host:        "ho2",
				Path:        "pa2",
				RawPath:     "rap2",
				ForceQuery:  true,
				RawQuery:    "a=masked_value&c=masked_value&e=masked_value",
				Fragment:    "masked_fragment",
				RawFragment: "",
			}),
			inResp:   testResp(t, http.Header{"moon": {"white"}}),          //nolint:bodyclose
			wantResp: testCleanResp(http.Header{"moon": {"masked_value"}}), //nolint:bodyclose
			inErr:    constable.Error("yay pandas"),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rtCalled, wrapCalled, innerCalled bool

			rtFunc := roundtripper.Func(func(r *http.Request) (*http.Response, error) {
				rtCalled = true
				require.Equal(t, tt.inReq, r)
				return tt.inResp, tt.inErr
			})

			var gotReq *http.Request
			var gotResp *http.Response
			var gotErr error

			wrapFunc := func(rt http.RoundTripper) http.RoundTripper {
				wrapCalled = true
				return roundtripper.Func(func(r *http.Request) (*http.Response, error) {
					innerCalled = true

					gotReq = r

					resp, err := rt.RoundTrip(r) //nolint:bodyclose

					gotResp = resp
					gotErr = err

					return resp, err
				})
			}

			out := safeDebugWrappers(rtFunc, wrapFunc, func() bool { return tt.shouldLog })

			resp, err := out.RoundTrip(tt.inReq) //nolint:bodyclose

			require.Equal(t, tt.inResp, resp)
			require.Equal(t, tt.inErr, err)
			require.True(t, rtCalled)
			require.Equal(t, tt.shouldLog, wrapCalled)
			require.Equal(t, tt.shouldLog, innerCalled)

			require.Equal(t, tt.wantReq, gotReq)
			require.Equal(t, tt.wantResp, gotResp)
			require.Equal(t, tt.inErr, gotErr)
		})
	}
}

func testReq(t *testing.T, header http.Header, u *url.URL) *http.Request {
	t.Helper()

	r, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://overwritten.com", nil)
	require.NoError(t, err)

	if u == nil {
		u = &url.URL{}
	}

	r.URL = u
	r.Header = header

	// something non-nil for testing
	r.Body = io.NopCloser(&bytes.Buffer{})
	r.Form = url.Values{"a": {"b"}}
	r.PostForm = url.Values{"c": {"d"}}

	return r
}

func testResp(t *testing.T, header http.Header) *http.Response {
	t.Helper()

	return &http.Response{
		Status: "pandas are the best",
		Header: header,

		// something non-nil for testing
		Body:    io.NopCloser(&bytes.Buffer{}),
		Request: testReq(t, header, nil),
	}
}

func testCleanReq(header http.Header, u *url.URL) *http.Request {
	if u == nil {
		u = &url.URL{}
	}

	return &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: header,
	}
}

func testCleanResp(header http.Header) *http.Response {
	return &http.Response{
		Status: "pandas are the best",
		Header: header,
	}
}
