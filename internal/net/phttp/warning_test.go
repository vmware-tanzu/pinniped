// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package phttp

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/httputil/roundtripper"
)

func Test_warningWrapper(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		resp       *http.Response
		wantCodes  []int
		wantAgents []string
		wantTexts  []string
	}{
		{
			name:       "nil resp",
			resp:       nil,
			wantCodes:  nil,
			wantAgents: nil,
			wantTexts:  nil,
		},
		{
			name:       "no warning",
			resp:       testResp(t, http.Header{"moon": {"white"}}), //nolint:bodyclose
			wantCodes:  nil,
			wantAgents: nil,
			wantTexts:  nil,
		},
		{
			name:       "malformed warning",
			resp:       testResp(t, http.Header{"Warning": {"wee"}}), //nolint:bodyclose
			wantCodes:  nil,
			wantAgents: nil,
			wantTexts:  nil,
		},
		{
			name:       "partial malformed warning",
			resp:       testResp(t, http.Header{"Warning": {`123 foo "bar"`, "wee"}}), //nolint:bodyclose
			wantCodes:  []int{123},
			wantAgents: []string{"foo"},
			wantTexts:  []string{"bar"},
		},
		{
			name:       "partial malformed warning other order",
			resp:       testResp(t, http.Header{"Warning": {"bar", `852 nah "dude"`, "wee"}}), //nolint:bodyclose
			wantCodes:  []int{852},
			wantAgents: []string{"nah"},
			wantTexts:  []string{"dude"},
		},
		{
			name:       "multiple warnings",
			resp:       testResp(t, http.Header{"Warning": {`123 foo "bar"`, `222 good "day"`}}), //nolint:bodyclose
			wantCodes:  []int{123, 222},
			wantAgents: []string{"foo", "good"},
			wantTexts:  []string{"bar", "day"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var rtCalled bool

			staticErr := constable.Error("yay pandas")

			rtFunc := roundtripper.Func(func(r *http.Request) (*http.Response, error) {
				rtCalled = true
				require.Nil(t, r)
				return tt.resp, staticErr
			})

			h := &testWarningHandler{}
			out := warningWrapper(rtFunc, h)

			resp, err := out.RoundTrip(nil) //nolint:bodyclose

			require.Equal(t, tt.resp, resp)
			require.Equal(t, staticErr, err)
			require.True(t, rtCalled)

			require.Equal(t, tt.wantCodes, h.codes)
			require.Equal(t, tt.wantAgents, h.agents)
			require.Equal(t, tt.wantTexts, h.texts)
		})
	}
}

type testWarningHandler struct {
	codes  []int
	agents []string
	texts  []string
}

func (h *testWarningHandler) HandleWarningHeader(code int, agent, text string) {
	h.codes = append(h.codes, code)
	h.agents = append(h.agents, agent)
	h.texts = append(h.texts, text)
}
