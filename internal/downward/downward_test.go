// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package downward

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		inputDir string
		wantErr  string
		want     *PodInfo
	}{
		{
			name:     "missing directory",
			inputDir: "./testdata/no-such-directory",
			wantErr:  "could not load namespace: open testdata/no-such-directory/namespace: no such file or directory",
		},
		{
			name:     "missing labels file",
			inputDir: "./testdata/missinglabels",
			wantErr:  "could not load labels: open testdata/missinglabels/labels: no such file or directory",
		},
		{
			name:     "invalid labels file",
			inputDir: "./testdata/invalidlabels",
			wantErr:  "could not parse labels: expected 2 parts, found 1: short buffer",
		},
		{
			name:     "valid",
			inputDir: "./testdata/valid",
			want: &PodInfo{
				Namespace: "test-namespace",
				Name:      "test-name",
				Labels:    map[string]string{"foo": "bar", "bat": "baz"},
			},
		},
		{
			name:     "valid without name",
			inputDir: "./testdata/validwithoutname",
			want: &PodInfo{
				Namespace: "test-namespace",
				Labels:    map[string]string{"foo": "bar", "bat": "baz"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(tt.inputDir)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParseMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		wantErr string
		want    map[string]string
	}{
		{
			name: "empty",
			want: map[string]string{},
		},
		{
			name:    "missing equal",
			input:   []byte(`akjhlakjh`),
			wantErr: "expected 2 parts, found 1: short buffer",
		},
		{
			name:    "missing invalid value",
			input:   []byte(`akjhlakjh="foo\qbar"`),
			wantErr: "invalid quoted value: invalid syntax",
		},
		{
			name: "success",
			input: []byte(`
fooTime="2020-07-15T19:35:12.027636555Z"
example.com/config.source="api"
example.com/bar="baz\x01"
`),
			want: map[string]string{
				"fooTime":                   "2020-07-15T19:35:12.027636555Z",
				"example.com/config.source": "api",
				"example.com/bar":           "baz\x01",
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseMap(tt.input)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
