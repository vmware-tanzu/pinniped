// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/sets"
)

func TestSanitizeParams(t *testing.T) {
	tests := []struct {
		name        string
		params      url.Values
		allowedKeys sets.Set[string]
		want        string
	}{
		{
			name:        "nil values",
			params:      nil,
			allowedKeys: nil,
			want:        "",
		},
		{
			name:        "empty values",
			params:      url.Values{},
			allowedKeys: nil,
			want:        "",
		},
		{
			name:        "all allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: sets.New("foo", "bar"),
			want:        "bar=d&bar=e&bar=f&foo=a&foo=b&foo=c",
		},
		{
			name:        "all allowed values with single values",
			params:      url.Values{"foo": []string{"a"}, "bar": []string{"d"}},
			allowedKeys: sets.New("foo", "bar"),
			want:        "bar=d&foo=a",
		},
		{
			name:        "some allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: sets.New("foo"),
			want:        "bar=redacted&bar=redacted&bar=redacted&foo=a&foo=b&foo=c",
		},
		{
			name:        "some allowed values with single values",
			params:      url.Values{"foo": []string{"a"}, "bar": []string{"d"}},
			allowedKeys: sets.New("foo"),
			want:        "bar=redacted&foo=a",
		},
		{
			name:        "no allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: sets.New[string](),
			want:        "bar=redacted&bar=redacted&bar=redacted&foo=redacted&foo=redacted&foo=redacted",
		},
		{
			name:        "nil allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: nil,
			want:        "bar=redacted&bar=redacted&bar=redacted&foo=redacted&foo=redacted&foo=redacted",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, SanitizeParams(tt.params, tt.allowedKeys))
		})
	}
}
