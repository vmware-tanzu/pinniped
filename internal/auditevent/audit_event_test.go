// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package auditevent

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
		want        []any
	}{
		{
			name:        "nil values",
			params:      nil,
			allowedKeys: nil,
			want: []any{
				"params",
				map[string]string{},
			},
		},
		{
			name:        "empty values",
			params:      url.Values{},
			allowedKeys: nil,
			want: []any{
				"params",
				map[string]string{},
			},
		},
		{
			name:        "all allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: sets.New("foo", "bar"),
			want: []any{
				"params",
				map[string]string{
					"bar": "d",
					"foo": "a",
				},
				"multiValueParams",
				url.Values{
					"bar": []string{"d", "e", "f"},
					"foo": []string{"a", "b", "c"},
				},
			},
		},
		{
			name:        "all allowed values with single values",
			params:      url.Values{"foo": []string{"a"}, "bar": []string{"d"}},
			allowedKeys: sets.New("foo", "bar"),
			want: []any{
				"params",
				map[string]string{
					"foo": "a",
					"bar": "d",
				},
			},
		},
		{
			name:        "some allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: sets.New("foo"),
			want: []any{
				"params",
				map[string]string{
					"bar": "redacted",
					"foo": "a",
				},
				"multiValueParams",
				url.Values{
					"bar": []string{"redacted", "redacted", "redacted"},
					"foo": []string{"a", "b", "c"},
				},
			},
		},
		{
			name:        "some allowed values with single values",
			params:      url.Values{"foo": []string{"a"}, "bar": []string{"d"}},
			allowedKeys: sets.New("foo"),
			want: []any{
				"params",
				map[string]string{
					"bar": "redacted",
					"foo": "a",
				},
			},
		},
		{
			name:        "no allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: sets.New[string](),
			want: []any{
				"params",
				map[string]string{
					"bar": "redacted",
					"foo": "redacted",
				},
				"multiValueParams",
				url.Values{
					"bar": {"redacted", "redacted", "redacted"},
					"foo": {"redacted", "redacted", "redacted"},
				},
			},
		},
		{
			name:        "nil allowed values",
			params:      url.Values{"foo": []string{"a", "b", "c"}, "bar": []string{"d", "e", "f"}},
			allowedKeys: nil,
			want: []any{
				"params",
				map[string]string{
					"bar": "redacted",
					"foo": "redacted",
				},
				"multiValueParams",
				url.Values{
					"bar": {"redacted", "redacted", "redacted"},
					"foo": {"redacted", "redacted", "redacted"},
				},
			},
		},
		{
			name: "url decodes allowed values",
			params: url.Values{
				"foo": []string{"a%3Ab", "c", "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"},
				"bar": []string{"d", "e", "f"},
			},
			allowedKeys: sets.New("foo"),
			want: []any{
				"params",
				map[string]string{
					"bar": "redacted",
					"foo": "a:b",
				},
				"multiValueParams",
				url.Values{
					"bar": {"redacted", "redacted", "redacted"},
					"foo": {"a:b", "c", "urn:ietf:params:oauth:grant-type:token-exchange"},
				},
			},
		},
		{
			name: "ignores url decode errors",
			params: url.Values{
				"bad_encoding": []string{"%.."},
			},
			allowedKeys: sets.New("bad_encoding"),
			want: []any{
				"params",
				map[string]string{
					"bad_encoding": "%..",
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// This comparison should require the exact order
			require.Equal(t, test.want, SanitizeParams(test.params, test.allowedKeys))
		})
	}
}
