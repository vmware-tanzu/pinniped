// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_verb(t *testing.T) {
	tests := []struct {
		name string
		f    func() string
		want string
	}{
		{
			name: "error: string format",
			f: func() string {
				return fmt.Errorf("%s", VerbGet).Error()
			},
			want: "get",
		},
		{
			name: "error: value format",
			f: func() string {
				return fmt.Errorf("%v", VerbUpdate).Error()
			},
			want: "update",
		},
		{
			name: "error: go value format",
			f: func() string {
				return fmt.Errorf("%#v", VerbDelete).Error()
			},
			want: `"delete"`,
		},
		{
			name: "error: go value format in middelware request",
			f: func() string {
				return fmt.Errorf("%#v", request{verb: VerbPatch}).Error()
			},
			want: `kubeclient.request{verb:"patch", namespace:"", resource:schema.GroupVersionResource{Group:"", Version:"", Resource:""}, reqFuncs:[]func(kubeclient.Object)(nil), respFuncs:[]func(kubeclient.Object)(nil), subresource:""}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.f())
		})
	}
}
