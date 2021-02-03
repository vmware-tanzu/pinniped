// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package kubeclient

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func Test_maybeRestoreGVK(t *testing.T) {
	type args struct {
		unknown         *runtime.Unknown
		origGVK, newGVK schema.GroupVersionKind
	}
	tests := []struct {
		name        string
		args        args
		want        runtime.Object
		wantChanged bool
		wantErr     string
	}{
		{
			name: "should update gvk via JSON",
			args: args{
				unknown: &runtime.Unknown{
					TypeMeta: runtime.TypeMeta{
						APIVersion: "new/v1",
						Kind:       "Tree",
					},
					Raw:         []byte(`{"apiVersion":"new/v1","kind":"Tree","spec":{"pandas":"love"}}`),
					ContentType: runtime.ContentTypeJSON,
				},
				origGVK: schema.GroupVersionKind{
					Group:   "old",
					Version: "v1",
					Kind:    "Tree",
				},
				newGVK: schema.GroupVersionKind{
					Group:   "new",
					Version: "v1",
					Kind:    "Tree",
				},
			},
			want: &runtime.Unknown{
				TypeMeta: runtime.TypeMeta{
					APIVersion: "old/v1",
					Kind:       "Tree",
				},
				Raw:         []byte(`{"apiVersion":"old/v1","kind":"Tree","spec":{"pandas":"love"}}`),
				ContentType: runtime.ContentTypeJSON,
			},
			wantChanged: true,
			wantErr:     "",
		},
		{
			name: "should update gvk via protobuf",
			args: args{
				unknown: &runtime.Unknown{
					TypeMeta: runtime.TypeMeta{
						APIVersion: "new/v1",
						Kind:       "Tree",
					},
					Raw:         []byte(`assumed to be valid and does not change`),
					ContentType: runtime.ContentTypeProtobuf,
				},
				origGVK: schema.GroupVersionKind{
					Group:   "original",
					Version: "v1",
					Kind:    "Tree",
				},
				newGVK: schema.GroupVersionKind{
					Group:   "new",
					Version: "v1",
					Kind:    "Tree",
				},
			},
			want: &runtime.Unknown{
				TypeMeta: runtime.TypeMeta{
					APIVersion: "original/v1",
					Kind:       "Tree",
				},
				Raw:         []byte(`assumed to be valid and does not change`),
				ContentType: runtime.ContentTypeProtobuf,
			},
			wantChanged: true,
			wantErr:     "",
		},
		{
			name: "should ignore because gvk is different",
			args: args{
				unknown: &runtime.Unknown{
					TypeMeta: runtime.TypeMeta{
						APIVersion: "new/v1",
						Kind:       "Tree",
					},
				},
				newGVK: schema.GroupVersionKind{
					Group:   "new",
					Version: "v1",
					Kind:    "Forest",
				},
			},
			want:        nil,
			wantChanged: false,
			wantErr:     "",
		},
		{
			name: "empty raw is ignored",
			args: args{
				unknown: &runtime.Unknown{},
			},
			want:        nil,
			wantChanged: false,
			wantErr:     "",
		},
		{
			name: "invalid content type errors",
			args: args{
				unknown: &runtime.Unknown{
					TypeMeta: runtime.TypeMeta{
						APIVersion: "walrus.tld/v1",
						Kind:       "Seal",
					},
					Raw:         []byte(`data that should be ignored because we do not used YAML`),
					ContentType: runtime.ContentTypeYAML,
				},
				origGVK: schema.GroupVersionKind{
					Group:   "pinniped.dev",
					Version: "v1",
					Kind:    "Seal",
				},
				newGVK: schema.GroupVersionKind{
					Group:   "walrus.tld",
					Version: "v1",
					Kind:    "Seal",
				},
			},
			want:        nil,
			wantChanged: false,
			wantErr:     "unknown content type: application/yaml",
		},
		{
			name: "invalid JSON should error",
			args: args{
				unknown: &runtime.Unknown{
					TypeMeta: runtime.TypeMeta{
						APIVersion: "ocean/v1",
						Kind:       "Water",
					},
					Raw:         []byte(`lol not JSON`),
					ContentType: runtime.ContentTypeJSON,
				},
				origGVK: schema.GroupVersionKind{
					Group:   "dirt",
					Version: "v1",
					Kind:    "Land",
				},
				newGVK: schema.GroupVersionKind{
					Group:   "ocean",
					Version: "v1",
					Kind:    "Water",
				},
			},
			want:        nil,
			wantChanged: false,
			wantErr:     "failed to unmarshall json keys: invalid character 'l' looking for beginning of value",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			serializer := &testSerializer{unknown: tt.args.unknown}
			respData := []byte(`original`)
			result := &mutationResult{origGVK: tt.args.origGVK, newGVK: tt.args.newGVK, gvkChanged: tt.args.origGVK != tt.args.newGVK}

			newRespData, err := maybeRestoreGVK(serializer, respData, result)

			if len(tt.wantErr) > 0 {
				require.EqualError(t, err, tt.wantErr)
				require.Nil(t, newRespData)
				require.Nil(t, serializer.obj)
				return
			}

			require.NoError(t, err)

			if tt.wantChanged {
				require.Equal(t, []byte(`changed`), newRespData)
			} else {
				require.Equal(t, []byte(`original`), newRespData)
			}

			require.Equal(t, tt.want, serializer.obj)
		})
	}
}

type testSerializer struct {
	unknown *runtime.Unknown
	obj     runtime.Object
}

func (s *testSerializer) Encode(obj runtime.Object, w io.Writer) error {
	s.obj = obj
	_, err := w.Write([]byte(`changed`))
	return err
}

func (s *testSerializer) Decode(_ []byte, _ *schema.GroupVersionKind, into runtime.Object) (runtime.Object, *schema.GroupVersionKind, error) {
	u := into.(*runtime.Unknown)
	*u = *s.unknown
	return u, nil, nil
}

func (s *testSerializer) Identifier() runtime.Identifier {
	panic("not called")
}
