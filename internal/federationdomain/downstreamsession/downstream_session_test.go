// Copyright 2023-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package downstreamsession

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/celtransformer"
	"go.pinniped.dev/internal/idtransform"
)

func TestApplyIdentityTransformations(t *testing.T) {
	tests := []struct {
		name         string
		transforms   []celtransformer.CELTransformation
		username     string
		groups       []string
		wantUsername string
		wantGroups   []string
		wantErr      string
	}{
		{
			name: "unexpected errors",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.UsernameTransformation{Expression: `""`},
			},
			username: "ryan",
			groups:   []string{"a", "b"},
			wantErr:  "configured identity transformation or policy resulted in unexpected error",
		},
		{
			name: "auth disallowed by policy with implicit rejection message",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.AllowAuthenticationPolicy{Expression: `false`},
			},
			username: "ryan",
			groups:   []string{"a", "b"},
			wantErr:  "configured identity policy rejected this authentication: authentication was rejected by a configured policy",
		},
		{
			name: "auth disallowed by policy with explicit rejection message",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.AllowAuthenticationPolicy{
					Expression:                    `false`,
					RejectedAuthenticationMessage: "this is the stated reason",
				},
			},
			username: "ryan",
			groups:   []string{"a", "b"},
			wantErr:  "configured identity policy rejected this authentication: this is the stated reason",
		},
		{
			name: "successful auth",
			transforms: []celtransformer.CELTransformation{
				&celtransformer.UsernameTransformation{Expression: `"pre:" + username`},
				&celtransformer.GroupsTransformation{Expression: `groups.map(g, "pre:" + g)`},
			},
			username:     "ryan",
			groups:       []string{"a", "b"},
			wantUsername: "pre:ryan",
			wantGroups:   []string{"pre:a", "pre:b"},
		},
	}

	for _, test := range tests {
		tt := test
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transformer, err := celtransformer.NewCELTransformer(5 * time.Second)
			require.NoError(t, err)

			pipeline := idtransform.NewTransformationPipeline()
			for _, transform := range tt.transforms {
				compiledTransform, err := transformer.CompileTransformation(transform, nil)
				require.NoError(t, err)
				pipeline.AppendTransformation(compiledTransform)
			}

			gotUsername, gotGroups, err := ApplyIdentityTransformations(context.Background(), pipeline, tt.username, tt.groups)
			if tt.wantErr != "" {
				require.EqualError(t, err, tt.wantErr)
				require.Empty(t, gotUsername)
				require.Nil(t, gotGroups)
			} else {
				require.NoError(t, err)
				require.Equal(t, tt.wantUsername, gotUsername)
				require.Equal(t, tt.wantGroups, gotGroups)
			}
		})
	}
}
