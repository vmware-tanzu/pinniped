// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package transformtestutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/celtransformer"
	"go.pinniped.dev/internal/idtransform"
)

func NewPrefixingPipeline(t *testing.T, usernamePrefix, groupsPrefix string) *idtransform.TransformationPipeline {
	t.Helper()

	transformer, err := celtransformer.NewCELTransformer(5 * time.Second)
	require.NoError(t, err)

	p := idtransform.NewTransformationPipeline()

	userTransform, err := transformer.CompileTransformation(
		&celtransformer.UsernameTransformation{Expression: fmt.Sprintf(`"%s" + username`, usernamePrefix)},
		nil,
	)
	require.NoError(t, err)
	p.AppendTransformation(userTransform)

	groupsTransform, err := transformer.CompileTransformation(
		&celtransformer.GroupsTransformation{Expression: fmt.Sprintf(`groups.map(g, "%s" + g)`, groupsPrefix)},
		nil,
	)
	require.NoError(t, err)
	p.AppendTransformation(groupsTransform)

	return p
}

func NewRejectAllAuthPipeline(t *testing.T) *idtransform.TransformationPipeline {
	t.Helper()

	transformer, err := celtransformer.NewCELTransformer(5 * time.Second)
	require.NoError(t, err)

	p := idtransform.NewTransformationPipeline()

	compiledTransform, err := transformer.CompileTransformation(
		&celtransformer.AllowAuthenticationPolicy{Expression: `false`},
		nil,
	)
	require.NoError(t, err)
	p.AppendTransformation(compiledTransform)

	return p
}
