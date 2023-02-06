// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package idtransform defines upstream-to-downstream identity transformations which could be
// implemented using various approaches or languages.
package idtransform

import (
	"context"
	"fmt"
	"strings"
)

// TransformationResult is the result of evaluating a transformation against some inputs.
type TransformationResult struct {
	Username                      string   // the new username for an allowed auth
	Groups                        []string // the new group names for an allowed auth
	AuthenticationAllowed         bool     // when false, disallow this authentication attempt
	RejectedAuthenticationMessage string   // should be set when AuthenticationAllowed is false
}

// IdentityTransformation is an individual identity transformation which can be evaluated.
type IdentityTransformation interface {
	Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error)
}

// TransformationPipeline is a list of identity transforms, which can be evaluated in order against some given input
// values.
type TransformationPipeline struct {
	transforms []IdentityTransformation
}

// NewTransformationPipeline creates an empty TransformationPipeline.
func NewTransformationPipeline() *TransformationPipeline {
	return &TransformationPipeline{transforms: []IdentityTransformation{}}
}

// AppendTransformation adds a transformation to the end of the list of transformations for this pipeline.
// This is not thread-safe, so be sure to add all transformations from a single goroutine before using Evaluate
// from multiple goroutines.
func (p *TransformationPipeline) AppendTransformation(t IdentityTransformation) {
	p.transforms = append(p.transforms, t)
}

// Evaluate runs the transformation pipeline for a given input identity. It returns a potentially transformed or
// rejected identity, or an error. If any transformation in the list rejects the authentication, then the list is
// short-circuited but no error is returned. Only unexpected errors are returned as errors. This is safe to call
// from multiple goroutines.
func (p *TransformationPipeline) Evaluate(ctx context.Context, username string, groups []string) (*TransformationResult, error) {
	accumulatedResult := &TransformationResult{
		Username:              username,
		Groups:                groups,
		AuthenticationAllowed: true,
	}
	var err error
	for i, transform := range p.transforms {
		accumulatedResult, err = transform.Evaluate(ctx, accumulatedResult.Username, accumulatedResult.Groups)
		if err != nil {
			// There was an unexpected error evaluating a transformation.
			return nil, fmt.Errorf("identity transformation at index %d: %w", i, err)
		}
		if !accumulatedResult.AuthenticationAllowed {
			// Auth has been rejected by a policy. Stop evaluating the rest of the transformations.
			return accumulatedResult, nil
		}
		if strings.TrimSpace(accumulatedResult.Username) == "" {
			return nil, fmt.Errorf("identity transformation returned an empty username, which is not allowed")
		}
	}
	// There were no unexpected errors and no policy which rejected auth.
	return accumulatedResult, nil
}
