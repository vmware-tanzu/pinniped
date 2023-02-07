// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package celtransformer is an implementation of upstream-to-downstream identity transformations
// and policies using CEL scripts.
//
// The CEL language is documented in https://github.com/google/cel-spec/blob/master/doc/langdef.md
// with optional extensions documented in https://github.com/google/cel-go/tree/master/ext.
package celtransformer

import (
	"context"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"

	"go.pinniped.dev/internal/idtransform"
)

const (
	usernameVariableName        = "username"
	groupsVariableName          = "groups"
	constStringVariableName     = "strConst"
	constStringListVariableName = "strListConst"

	defaultPolicyRejectedAuthMessage = "Authentication was rejected by a configured policy"
)

// CELTransformer can compile any number of transformation expression pipelines.
// Each compiled pipeline can be cached in memory for later thread-safe evaluation.
type CELTransformer struct {
	compiler             *cel.Env
	maxExpressionRuntime time.Duration
}

// NewCELTransformer returns a CELTransformer.
// A running process should only need one instance of a CELTransformer.
func NewCELTransformer(maxExpressionRuntime time.Duration) (*CELTransformer, error) {
	env, err := newEnv()
	if err != nil {
		return nil, err
	}
	return &CELTransformer{compiler: env, maxExpressionRuntime: maxExpressionRuntime}, nil
}

// TransformationConstants can be used to make more variables available to compiled CEL expressions for convenience.
type TransformationConstants struct {
	// A map of variable names to their string values. If a key "x" has value "123", then it will be available
	// to CEL expressions as the variable `strConst.x` with value `"123"`.
	StringConstants map[string]string
	// A map of variable names to their string list values. If a key "x" has value []string{"123","456"},
	// then it will be available to CEL expressions as the variable `strListConst.x` with value `["123","456"]`.
	StringListConstants map[string][]string
}

// Valid identifiers in CEL expressions are defined by the CEL language spec as: [_a-zA-Z][_a-zA-Z0-9]*
var validIdentifiersRegexp = regexp.MustCompile(`^[_a-zA-Z][_a-zA-Z0-9]*$`)

func (t *TransformationConstants) validateVariableNames() error {
	const errFormat = "%q is an invalid const variable name (must match [_a-zA-Z][_a-zA-Z0-9]*)"
	for k := range t.StringConstants {
		if !validIdentifiersRegexp.MatchString(k) {
			return fmt.Errorf(errFormat, k)
		}
	}
	for k := range t.StringListConstants {
		if !validIdentifiersRegexp.MatchString(k) {
			return fmt.Errorf(errFormat, k)
		}
	}
	return nil
}

// CompileTransformation compiles a CEL-based identity transformation expression.
// The compiled transform can be cached in memory and executed repeatedly and in a thread-safe way.
// The caller must not modify the consts param struct after calling this function to allow
// the returned IdentityTransformation to use it as a thread-safe read-only structure.
func (c *CELTransformer) CompileTransformation(t CELTransformation, consts *TransformationConstants) (idtransform.IdentityTransformation, error) {
	if consts == nil {
		consts = &TransformationConstants{}
	}
	if err := consts.validateVariableNames(); err != nil {
		return nil, err
	}
	return t.compile(c, consts)
}

// CELTransformation can be compiled into an IdentityTransformation.
type CELTransformation interface {
	compile(transformer *CELTransformer, consts *TransformationConstants) (idtransform.IdentityTransformation, error)
}

// UsernameTransformation is a CEL expression that can transform a username (or leave it unchanged).
// It implements CELTransformation.
type UsernameTransformation struct {
	Expression string
}

// GroupsTransformation is a CEL expression that can transform a list of group names (or leave it unchanged).
// It implements CELTransformation.
type GroupsTransformation struct {
	Expression string
}

// AllowAuthenticationPolicy is a CEL expression that can allow the authentication to proceed by returning true.
// It implements CELTransformation. When the CEL expression returns false, the authentication is rejected and the
// RejectedAuthenticationMessage is used. When RejectedAuthenticationMessage is empty, a default message will be
// used for rejected authentications.
type AllowAuthenticationPolicy struct {
	Expression                    string
	RejectedAuthenticationMessage string
}

func compileProgram(transformer *CELTransformer, expectedExpressionType *cel.Type, expr string) (cel.Program, error) {
	if strings.TrimSpace(expr) == "" {
		return nil, fmt.Errorf("cannot compile empty CEL expression")
	}

	// compile does both parsing and type checking. The parsing phase indicates whether the expression is
	// syntactically valid and expands any macros present within the environment. Parsing and checking are
	// more computationally expensive than evaluation, so parsing and checking are done in advance.
	ast, issues := transformer.compiler.Compile(expr)
	if issues != nil {
		return nil, fmt.Errorf("CEL expression compile error: %s", issues.String())
	}

	// The compiler's type checker has determined the type of the expression's result.
	// Check that it matches the type that we expect.
	if ast.OutputType().String() != expectedExpressionType.String() {
		return nil, fmt.Errorf("CEL expression should return type %q but returns type %q", expectedExpressionType, ast.OutputType())
	}

	// The cel.Program is stateless, thread-safe, and cachable.
	program, err := transformer.compiler.Program(ast,
		cel.InterruptCheckFrequency(100), // Kubernetes uses 100 here, so we'll copy that setting.
		cel.EvalOptions(cel.OptOptimize), // Optimize certain things now rather than at evaluation time.
	)
	if err != nil {
		return nil, fmt.Errorf("CEL expression program construction error: %w", err)
	}
	return program, nil
}

func (t *UsernameTransformation) compile(transformer *CELTransformer, consts *TransformationConstants) (idtransform.IdentityTransformation, error) {
	program, err := compileProgram(transformer, cel.StringType, t.Expression)
	if err != nil {
		return nil, err
	}
	return &compiledUsernameTransformation{
		baseCompiledTransformation: &baseCompiledTransformation{
			program:              program,
			consts:               consts,
			maxExpressionRuntime: transformer.maxExpressionRuntime,
		},
	}, nil
}

func (t *GroupsTransformation) compile(transformer *CELTransformer, consts *TransformationConstants) (idtransform.IdentityTransformation, error) {
	program, err := compileProgram(transformer, cel.ListType(cel.StringType), t.Expression)
	if err != nil {
		return nil, err
	}
	return &compiledGroupsTransformation{
		baseCompiledTransformation: &baseCompiledTransformation{
			program:              program,
			consts:               consts,
			maxExpressionRuntime: transformer.maxExpressionRuntime,
		},
	}, nil
}

func (t *AllowAuthenticationPolicy) compile(transformer *CELTransformer, consts *TransformationConstants) (idtransform.IdentityTransformation, error) {
	program, err := compileProgram(transformer, cel.BoolType, t.Expression)
	if err != nil {
		return nil, err
	}
	return &compiledAllowAuthenticationPolicy{
		baseCompiledTransformation: &baseCompiledTransformation{
			program:              program,
			consts:               consts,
			maxExpressionRuntime: transformer.maxExpressionRuntime,
		},
		rejectedAuthenticationMessage: t.RejectedAuthenticationMessage,
	}, nil
}

// Base type for common aspects of compiled transformations.
type baseCompiledTransformation struct {
	program              cel.Program
	consts               *TransformationConstants
	maxExpressionRuntime time.Duration
}

// Implements idtransform.IdentityTransformation.
type compiledUsernameTransformation struct {
	*baseCompiledTransformation
}

// Implements idtransform.IdentityTransformation.
type compiledGroupsTransformation struct {
	*baseCompiledTransformation
}

// Implements idtransform.IdentityTransformation.
type compiledAllowAuthenticationPolicy struct {
	*baseCompiledTransformation
	rejectedAuthenticationMessage string
}

func (c *baseCompiledTransformation) evalProgram(ctx context.Context, username string, groups []string) (ref.Val, error) {
	// Limit the runtime of a CEL expression to avoid accidental very expensive expressions.
	timeoutCtx, cancel := context.WithTimeout(ctx, c.maxExpressionRuntime)
	defer cancel()

	// Evaluation is thread-safe and side effect free. Many inputs can be sent to the same cel.Program
	// and if fields are present in the input, but not referenced in the expression, they are ignored.
	// The argument to Eval may either be an `interpreter.Activation` or a `map[string]interface{}`.
	val, _, err := c.program.ContextEval(timeoutCtx, map[string]interface{}{
		usernameVariableName:        username,
		groupsVariableName:          groups,
		constStringVariableName:     c.consts.StringConstants,
		constStringListVariableName: c.consts.StringListConstants,
	})
	return val, err
}

func (c *compiledUsernameTransformation) Evaluate(ctx context.Context, username string, groups []string) (*idtransform.TransformationResult, error) {
	val, err := c.evalProgram(ctx, username, groups)
	if err != nil {
		return nil, err
	}
	nativeValue, err := val.ConvertToNative(reflect.TypeOf(""))
	if err != nil {
		return nil, fmt.Errorf("could not convert expression result to string: %w", err)
	}
	stringValue, ok := nativeValue.(string)
	if !ok {
		return nil, fmt.Errorf("could not convert expression result to string")
	}
	return &idtransform.TransformationResult{
		Username:              stringValue,
		Groups:                groups, // groups are not modified by username transformations
		AuthenticationAllowed: true,
	}, nil
}

func (c *compiledGroupsTransformation) Evaluate(ctx context.Context, username string, groups []string) (*idtransform.TransformationResult, error) {
	val, err := c.evalProgram(ctx, username, groups)
	if err != nil {
		return nil, err
	}
	nativeValue, err := val.ConvertToNative(reflect.TypeOf([]string{}))
	if err != nil {
		return nil, fmt.Errorf("could not convert expression result to []string: %w", err)
	}
	stringSliceValue, ok := nativeValue.([]string)
	if !ok {
		return nil, fmt.Errorf("could not convert expression result to []string")
	}
	return &idtransform.TransformationResult{
		Username:              username, // username is not modified by groups transformations
		Groups:                stringSliceValue,
		AuthenticationAllowed: true,
	}, nil
}

func (c *compiledAllowAuthenticationPolicy) Evaluate(ctx context.Context, username string, groups []string) (*idtransform.TransformationResult, error) {
	val, err := c.evalProgram(ctx, username, groups)
	if err != nil {
		return nil, err
	}
	nativeValue, err := val.ConvertToNative(reflect.TypeOf(true))
	if err != nil {
		return nil, fmt.Errorf("could not convert expression result to bool: %w", err)
	}
	boolValue, ok := nativeValue.(bool)
	if !ok {
		return nil, fmt.Errorf("could not convert expression result to bool")
	}
	result := &idtransform.TransformationResult{
		Username:              username, // username is not modified by policies
		Groups:                groups,   // groups are not modified by policies
		AuthenticationAllowed: boolValue,
	}
	if !boolValue {
		if len(c.rejectedAuthenticationMessage) == 0 {
			result.RejectedAuthenticationMessage = defaultPolicyRejectedAuthMessage
		} else {
			result.RejectedAuthenticationMessage = c.rejectedAuthenticationMessage
		}
	}
	return result, nil
}

func newEnv() (*cel.Env, error) {
	// Note that Kubernetes uses CEL in several places, which are helpful to see as an example of
	// how to configure the CEL compiler for production usage. Examples:
	// https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiserver/pkg/admission/plugin/validatingadmissionpolicy/compiler.go
	// https://github.com/kubernetes/kubernetes/blob/master/staging/src/k8s.io/apiextensions-apiserver/pkg/apiserver/schema/cel/compilation.go
	return cel.NewEnv(
		// Declare our variable without giving them values yet. By declaring them here, the type is known during
		// the parsing/checking phase.
		cel.Variable(usernameVariableName, cel.StringType),
		cel.Variable(groupsVariableName, cel.ListType(cel.StringType)),
		cel.Variable(constStringVariableName, cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable(constStringListVariableName, cel.MapType(cel.StringType, cel.ListType(cel.StringType))),

		// Enable the strings extensions.
		// See https://github.com/google/cel-go/tree/master/ext#strings
		// CEL also has other extensions for bas64 encoding/decoding and for math that we could choose to enable.
		// See https://github.com/google/cel-go/tree/master/ext
		// Kubernetes adds more extensions for extra regexp helpers, URLs, and extra list helpers that we could also
		// consider enabling. Note that if we added their regexp extension, then we would also need to add
		// cel.OptimizeRegex(library.ExtensionLibRegexOptimizations...) as an option when we call cel.Program.
		// See https://github.com/kubernetes/kubernetes/tree/master/staging/src/k8s.io/apiserver/pkg/cel/library
		ext.Strings(),

		// Just in case someone converts a string to a timestamp, make any time operations which do not include
		// an explicit timezone argument default to UTC.
		cel.DefaultUTCTimeZone(true),

		// Check list and map literal entry types during type-checking.
		cel.HomogeneousAggregateLiterals(),

		// Check for collisions in declarations now instead of later.
		cel.EagerlyValidateDeclarations(true),
	)
}
