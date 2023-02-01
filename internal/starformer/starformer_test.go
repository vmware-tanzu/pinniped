// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package starformer

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
)

func TestTypicalPerformance(t *testing.T) {
	t.Parallel()

	starformer, err := New(here.Doc(`
		def transform(username, groups):
			prefixedGroups = []
			for g in groups:
				prefixedGroups.append("group_prefix:" + g)
			return "username_prefix:" + username, prefixedGroups
	`))
	require.NoError(t, err)
	require.NotNil(t, starformer)

	groups := []string{}
	wantGroups := []string{}
	for i := 0; i < 100; i++ {
		groups = append(groups, fmt.Sprintf("g%d", i))
		wantGroups = append(wantGroups, fmt.Sprintf("group_prefix:g%d", i))
	}

	// Before looking at performance, check that the behavior of the function is correct.
	gotUsername, gotGroups, err := starformer.Transform("ryan", groups)
	require.NoError(t, err)
	require.Equal(t, "username_prefix:ryan", gotUsername)
	require.Equal(t, wantGroups, gotGroups)
	// Calling it a second time should give the same results again for the same inputs.
	gotUsername, gotGroups, err = starformer.Transform("ryan", groups)
	require.NoError(t, err)
	require.Equal(t, "username_prefix:ryan", gotUsername)
	require.Equal(t, wantGroups, gotGroups)

	// This is meant to give a sense of typical runtime of a Starlark function which transforms
	// a username and 100 group names. It is not meant to be a pass/fail test or scientific benchmark test.
	iterations := 1000
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, _, _ = starformer.Transform("ryan", groups)
	}
	elapsed := time.Since(start)
	t.Logf("TestTypicalPerformance %d iteration of Transform took %s; average runtime %s", iterations, elapsed, elapsed/time.Duration(iterations))
	// On my laptop this prints: TestTypicalPerformance 1000 iteration of Transform took 299.109387ms; average runtime 299.109µs
}

func TestTransformer(t *testing.T) {
	// See Starlark dialect language documentation here: https://github.com/google/starlark-go/blob/master/doc/spec.md
	tests := []struct {
		name             string
		starlarkSrc      string
		username         string
		groups           []string
		wantUsername     string
		wantGroups       []string
		wantNewErr       string
		wantTransformErr string
	}{
		{
			name: "identity function makes no modification",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return username, groups
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1", "g2"},
		},
		{
			name: "returning None is a shortcut for making no modification",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return None
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1", "g2"},
		},
		{
			name: "prefixing the username",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return "foobar:" + username, groups
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "foobar:ryan",
			wantGroups:   []string{"g1", "g2"},
		},
		{
			name: "down-casing the username",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return username.lower(), groups
			`),
			username:     "RyAn",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1", "g2"},
		},
		{
			name: "removing all groups",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return username, ()
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{},
		},
		{
			name: "modifying groups",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return username, ("new-g1", "new-g2")
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"new-g1", "new-g2"},
		},
		{
			name: "converting the groups param to a list type in the business logic is easy, and returning groups as a list works",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					groupsList = list(groups)
					groupsList.pop()
					return username, groupsList
			`),
			username:     "ryan",
			groups:       []string{"g1", "g3"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1"},
		},
		{
			name: "can print from the script",
			starlarkSrc: here.Doc(`
				print("this should get logged by Pinniped but it is not asserted here")
				def transform(username, groups):
					print("this should get logged by Pinniped but it is not asserted here:", username)
					return username, groups
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1", "g2"},
		},
		{
			name: "rejecting a login by raising an error",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					if username == "ryan":
						fail("i don't like the username", username)
					else:
						return username, groups
			`),
			username:         "ryan",
			groups:           []string{"g1", "g2"},
			wantTransformErr: `error while running starlark "transform" function: fail: i don't like the username ryan`,
		},
		{
			name: "using the non-standard 'set' type is allowed",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					groupsSet = set(groups)
					if "g2" in groupsSet:
						return username, groups
					else:
						fail("user", username, "does not belong to group g2")
			`),
			username:         "ryan",
			groups:           []string{"g1", "g3"},
			wantTransformErr: `error while running starlark "transform" function: fail: user ryan does not belong to group g2`,
		},
		{
			name: "using the non-standard 'set' type is allowed, and the groups can be returned as a set",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					groupsSet = set(groups)
					groupsSet = groupsSet.union(["g42"])
					if "g2" in groupsSet:
						return username, groupsSet
					else:
						fail("user", username, "does not belong to group g2")
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1", "g2", "g42"},
		},
		{
			name: "the math module may be loaded",
			starlarkSrc: here.Doc(`
				load('math.star', 'math')
				def transform(username, groups):
					if math.round(0.4) == 0.0:
						return username, groups
					else:
						fail("math module is supposed to work")
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{"g1", "g2"},
		},
		{
			name: "the json module may be loaded",
			starlarkSrc: here.Doc(`
				load('json.star', 'json')
				def transform(username, groups):
					return username, [json.encode({"hello": groups[0]})]
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "ryan",
			wantGroups:   []string{`{"hello":"g1"}`},
		},
		{
			name: "the time module may be loaded",
			starlarkSrc: here.Doc(`
				load('time.star', 'time')
				def transform(username, groups):
					if time.now() > time.parse_time("2001-01-20T00:00:00Z"):
						return "someone", ["g3", "g4"]
					fail("huh?")
			`),
			username:     "ryan",
			groups:       []string{"g1", "g2"},
			wantUsername: "someone",
			wantGroups:   []string{"g3", "g4"},
		},
		{
			name: "loading other modules results in an error",
			starlarkSrc: here.Doc(`
				load('other.star', 'other')
				def transform(username, groups):
					return username, groups
			`),
			username:   "ryan",
			groups:     []string{"g1", "g2"},
			wantNewErr: "error while loading starlark transform script: cannot load other.star: only the following modules may be loaded: json.star, time.star, math.star",
		},
		{
			name: "unexpected error during loading",
			starlarkSrc: here.Doc(`
				this is not valid starlark syntax
			`),
			wantNewErr: "error while loading starlark transform script: transform.star:1:8: got illegal token, want newline",
		},
		{
			name: "too many execution steps during loading",
			starlarkSrc: here.Doc(`
				def helper():
					a = 0
					for x in range(1000000):
						a += 1
				helper()
			`),
			wantNewErr: "error while loading starlark transform script: Starlark computation cancelled: too many steps",
		},
		{
			name: "too many execution steps during transform function",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					a = 0
					for x in range(1000000):
						a += 1
					return username, groups
			`),
			username:         "ryan",
			groups:           []string{"g1", "g2"},
			wantTransformErr: `error while running starlark "transform" function: Starlark computation cancelled: too many steps`,
		},
		{
			name: "returning the wrong data type",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return 42
			`),
			username:         "ryan",
			groups:           []string{"g1", "g2"},
			wantTransformErr: `expected starlark "transform" function to return None or a Tuple of length 2`,
		},
		{
			name: "returning the wrong data type inside the groups iterable return value",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return username, ("g1", 42)
			`),
			username:         "ryan",
			groups:           []string{"g1", "g2"},
			wantTransformErr: `expected starlark "transform" function's return tuple's second value to contain only non-empty strings`,
		},
		{
			name: "returning an empty string inside the groups iterable return value",
			starlarkSrc: here.Doc(`
				def transform(username, groups):
					return username, ("g1", "", "g2")
			`),
			username:         "ryan",
			groups:           []string{"g1", "g2"},
			wantTransformErr: `expected starlark "transform" function's return tuple's second value to contain only non-empty strings`,
		},
		{
			name: "no transform function defined",
			starlarkSrc: here.Doc(`
				def otherFunction(username, groups):
					return None
			`),
			wantNewErr: `starlark script does not define "transform" function`,
		},
		{
			name: "transform function defined with wrong number of positional parameters",
			starlarkSrc: here.Doc(`
				def transform(username):
					return None
			`),
			wantNewErr: `starlark script's global "transform" function has 1 parameters but should have 2`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			starformer, err := New(tt.starlarkSrc)
			if tt.wantNewErr != "" {
				require.EqualError(t, err, tt.wantNewErr)
				require.Nil(t, starformer)
				return // wanted an error from New, so don't keep going
			}
			require.NoError(t, err)
			require.NotNil(t, starformer)

			gotUsername, gotGroups, err := starformer.Transform(tt.username, tt.groups)
			if tt.wantTransformErr != "" {
				require.EqualError(t, err, tt.wantTransformErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantUsername, gotUsername)
			require.Equal(t, tt.wantGroups, gotGroups)
		})
	}
}
