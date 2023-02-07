// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package celtransformer

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/idtransform"
)

func TestTransformer(t *testing.T) {
	var veryLargeGroupList []string
	for i := 0; i < 10000; i++ {
		veryLargeGroupList = append(veryLargeGroupList, fmt.Sprintf("g%d", i))
	}

	alreadyCancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name       string
		username   string
		groups     []string
		transforms []CELTransformation
		consts     *TransformationConstants
		ctx        context.Context

		wantUsername            string
		wantGroups              []string
		wantAuthRejected        bool
		wantAuthRejectedMessage string
		wantCompileErr          string
		wantEvaluationErr       string
	}{
		{
			name:         "empty transforms list does not change the identity and allows auth",
			username:     "ryan",
			groups:       []string{"admins", "developers", "other"},
			transforms:   []CELTransformation{},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "simple transforms which do not change the identity and allows auth",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username`},
				&GroupsTransformation{Expression: `groups`},
				&AllowAuthenticationPolicy{Expression: `true`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "transformations run in the order that they are given and accumulate results",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `"a:" + username`},
				&UsernameTransformation{Expression: `"b:" + username`},
				&GroupsTransformation{Expression: `groups.map(g, "a:" + g)`},
				&GroupsTransformation{Expression: `groups.map(g, "b:" + g)`},
			},
			wantUsername: "b:a:ryan",
			wantGroups:   []string{"b:a:admins", "b:a:developers", "b:a:other"},
		},
		{
			name:     "policies which return false cause the pipeline to stop running and return a rejected auth result",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `"a:" + username`},
				&AllowAuthenticationPolicy{Expression: `true`, RejectedAuthenticationMessage: `Everyone is allowed`},
				&GroupsTransformation{Expression: `groups.map(g, "a:" + g)`},
				&AllowAuthenticationPolicy{Expression: `username == "admin"`, RejectedAuthenticationMessage: `Only the username "admin" is allowed`},
				&GroupsTransformation{Expression: `groups.map(g, "b:" + g)`}, // does not get evaluated
			},
			wantUsername:            "a:ryan",
			wantGroups:              []string{"a:admins", "a:developers", "a:other"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Only the username "admin" is allowed`,
		},
		{
			name:     "policies without a RejectedAuthenticationMessage get a default message",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `username == "admin"`, RejectedAuthenticationMessage: ""},
			},
			wantUsername:            "ryan",
			wantGroups:              []string{"admins", "developers", "other"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Authentication was rejected by a configured policy`,
		},
		{
			name:     "any transformations can use the username and group variables",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `groups[0] == "admins" && username == "ryan"`},
				&GroupsTransformation{Expression: `groups + [username]`},
				&UsernameTransformation{Expression: `groups[2]`},               // changes the username to "other"
				&GroupsTransformation{Expression: `groups + [username + "2"]`}, // by the time this expression runs, the username was already changed to "other"
			},
			wantUsername: "other",
			wantGroups:   []string{"admins", "developers", "other", "ryan", "other2"},
		},
		{
			name:     "any transformation can use the provided constants as variables",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			consts: &TransformationConstants{
				StringConstants: map[string]string{
					"x": "abc",
					"y": "def",
				},
				StringListConstants: map[string][]string{
					"x": {"uvw", "xyz"},
					"y": {"123", "456"},
				},
			},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `strConst.x + strListConst.x[0]`},
				&GroupsTransformation{Expression: `[strConst.x, strConst.y, strListConst.x[1], strListConst.y[0]]`},
				&AllowAuthenticationPolicy{Expression: `strConst.x == "abc"`},
			},
			wantUsername: "abcuvw",
			wantGroups:   []string{"abc", "def", "xyz", "123"},
		},
		{
			name:     "the CEL string extensions are enabled for use in the expressions",
			username: " ryan ",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.map(g, g.replace("mins", "ministrators"))`},
				&UsernameTransformation{Expression: `username.upperAscii()`},
				&AllowAuthenticationPolicy{Expression: `(username.lowerAscii()).trim() == "ryan"`, RejectedAuthenticationMessage: `Silly example`},
				&UsernameTransformation{Expression: `username.trim()`},
			},
			wantUsername: "RYAN",
			wantGroups:   []string{"administrators", "developers", "other"},
		},
		{
			name:     "UTC is the default time zone for time operations",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `string(timestamp("2023-01-16T10:00:20.021-08:00").getHours())`},
			},
			// Without the compiler option cel.DefaultUTCTimeZone, this result would be 10.
			// With the option, this result is the original hour from the timestamp string (10), plus the effect
			// of the timezone (8), to move the hour into the UTC time zone.
			wantUsername: "18",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "the default UTC time zone for time operations can be overridden by passing the time zone as an argument to the operation",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `string(timestamp("2023-01-16T10:00:20.021-08:00").getHours("US/Mountain"))`},
			},
			// This is the hour of the timestamp in Mountain time, which is one time zone over from Pacific (-08:00),
			// hence it is one larger than the original "10" from the timestamp string.
			wantUsername: "11",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "quick expressions are finished by CEL before CEL even looks at the cancel context",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `["one group"]`},
			},
			ctx:          alreadyCancelledContext,
			wantUsername: "ryan",
			wantGroups:   []string{"one group"},
		},

		//
		// Unit tests to demonstrate practical examples of useful CEL expressions.
		//
		{
			name:     "can prefix username and all groups",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `"username_prefix:" + username`},
				&GroupsTransformation{Expression: `groups.map(g, "group_prefix:" + g)`},
			},
			wantUsername: "username_prefix:ryan",
			wantGroups:   []string{"group_prefix:admins", "group_prefix:developers", "group_prefix:other"},
		},
		{
			name:     "can suffix username and all groups",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username + ":username_suffix"`},
				&GroupsTransformation{Expression: `groups.map(g, g + ":group_suffix")`},
			},
			wantUsername: "ryan:username_suffix",
			wantGroups:   []string{"admins:group_suffix", "developers:group_suffix", "other:group_suffix"},
		},
		{
			name:     "can change case of username and all groups",
			username: "rYan 🚀",
			groups:   []string{"aDmins", "dEvelopers", "oTher"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username.lowerAscii()`},
				&GroupsTransformation{Expression: `groups.map(g, g.upperAscii())`},
			},
			wantUsername: "ryan 🚀",
			wantGroups:   []string{"ADMINS", "DEVELOPERS", "OTHER"},
		},
		{
			name:     "can replace whitespace",
			username: " r\ty a n \n",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username.replace(" ", "").replace("\n", "").replace("\t", "")`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "can filter groups based on an allow list",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.filter(g, g in ["admins", "developers"])`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers"},
		},
		{
			name:     "can filter groups based on an allow list provided as a const",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			consts: &TransformationConstants{
				StringListConstants: map[string][]string{"allowedGroups": {"admins", "developers"}},
			},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.filter(g, g in strListConst.allowedGroups)`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers"},
		},
		{
			name:     "can filter groups based on a disallow list",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.filter(g, !(g in ["admins", "developers"]))`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"other"},
		},
		{
			name:     "can filter groups based on a disallowed prefixes",
			username: "ryan",
			groups:   []string{"disallowed1:admins", "disallowed2:developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.filter(group, !(["disallowed1:", "disallowed2:"].exists(prefix, group.startsWith(prefix))))`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"other"},
		},
		{
			name:     "can filter groups based on a disallowed prefixes provided as a const",
			username: "ryan",
			groups:   []string{"disallowed1:admins", "disallowed2:developers", "other"},
			consts: &TransformationConstants{
				StringListConstants: map[string][]string{"disallowedPrefixes": {"disallowed1:", "disallowed2:"}},
			},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.filter(group, !(strListConst.disallowedPrefixes.exists(prefix, group.startsWith(prefix))))`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"other"},
		},
		{
			name:     "can add a group",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups + ["new-group"]`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other", "new-group"},
		},
		{
			name:     "can add a group from a const",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			consts: &TransformationConstants{
				StringConstants: map[string]string{"groupToAlwaysAdd": "new-group"},
			},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups + [strConst.groupToAlwaysAdd]`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other", "new-group"},
		},
		{
			name:     "can add a group but only if they already belong to another group - when the user does belong to that other group",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `"other" in groups ? groups + ["new-group"] : groups`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other", "new-group"},
		},
		{
			name:     "can add a group but only if they already belong to another group - when the user does NOT belong to that other group",
			username: "ryan",
			groups:   []string{"admins", "developers"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `"other" in groups ? groups + ["new-group"] : groups`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers"},
		},
		{
			name:     "can rename a group",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.map(g, g == "other" ? "other-renamed" : g)`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other-renamed"},
		},
		{
			name:     "can reject auth based on belonging to one group - when the user meets the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other", "super-admins"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `"super-admins" in groups`, RejectedAuthenticationMessage: `Only users who belong to the "super-admins" group are allowed`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other", "super-admins"},
		},
		{
			name:     "can reject auth based on belonging to one group - when the user does NOT meet the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `"super-admins" in groups`, RejectedAuthenticationMessage: `Only users who belong to the "super-admins" group are allowed`},
			},
			wantUsername:            "ryan",
			wantGroups:              []string{"admins", "developers", "other"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Only users who belong to the "super-admins" group are allowed`,
		},
		{
			name:     "can reject auth unless the user belongs to any one of the groups in a list - when the user meets the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "foobar", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `groups.exists(g, g in ["foobar", "foobaz", "foobat"])`, RejectedAuthenticationMessage: `Only users who belong to any of the groups in a list are allowed`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "foobar", "other"},
		},
		{
			name:     "can reject auth unless the user belongs to any one of the groups in a list - when the user does NOT meet the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `groups.exists(g, g in ["foobar", "foobaz", "foobat"])`, RejectedAuthenticationMessage: `Only users who belong to any of the groups in a list are allowed`},
			},
			wantUsername:            "ryan",
			wantGroups:              []string{"admins", "developers", "other"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Only users who belong to any of the groups in a list are allowed`,
		},
		{
			name:     "can reject auth unless the user belongs to all of the groups in a list - when the user meets the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other", "foobar", "foobaz", "foobat"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `["foobar", "foobaz", "foobat"].all(g, g in groups)`, RejectedAuthenticationMessage: `Only users who belong to all groups in a list are allowed`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other", "foobar", "foobaz", "foobat"},
		},
		{
			name:     "can reject auth unless the user belongs to all of the groups in a list - when the user does NOT meet the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other", "foobaz", "foobat"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `["foobar", "foobaz", "foobat"].all(g, g in groups)`, RejectedAuthenticationMessage: `Only users who belong to all groups in a list are allowed`},
			},
			wantUsername:            "ryan",
			wantGroups:              []string{"admins", "developers", "other", "foobaz", "foobat"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Only users who belong to all groups in a list are allowed`,
		},
		{
			name:     "can reject auth if the user belongs to any groups in a disallowed groups list - when the user meets the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `!groups.exists(g, g in ["foobar", "foobaz"])`, RejectedAuthenticationMessage: `Only users who do not belong to any of the groups in a list are allowed`},
			},
			wantUsername: "ryan",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "can reject auth if the user belongs to any groups in a disallowed groups list - when the user does NOT meet the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other", "foobaz"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `!groups.exists(g, g in ["foobar", "foobaz"])`, RejectedAuthenticationMessage: `Only users who do not belong to any of the groups in a list are allowed`},
			},
			wantUsername:            "ryan",
			wantGroups:              []string{"admins", "developers", "other", "foobaz"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Only users who do not belong to any of the groups in a list are allowed`,
		},
		{
			name:     "can reject auth unless the username is in an allowed users list - when the user meets the criteria",
			username: "foobaz",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `username in ["foobar", "foobaz"]`, RejectedAuthenticationMessage: `Only certain usernames allowed`},
			},
			wantUsername: "foobaz",
			wantGroups:   []string{"admins", "developers", "other"},
		},
		{
			name:     "can reject auth unless the username is in an allowed users list - when the user does NOT meet the criteria",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `username in ["foobar", "foobaz"]`, RejectedAuthenticationMessage: `Only certain usernames allowed`},
			},
			wantUsername:            "ryan",
			wantGroups:              []string{"admins", "developers", "other"},
			wantAuthRejected:        true,
			wantAuthRejectedMessage: `Only certain usernames allowed`,
		},

		//
		// Error cases
		//
		{
			name:     "username transformation returns an empty string as the new username",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `""`},
			},
			wantEvaluationErr: "identity transformation returned an empty username, which is not allowed",
		},
		{
			name:     "username transformation returns a string containing only whitespace as the new username",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `" \n \t "`},
			},
			wantEvaluationErr: "identity transformation returned an empty username, which is not allowed",
		},
		{
			name: "username transformation compiles to return null, which is not a string so it has the wrong type",
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `null`},
			},
			wantCompileErr: `CEL expression should return type "string" but returns type "null_type"`,
		},
		{
			name: "groups transformation compiles to return null, which is not a string so it has the wrong type",
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `null`},
			},
			wantCompileErr: `CEL expression should return type "list(string)" but returns type "null_type"`,
		},
		{
			name: "policy transformation compiles to return null, which is not a string so it has the wrong type",
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `null`},
			},
			wantCompileErr: `CEL expression should return type "bool" but returns type "null_type"`,
		},
		{
			name: "username transformation has empty expression",
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: ``},
			},
			wantCompileErr: `cannot compile empty CEL expression`,
		},
		{
			name: "groups transformation has empty expression",
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: ``},
			},
			wantCompileErr: `cannot compile empty CEL expression`,
		},
		{
			name: "policy transformation has empty expression",
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: ``},
			},
			wantCompileErr: `cannot compile empty CEL expression`,
		},
		{
			name: "username transformation has expression which contains only whitespace",
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: " \n\t "},
			},
			wantCompileErr: `cannot compile empty CEL expression`,
		},
		{
			name: "groups transformation has expression which contains only whitespace",
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: " \n\t "},
			},
			wantCompileErr: `cannot compile empty CEL expression`,
		},
		{
			name: "policy transformation has expression which contains only whitespace",
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: " \n\t "},
			},
			wantCompileErr: `cannot compile empty CEL expression`,
		},
		{
			name:     "slow username transformation expressions are canceled by the cancel context after partial evaluation",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `groups.filter(x, groups.all(x, true))[0]`},
			},
			ctx:               alreadyCancelledContext,
			wantEvaluationErr: `identity transformation at index 0: operation interrupted`,
		},
		{
			name:     "slow groups transformation expressions are canceled by the cancel context after partial evaluation",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.filter(x, groups.all(x, true))`},
			},
			ctx:               alreadyCancelledContext,
			wantEvaluationErr: `identity transformation at index 0: operation interrupted`,
		},
		{
			name:     "slow policy expressions are canceled by the cancel context after partial evaluation",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: "username"},
				&AllowAuthenticationPolicy{Expression: `groups.all(x, groups.all(x, true))`}, // this is the slow one
			},
			ctx:               alreadyCancelledContext,
			wantEvaluationErr: `identity transformation at index 1: operation interrupted`,
		},
		{
			name:     "slow transformation expressions are canceled and the rest of the expressions do not run",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username`}, // quick expressions are allowed to run even though the context is cancelled
				&UsernameTransformation{Expression: `groups.filter(x, groups.all(x, true))[0]`},
				&UsernameTransformation{Expression: `groups.filter(x, groups.all(x, true))[0]`},
				&UsernameTransformation{Expression: `groups.filter(x, groups.all(x, true))[0]`},
			},
			ctx:               alreadyCancelledContext,
			wantEvaluationErr: `identity transformation at index 1: operation interrupted`,
		},
		{
			name:     "slow username transformation expressions are canceled after a maximum allowed duration",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				// On my laptop, evaluating this expression would take ~20 seconds if we allowed it to evaluate to completion.
				&UsernameTransformation{Expression: `groups.filter(x, groups.all(x, true))[0]`},
			},
			wantEvaluationErr: `identity transformation at index 0: operation interrupted`,
		},
		{
			name:     "slow groups transformation expressions are canceled after a maximum allowed duration",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				// On my laptop, evaluating this expression would take ~20 seconds if we allowed it to evaluate to completion.
				&GroupsTransformation{Expression: `groups.filter(x, groups.all(x, true))`},
			},
			wantEvaluationErr: `identity transformation at index 0: operation interrupted`,
		},
		{
			name:     "slow policy transformation expressions are canceled after a maximum allowed duration",
			username: "ryan",
			groups:   veryLargeGroupList,
			transforms: []CELTransformation{
				// On my laptop, evaluating this expression would take ~20 seconds if we allowed it to evaluate to completion.
				&AllowAuthenticationPolicy{Expression: `groups.all(x, groups.all(x, true))`},
			},
			wantEvaluationErr: `identity transformation at index 0: operation interrupted`,
		},
		{
			name: "compile errors are returned by the compile step for a username transform",
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `foobar.junk()`},
			},
			wantCompileErr: here.Doc(`
				CEL expression compile error: ERROR: <input>:1:1: undeclared reference to 'foobar' (in container '')
				 | foobar.junk()
				 | ^
				ERROR: <input>:1:12: undeclared reference to 'junk' (in container '')
				 | foobar.junk()
				 | ...........^`,
			),
		},
		{
			name: "compile errors are returned by the compile step for a groups transform",
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `foobar.junk()`},
			},
			wantCompileErr: here.Doc(`
				CEL expression compile error: ERROR: <input>:1:1: undeclared reference to 'foobar' (in container '')
				 | foobar.junk()
				 | ^
				ERROR: <input>:1:12: undeclared reference to 'junk' (in container '')
				 | foobar.junk()
				 | ...........^`,
			),
		},
		{
			name: "compile errors are returned by the compile step for a policy",
			transforms: []CELTransformation{
				&AllowAuthenticationPolicy{Expression: `foobar.junk()`},
			},
			wantCompileErr: here.Doc(`
				CEL expression compile error: ERROR: <input>:1:1: undeclared reference to 'foobar' (in container '')
				 | foobar.junk()
				 | ^
				ERROR: <input>:1:12: undeclared reference to 'junk' (in container '')
				 | foobar.junk()
				 | ...........^`,
			),
		},
		{
			name:     "evaluation errors stop the pipeline and return an error",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: "username"},
				&AllowAuthenticationPolicy{Expression: `1 / 0 == 7`},
			},
			wantEvaluationErr: `identity transformation at index 1: division by zero`,
		},
		{
			name:     "HomogeneousAggregateLiterals compiler setting is enabled to help the user avoid type mistakes in expressions",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.all(g, g in ["admins", 1])`},
			},
			wantCompileErr: here.Doc(`
				CEL expression compile error: ERROR: <input>:1:31: expected type 'string' but found 'int'
				 | groups.all(g, g in ["admins", 1])
				 | ..............................^`,
			),
		},
		{
			name:     "when an expression's type cannot be determined at compile time, e.g. due to the use of dynamic types",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `groups.map(g, {"admins": dyn(1), "developers":"a"}[g])`},
			},
			wantCompileErr: `CEL expression should return type "list(string)" but returns type "list(dyn)"`,
		},
		{
			name:     "using string constants which were not were provided",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `strConst.x`},
			},
			wantEvaluationErr: `identity transformation at index 0: no such key: x`,
		},
		{
			name:     "using string list constants which were not were provided",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			transforms: []CELTransformation{
				&GroupsTransformation{Expression: `strListConst.x`},
			},
			wantEvaluationErr: `identity transformation at index 0: no such key: x`,
		},
		{
			name:     "using an illegal name for a string constant",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			consts:   &TransformationConstants{StringConstants: map[string]string{" illegal": "a"}},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username`},
			},
			wantCompileErr: `" illegal" is an invalid const variable name (must match [_a-zA-Z][_a-zA-Z0-9]*)`,
		},
		{
			name:     "using an illegal name for a stringList constant",
			username: "ryan",
			groups:   []string{"admins", "developers", "other"},
			consts:   &TransformationConstants{StringListConstants: map[string][]string{" illegal": {"a"}}},
			transforms: []CELTransformation{
				&UsernameTransformation{Expression: `username`},
			},
			wantCompileErr: `" illegal" is an invalid const variable name (must match [_a-zA-Z][_a-zA-Z0-9]*)`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			transformer, err := NewCELTransformer(100 * time.Millisecond)
			require.NoError(t, err)

			pipeline := idtransform.NewTransformationPipeline()

			for _, transform := range tt.transforms {
				compiledTransform, err := transformer.CompileTransformation(transform, tt.consts)
				if tt.wantCompileErr != "" {
					require.EqualError(t, err, tt.wantCompileErr)
					return // the rest of the test doesn't make sense when there was a compile error
				}
				require.NoError(t, err, "got an unexpected compile error")
				pipeline.AppendTransformation(compiledTransform)
			}

			ctx := context.Background()
			if tt.ctx != nil {
				ctx = tt.ctx
			}

			result, err := pipeline.Evaluate(ctx, tt.username, tt.groups)
			if tt.wantEvaluationErr != "" {
				require.EqualError(t, err, tt.wantEvaluationErr)
				return // the rest of the test doesn't make sense when there was an evaluation error
			}
			require.NoError(t, err, "got an unexpected evaluation error")

			require.Equal(t, tt.wantUsername, result.Username)
			require.Equal(t, tt.wantGroups, result.Groups)
			require.Equal(t, !tt.wantAuthRejected, result.AuthenticationAllowed, "AuthenticationAllowed had unexpected value")
			require.Equal(t, tt.wantAuthRejectedMessage, result.RejectedAuthenticationMessage)
		})
	}
}

func TestTypicalPerformanceAndThreadSafety(t *testing.T) {
	t.Parallel()

	transformer, err := NewCELTransformer(100 * time.Millisecond)
	require.NoError(t, err)

	pipeline := idtransform.NewTransformationPipeline()

	var compiledTransform idtransform.IdentityTransformation
	compiledTransform, err = transformer.CompileTransformation(&UsernameTransformation{Expression: `"username_prefix:" + username`}, nil)
	require.NoError(t, err)
	pipeline.AppendTransformation(compiledTransform)
	compiledTransform, err = transformer.CompileTransformation(&GroupsTransformation{Expression: `groups.map(g, "group_prefix:" + g)`}, nil)
	require.NoError(t, err)
	pipeline.AppendTransformation(compiledTransform)
	compiledTransform, err = transformer.CompileTransformation(&AllowAuthenticationPolicy{Expression: `username == "username_prefix:ryan"`}, nil)
	require.NoError(t, err)
	pipeline.AppendTransformation(compiledTransform)

	var groups []string
	var wantGroups []string
	for i := 0; i < 100; i++ {
		groups = append(groups, fmt.Sprintf("g%d", i))
		wantGroups = append(wantGroups, fmt.Sprintf("group_prefix:g%d", i))
	}

	// Before looking at performance, check that the behavior of the function is correct.
	result, err := pipeline.Evaluate(context.Background(), "ryan", groups)
	require.NoError(t, err)
	require.Equal(t, "username_prefix:ryan", result.Username)
	require.Equal(t, wantGroups, result.Groups)
	require.True(t, result.AuthenticationAllowed)
	require.Empty(t, result.RejectedAuthenticationMessage)

	// This loop is meant to give a sense of typical runtime of CEL expressions which transforms a username
	// and 100 group names. It is not meant to be a pass/fail test or scientific benchmark test.
	iterations := 1000
	start := time.Now()
	for i := 0; i < iterations; i++ {
		_, _ = pipeline.Evaluate(context.Background(), "ryan", groups)
	}
	elapsed := time.Since(start)
	t.Logf("TestTypicalPerformanceAndThreadSafety %d iterations of Evaluate took %s; average runtime %s", iterations, elapsed, elapsed/time.Duration(iterations))
	// On my laptop this prints: TestTypicalPerformanceAndThreadSafety 1000 iterations of Evaluate took 257.981421ms; average runtime 257.981µs

	// Now use the transformations pipeline from different goroutines at the same time. Hopefully the race detector
	// will complain if this is not thread safe in some way. Use the pipeline enough that it will be very likely that
	// there will be several parallel invocations of the Evaluate function. Every invocation should also yield the
	// exact same result, since they are all using the same inputs. This assumes that the unit tests are run using
	// the race detector.
	var wg sync.WaitGroup
	numGoroutines := 10
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1) // increment WaitGroup counter for each goroutine
		go func() {
			defer wg.Done() // decrement WaitGroup counter when this goroutine finishes
			for j := 0; j < iterations*2; j++ {
				localResult, localErr := pipeline.Evaluate(context.Background(), "ryan", groups)
				require.NoError(t, localErr)
				require.Equal(t, "username_prefix:ryan", localResult.Username)
				require.Equal(t, wantGroups, localResult.Groups)
				require.True(t, localResult.AuthenticationAllowed)
				require.Empty(t, localResult.RejectedAuthenticationMessage)
			}
		}()
	}
	wg.Wait() // wait for the counter to reach zero, indicating the all goroutines are finished
}
