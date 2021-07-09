// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package starformer is an implementation of UpstreamToDownstreamTransformer using Starlark scripts.
// See Starlark dialect language documentation here: https://github.com/google/starlark-go/blob/master/doc/spec.md
// A video introduction to Starlark and how to integrate it into projects is here: https://www.youtube.com/watch?v=9P_YKVhncWI
package starformer

import (
	"fmt"

	"go.starlark.net/lib/json"
	starlarkmath "go.starlark.net/lib/math"
	"go.starlark.net/lib/time"
	"go.starlark.net/resolve"
	"go.starlark.net/starlark"

	"go.pinniped.dev/internal/plog"
)

const (
	maxExecutionSteps     = 10000000
	transformFunctionName = "transform"
)

// Configure some global variables in starlark-go.
// nolint:gochecknoinits // wish these weren't globals but oh well
func init() {
	// Allow the non-standard "set" data structure to be used.
	resolve.AllowSet = true

	// Note that we could allow "while" statements and recursive functions, but the language already
	// has "for" loops so it seems unnecessary for our use case. This is currently the default
	// value in starlark-go but repeating it here as documentation.
	resolve.AllowRecursion = false
}

type Transformer struct {
	hook *starlark.Function
}

// New creates an instance of Transformer. Given some Starlark source code as a string, it loads the code.
// If there is any error during loading, it will return the error. It expects the loaded code to define
// a Starlark function called "transform" which should take two positional arguments. The returned
// Transformer can be safely called from multiple threads simultaneously, no matter how the Starlark
// source code was written, because the Starlark module has been frozen (made immutable).
func New(starlarkSourceCode string) (*Transformer, error) {
	// Create a Starlark thread in which the source will be loaded.
	thread := &starlark.Thread{
		Name: "starlark script loader",
		Print: func(thread *starlark.Thread, msg string) {
			// When the script has a top-level print(), send it to the server log.
			plog.Debug("debug message while loading starlark transform script", "msg", msg)
		},
		Load: func(thread *starlark.Thread, module string) (starlark.StringDict, error) {
			// Allow starlark-go's custom built-in modules to be loaded by scripts if they desire.
			switch module {
			case "json.star":
				return starlark.StringDict{"json": json.Module}, nil
			case "time.star":
				return starlark.StringDict{"time": time.Module}, nil
			case "math.star":
				return starlark.StringDict{"math": starlarkmath.Module}, nil
			default:
				// Don't allow any other file to be loaded.
				return nil, fmt.Errorf("only the following modules may be loaded: json.star, time.star, math.star")
			}
		},
	}

	// Prevent the top-level statements of the Starlark script from accidentally running forever.
	thread.SetMaxExecutionSteps(maxExecutionSteps)

	// Start with empty predeclared names, aside from the built-ins.
	predeclared := starlark.StringDict{}

	// Load a Starlark script. Initialization of a script runs its top-level statements from top to bottom,
	// and then "freezes" all of the values making them immutable. The result can be used in multiple threads
	// simultaneously without interfering, communicating, or racing with each other. The filename given here
	// will appear in some Starlark error messages.
	globals, err := starlark.ExecFile(thread, "transform.star", starlarkSourceCode, predeclared)
	if err != nil {
		return nil, fmt.Errorf("error while loading starlark transform script: %w", err)
	}

	// Get the function called "transform" from the global state of the module that was just loaded.
	hook, _ := globals[transformFunctionName].(*starlark.Function)
	if hook == nil {
		return nil, fmt.Errorf("starlark script does not define %q function", transformFunctionName)
	}

	// Check that the "transform" function takes the expected number of arguments so we can call it later.
	if hook.NumParams() != 2 {
		return nil, fmt.Errorf("starlark script's global %q function has %d parameters but should have 2", transformFunctionName, hook.NumParams())
	}

	return &Transformer{hook: hook}, nil
}

// Transform calls the Starlark "transform" function that was loaded by New. The username and groups params are
// passed into the Starlark function, and the return values of the Starlark function are returned. If there is an error
// during the call to the Starlark function (either a programming error, a runtime error, or an intentional call to
// Starlark's `fail` built-in function) then Transform will return the error. This function is thread-safe.
// The runtime of this function depends on the complexity of the Starlark source code, but for a typical Starlark
// function will be something on the order of 50µs on a modern laptop.
func (t *Transformer) Transform(username string, groups []string) (string, []string, error) {
	// TODO: maybe add a context param for cancellation, which is supported in starlark-go by
	//  calling thread.Cancel() from any goroutine, or maybe this doesn't matter because there is
	//  already a maxExecutionSteps so scripts are guaranteed to finish within a reasonable time.

	// Create a Starlark thread in which the function will be called.
	thread := &starlark.Thread{
		Name: "starlark script executor",
		Print: func(thread *starlark.Thread, msg string) {
			// When the script's 'transform' function has a print(), send it to the server log.
			plog.Debug("debug message while running starlark transform script", "msg", msg)
		},
	}

	// Prevent the Starlark function from accidentally running forever.
	thread.SetMaxExecutionSteps(maxExecutionSteps)

	// Prepare the function arguments as Starlark values.
	groupsTuple := starlark.Tuple{}
	for _, group := range groups {
		groupsTuple = append(groupsTuple, starlark.String(group))
	}
	args := starlark.Tuple{starlark.String(username), groupsTuple}

	// Call the Starlark hook function in the new thread and pass the arguments.
	// Get back the function's return value or an error.
	hookReturnValue, err := starlark.Call(thread, t.hook, args, nil)

	// Errors could be programming mistakes in the script, or could be an intentional usage of the `fail` built-in.
	// Either way, return an error to reject the login.
	if err != nil {
		return "", nil, fmt.Errorf("error while running starlark %q function: %w", transformFunctionName, err)
	}

	// The special Starlark value 'None' is interpreted here as a shortcut to mean make no edits.
	if hookReturnValue == starlark.None {
		return username, groups, nil
	}

	// TODO: maybe offer a way for the user to reject a login with a nice error message which we can distinguish from
	//  an accidental coding error, for example by returning a single string from their 'transform' function instead
	//  of a tuple, or by returning a special value that we set up in the module's state in advance like
	//  `return rejectAuthentication(message)`

	// Otherwise the function should have returned a tuple with two values.
	returnedTuple, ok := hookReturnValue.(starlark.Tuple)
	if !ok || returnedTuple.Len() != 2 {
		return "", nil, fmt.Errorf("expected starlark %q function to return None or a Tuple of length 2", transformFunctionName)
	}

	// The first value in the returned tuple is the username. Turn it back into a golang string.
	transformedUsername, ok := starlark.AsString(returnedTuple.Index(0))
	if !ok || len(transformedUsername) == 0 {
		return "", nil, fmt.Errorf("expected starlark %q function's return tuple to have a non-empty string as the first value", transformFunctionName)
	}

	// The second value in the returned tuple is an iterable of group names.
	returnedGroups, ok := returnedTuple.Index(1).(starlark.Iterable)
	if !ok {
		return "", nil, fmt.Errorf("expected starlark %q function's return tuple to have an iterable value as the second value", transformFunctionName)
	}

	// Turn the returned iterable of group names back into a golang []string, including turning an empty iterable into an empty slice.
	transformedGroupNames := []string{}
	groupsIterator := returnedGroups.Iterate()
	defer groupsIterator.Done()
	var transformedGroup starlark.Value
	for groupsIterator.Next(&transformedGroup) {
		transformedGroupName, ok := starlark.AsString(transformedGroup)
		if !ok || len(transformedGroupName) == 0 {
			return "", nil, fmt.Errorf("expected starlark %q function's return tuple's second value to contain only non-empty strings", transformFunctionName)
		}
		transformedGroupNames = append(transformedGroupNames, transformedGroupName)
	}

	// Got username and group names, so return them as the transformed values.
	return transformedUsername, transformedGroupNames, nil
}
