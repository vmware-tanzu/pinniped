// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package apigroup

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
)

func TestMakeError(t *testing.T) {
	_, ok := Make("bad-suffix", "shouldnt-matter.com")
	require.False(t, ok)
}

func TestMakeSuffix(t *testing.T) {
	s, ok := Make("something.pinniped.dev.something-else.pinniped.dev", "tuna.io")
	require.Equal(t, "something.pinniped.dev.something-else.tuna.io", s)
	require.True(t, ok)
}

func Example_loginv1alpha1() {
	s, _ := Make(loginv1alpha1.GroupName, "tuna.fish.io")
	fmt.Println(s)
	// Output: login.concierge.tuna.fish.io
}

func Example_string() {
	s, _ := Make("idp.supervisor.pinniped.dev", "marlin.io")
	fmt.Println(s)
	// Output: idp.supervisor.marlin.io
}
