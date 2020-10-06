// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestMustMarkRequired(t *testing.T) {
	require.NotPanics(t, func() { mustMarkRequired(&cobra.Command{}) })
	require.NotPanics(t, func() {
		cmd := &cobra.Command{}
		cmd.Flags().String("known-flag", "", "")
		mustMarkRequired(cmd, "known-flag")
	})
	require.Panics(t, func() { mustMarkRequired(&cobra.Command{}, "unknown-flag") })
}
