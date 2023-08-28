// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pversion

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/require"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
)

func TestGet(t *testing.T) {
	originalGitVersion := gitVersion
	t.Cleanup(func() {
		gitVersion = originalGitVersion
		readBuildInfo = debug.ReadBuildInfo
	})

	t.Run("when readBuildInfo() returns not ok", func(t *testing.T) {
		gitVersion = ""
		readBuildInfo = func() (info *debug.BuildInfo, ok bool) {
			return nil, false
		}

		info := apimachineryversion.Info{
			Major:        "0",
			Minor:        "0",
			GitVersion:   "v0.0.0",
			GitTreeState: "dirty",
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		}
		require.Equal(t, info, Get())
	})

	t.Run("when readBuildInfo() returns ok", func(t *testing.T) {
		gitVersion = "9.8.7"
		readBuildInfo = func() (info *debug.BuildInfo, ok bool) {
			buildInfo := debug.BuildInfo{
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "revision-value"},
					{Key: "vcs.time", Value: "time-value"},
					{Key: "vcs.modified", Value: "anything but 'true'"},
					{Key: "other", Value: "ignored"},
				},
			}
			return &buildInfo, true
		}

		expected := apimachineryversion.Info{
			Major:        "9",
			Minor:        "8",
			GitVersion:   "9.8.7",
			GitCommit:    "revision-value",
			GitTreeState: "dirty",
			BuildDate:    "time-value",
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		}

		require.Equal(t, expected, Get())
	})

	t.Run("when readBuildInfo() returns ok but gitVersion is not provided", func(t *testing.T) {
		gitVersion = ""
		readBuildInfo = func() (info *debug.BuildInfo, ok bool) {
			buildInfo := debug.BuildInfo{
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "384850953501b7d66d466b4ca4d13a81bc54a7c3"},
					{Key: "vcs.time", Value: "time-value"},
					{Key: "vcs.modified", Value: "anything but 'true'"},
					{Key: "other", Value: "ignored"},
				},
			}
			return &buildInfo, true
		}

		expected := apimachineryversion.Info{
			Major:        "0",
			Minor:        "0",
			GitVersion:   "v0.0.0-38485095-dirty",
			GitCommit:    "384850953501b7d66d466b4ca4d13a81bc54a7c3",
			GitTreeState: "dirty",
			BuildDate:    "time-value",
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		}

		require.Equal(t, expected, Get())
	})

	t.Run("when gitVersion is complex", func(t *testing.T) {
		gitVersion = "v1.2.3-abc123"
		readBuildInfo = func() (info *debug.BuildInfo, ok bool) {
			buildInfo := debug.BuildInfo{
				Settings: []debug.BuildSetting{
					{Key: "vcs.revision", Value: "abc123"},
					{Key: "vcs.time", Value: "time-value"},
					{Key: "vcs.modified", Value: "false"},
					{Key: "other", Value: "ignored"},
				},
			}
			return &buildInfo, true
		}

		expected := apimachineryversion.Info{
			Major:        "1",
			Minor:        "2",
			GitVersion:   "v1.2.3-abc123",
			GitCommit:    "abc123",
			GitTreeState: "clean",
			BuildDate:    "time-value",
			GoVersion:    runtime.Version(),
			Compiler:     runtime.Compiler,
			Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		}

		require.Equal(t, expected, Get())
	})
}
