// Copyright 2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package pversion

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/coreos/go-semver/semver"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
	k8sstrings "k8s.io/utils/strings"
)

// readBuildInfo is meant to be overwritten by tests.
//
//nolint:gochecknoglobals // these are swapped during unit tests.
var readBuildInfo = debug.ReadBuildInfo

// gitVersion is set using a linker flag
// -ldflags "-X 'go.pinniped.dev/internal/pversion.gitVersion=v9.8.7'"
// (or set for unit tests).
//
//nolint:gochecknoglobals // these are swapped during unit tests.
var gitVersion string

// Get returns the overall codebase version. It's for detecting
// what code a binary was built from.
//
// This function is very similar to the function defined in k8s.io/component-base (version/version.go)
// but is designed to work with golang's VCS build-time information.
//
// See:
// - https://github.com/kubernetes/component-base/blob/v0.28.0/version/version.go#L26-L42
// - https://tip.golang.org/doc/go1.18#go-version
func Get() apimachineryversion.Info {
	info := apimachineryversion.Info{
		Major:        "0",
		Minor:        "0",
		GitVersion:   "v0.0.0",
		GitTreeState: "dirty",
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}

	gitVersionWithoutLeadingV := gitVersion
	if strings.HasPrefix(gitVersion, "v") {
		gitVersionWithoutLeadingV, _ = strings.CutPrefix(gitVersion, "v")
	}

	gitVersionSemver, err := semver.NewVersion(gitVersionWithoutLeadingV)
	if err == nil && gitVersionSemver != nil {
		info.GitVersion = gitVersion
		info.Major = fmt.Sprintf("%d", gitVersionSemver.Major)
		info.Minor = fmt.Sprintf("%d", gitVersionSemver.Minor)
	}

	if debugBuildInfo, ok := readBuildInfo(); ok {
		for _, buildSetting := range debugBuildInfo.Settings {
			switch buildSetting.Key {
			case "vcs.revision":
				info.GitCommit = buildSetting.Value
			case "vcs.time":
				info.BuildDate = buildSetting.Value
			case "vcs.modified":
				if buildSetting.Value == "false" {
					info.GitTreeState = "clean"
				}
			}
		}
	}

	if info.GitVersion == "v0.0.0" && info.GitCommit != "" {
		info.GitVersion += fmt.Sprintf("-%s-%s",
			k8sstrings.ShortenString(info.GitCommit, 8),
			info.GitTreeState)
	}

	return info
}
