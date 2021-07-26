// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main is the combined entrypoint for all Pinniped server components.
//
// It dispatches to the appropriate Main() entrypoint based the name it is invoked as (os.Args[0]). In our server
// container image, this binary is symlinked to several names such as `/usr/local/bin/pinniped-concierge`.
package main

import (
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"

	concierge "go.pinniped.dev/internal/concierge/server"
	lua "go.pinniped.dev/internal/localuserauthenticator"
	supervisor "go.pinniped.dev/internal/supervisor/server"
)

//nolint: gochecknoglobals // these are swapped during unit tests.
var (
	fail        = klog.Fatalf
	subcommands = map[string]func(){
		"pinniped-concierge":       concierge.Main,
		"pinniped-supervisor":      supervisor.Main,
		"local-user-authenticator": lua.Main,
	}
)

func main() {
	if len(os.Args) == 0 {
		fail("missing os.Args")
	}
	binary := filepath.Base(os.Args[0])
	if subcommands[binary] == nil {
		fail("must be invoked as one of %v, not %q", sets.StringKeySet(subcommands).List(), binary)
	}
	subcommands[binary]()
}
