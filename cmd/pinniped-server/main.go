// Copyright 2021-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main is the combined entrypoint for all Pinniped server components.
//
// It dispatches to the appropriate Main() entrypoint based the name it is invoked as (os.Args[0]). In our server
// container image, this binary is symlinked to several names such as `/usr/local/bin/pinniped-concierge`.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/apimachinery/pkg/util/sets"

	concierge "go.pinniped.dev/internal/concierge/server"
	// this side effect import ensures that we use fipsonly crypto in boringcrypto mode.
	_ "go.pinniped.dev/internal/crypto/ptls"
	lua "go.pinniped.dev/internal/localuserauthenticator"
	"go.pinniped.dev/internal/plog"
	supervisor "go.pinniped.dev/internal/supervisor/server"
)

//nolint:gochecknoglobals // these are swapped during unit tests.
var (
	fail        = plog.Fatal
	subcommands = map[string]func(){
		"pinniped-concierge":       concierge.Main,
		"pinniped-supervisor":      supervisor.Main,
		"local-user-authenticator": lua.Main,
	}
)

func main() {
	if len(os.Args) == 0 {
		fail(fmt.Errorf("missing os.Args"))
	}
	binary := filepath.Base(os.Args[0])
	if subcommands[binary] == nil {
		fail(fmt.Errorf("must be invoked as one of %v, not %q", sets.StringKeySet(subcommands).List(), binary))
	}
	subcommands[binary]()
}
