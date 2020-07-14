/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app"
	"github.com/suzerain-io/placeholder-name/pkg/cmd"
)

func main() {
	// TODO need to remove the hello world stuff
	if os.Getenv("PLACEHOLDER_NAME_API_SERVER") == "1" {
		cmd.RunPlaceHolderServer()
	}

	if err := app.New(os.Args[1:], os.Stdout, os.Stderr).Run(); err != nil {
		os.Exit(1)
	}
}
