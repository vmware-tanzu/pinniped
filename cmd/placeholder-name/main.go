/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app"
)

func main() {
	if err := app.New(os.Args[1:], os.Stdout, os.Stderr).Run(); err != nil {
		os.Exit(1)
	}
}
