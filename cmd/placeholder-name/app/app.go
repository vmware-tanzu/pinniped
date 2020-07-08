/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package app is the command line entry point for placeholder-name.
package app

import (
	"io"
	"log"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app/config"
	"github.com/suzerain-io/placeholder-name/pkg/handlers"
)

// App is an object that represents the placeholder-name application.
type App struct {
	cmd *cobra.Command

	// runFunc runs the actual program, after the parsing of flags has been done.
	//
	// It is mostly a field for the sake of testing.
	runFunc func(configPath string)
}

// New constructs a new App with command line args, stdout and stderr.
func New(args []string, stdout, stderr io.Writer) *App {
	a := &App{
		runFunc: func(configPath string) {
			config, err := config.FromPath(configPath)
			if err != nil {
				log.Fatalf("could not load config: %v", err)
			}
			_ = config // TODO(akeesler): use me!

			addr := ":8080"
			log.Printf("Starting server on %v", addr)
			log.Fatal(http.ListenAndServe(addr, handlers.New()))
		},
	}

	var configPath string
	cmd := &cobra.Command{
		Use: `placeholder-name`,
		Long: `placeholder-name provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.`,
		Run: func(cmd *cobra.Command, args []string) {
			a.runFunc(configPath)
		},
		Args: cobra.NoArgs,
	}

	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	cmd.Flags().StringVarP(
		&configPath,
		"config",
		"c",
		"placeholder-name.yaml",
		"path to configuration file",
	)

	a.cmd = cmd

	return a
}

func (a *App) Run() error {
	return a.cmd.Execute()
}
