/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	ctx := genericapiserver.SetupSignalContext()

	if err := app.New(ctx, os.Args[1:], os.Stdout, os.Stderr).Run(); err != nil {
		klog.Fatal(err)
	}
}
