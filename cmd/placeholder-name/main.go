/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	genericapiserver "k8s.io/apiserver/pkg/server"
	"os"

	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	stopCh := genericapiserver.SetupSignalHandler()

	if err := app.New(os.Args[1:], os.Stdout, os.Stderr, stopCh).Run(); err != nil {
		klog.Fatal(err)
	}
}
