/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"

	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/placeholder-name/cmd/placeholder-name/app"
)

func main() {
	klog.Infof("Running %s at %#v", rest.DefaultKubernetesUserAgent(), version.Get())
	if err := app.New(os.Args[1:], os.Stdout, os.Stderr).Run(); err != nil {
		os.Exit(1)
	}
}
