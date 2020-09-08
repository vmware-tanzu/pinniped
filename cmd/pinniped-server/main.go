/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"os"
	"time"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/client-go/pkg/version"
	"k8s.io/client-go/rest"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/pinniped/internal/server"
)

func main() {
	logs.InitLogs()
	defer logs.FlushLogs()

	// Dump out the time since compile (mostly useful for benchmarking our local development cycle latency).
	var timeSinceCompile time.Duration
	if buildDate, err := time.Parse(time.RFC3339, version.Get().BuildDate); err == nil {
		timeSinceCompile = time.Since(buildDate)
	}
	klog.Infof("Running %s at %#v (%s since build)", rest.DefaultKubernetesUserAgent(), version.Get(), timeSinceCompile)

	ctx := genericapiserver.SetupSignalContext()

	if err := server.New(ctx, os.Args[1:], os.Stdout, os.Stderr).Run(); err != nil {
		klog.Fatal(err)
	}
}
