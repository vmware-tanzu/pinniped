package cmd

import (
	"flag"
	"os"
	"runtime"

	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"

	"github.com/suzerain-io/placeholder-name/pkg/cmd/server"
)

func RunPlaceHolderServer() {
	logs.InitLogs()
	defer logs.FlushLogs()

	// TODO do we need this?
	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	stopCh := genericapiserver.SetupSignalHandler()

	cmd := server.NewCommandStartPlaceHolderServer(os.Stdout, os.Stderr, stopCh)
	cmd.Flags().AddGoFlagSet(flag.CommandLine)
	if err := cmd.Execute(); err != nil {
		klog.Fatal(err)
	}
}
