// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"sync"

	"github.com/spf13/pflag"
)

//nolint: gochecknoglobals
var removeKlogGlobalFlagsLock sync.Mutex

// RemoveKlogGlobalFlags attempts to "remove" flags that get unconditionally added by importing klog.
func RemoveKlogGlobalFlags() {
	// since we mess with global state, we need a lock to synchronize us when called in parallel during tests
	removeKlogGlobalFlagsLock.Lock()
	defer removeKlogGlobalFlagsLock.Unlock()

	// if this function starts to panic, it likely means that klog stopped mucking with global flags
	const globalLogFlushFlag = "log-flush-frequency"
	if err := pflag.CommandLine.MarkHidden(globalLogFlushFlag); err != nil {
		panic(err)
	}
	if err := pflag.CommandLine.MarkDeprecated(globalLogFlushFlag, "unsupported"); err != nil {
		panic(err)
	}
	if pflag.CommandLine.Changed(globalLogFlushFlag) {
		panic("unsupported global klog flag set")
	}
}
