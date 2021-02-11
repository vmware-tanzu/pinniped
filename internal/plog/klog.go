// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"fmt"
	"sync"

	"github.com/spf13/pflag"
	"k8s.io/klog/v2"
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

// KRef is (mostly) copied from klog - it is a standard way to represent a a metav1.Object in logs
// when you only have access to the namespace and name of the object.
func KRef(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

// KObj is (mostly) copied from klog - it is a standard way to represent a metav1.Object in logs.
func KObj(obj klog.KMetadata) string {
	return fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
}

func klogLevelForPlogLevel(plogLevel LogLevel) (klogLevel klog.Level) {
	switch plogLevel {
	case LevelWarning:
		klogLevel = klogLevelWarning // unset means minimal logs (Error and Warning)
	case LevelInfo:
		klogLevel = klogLevelInfo
	case LevelDebug:
		klogLevel = klogLevelDebug
	case LevelTrace:
		klogLevel = klogLevelTrace
	case LevelAll:
		klogLevel = klogLevelAll + 100 // make all really mean all
	default:
		klogLevel = -1
	}

	return
}

func getKlogLevel() klog.Level {
	// hack around klog not exposing a Get method
	for i := klog.Level(0); i < 256; i++ {
		if klog.V(i).Enabled() {
			continue
		}
		return i - 1
	}

	return -1
}
