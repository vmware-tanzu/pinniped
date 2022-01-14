// Copyright 2020-2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"fmt"

	"k8s.io/klog/v2"
)

// KObj is (mostly) copied from klog - it is a standard way to represent a metav1.Object in logs.
func KObj(obj klog.KMetadata) string {
	return fmt.Sprintf("%s/%s", obj.GetNamespace(), obj.GetName())
}

func klogLevelForPlogLevel(plogLevel LogLevel) klog.Level {
	switch plogLevel {
	case LevelWarning:
		return klogLevelWarning // unset means minimal logs (Error and Warning)
	case LevelInfo:
		return klogLevelInfo
	case LevelDebug:
		return klogLevelDebug
	case LevelTrace:
		return klogLevelTrace
	case LevelAll:
		return klogLevelAll + 100 // make all really mean all
	default:
		return -1
	}
}
