// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package controllerlib

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/events"

	"go.pinniped.dev/internal/plog"
)

var _ events.EventRecorder = klogRecorder{}

type klogRecorder struct{}

func (n klogRecorder) Eventf(regarding runtime.Object, related runtime.Object, eventtype, reason, action, note string, args ...any) {
	plog.Debug("recording event",
		"regarding", regarding,
		"related", related,
		"eventtype", eventtype,
		"reason", reason,
		"action", action,
		"message", fmt.Sprintf(note, args...),
	)
}
