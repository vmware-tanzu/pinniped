// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package plog

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/component-base/logs"
	"k8s.io/klog/v2"
)

func TestValidateAndSetLogLevelGlobally(t *testing.T) {
	originalLogLevel := getKlogLevel(t)

	tests := []struct {
		name      string
		level     LogLevel
		wantLevel klog.Level
		wantErr   string
	}{
		{
			name:      "unset",
			wantLevel: 0,
		},
		{
			name:      "warning",
			level:     LevelWarning,
			wantLevel: 0,
		},
		{
			name:      "info",
			level:     LevelInfo,
			wantLevel: 2,
		},
		{
			name:      "debug",
			level:     LevelDebug,
			wantLevel: 4,
		},
		{
			name:      "trace",
			level:     LevelTrace,
			wantLevel: 6,
		},
		{
			name:      "all",
			level:     LevelAll,
			wantLevel: 108,
		},
		{
			name:      "invalid level",
			level:     "panda",
			wantLevel: originalLogLevel,
			wantErr:   errInvalidLogLevel.Error(),
		},
	}
	for _, tt := range tests {
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				undoGlobalLogLevelChanges(t, originalLogLevel)
			}()

			err := ValidateAndSetLogLevelGlobally(tt.level)
			require.Equal(t, tt.wantErr, errString(err))
			require.Equal(t, tt.wantLevel, getKlogLevel(t))
		})
	}

	require.Equal(t, originalLogLevel, getKlogLevel(t))
}

func getKlogLevel(t *testing.T) klog.Level {
	t.Helper()

	// hack around klog not exposing a Get method
	for i := klog.Level(0); i < 256; i++ {
		if klog.V(i).Enabled() {
			continue
		}
		return i - 1
	}

	t.Fatal("unknown log level")
	return 0
}

func errString(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}

func undoGlobalLogLevelChanges(t *testing.T, originalLogLevel klog.Level) {
	t.Helper()
	_, err := logs.GlogSetter(strconv.Itoa(int(originalLogLevel)))
	require.NoError(t, err)
}
