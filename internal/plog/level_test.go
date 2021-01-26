// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
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
	originalLogLevel := getKlogLevel()
	require.GreaterOrEqual(t, int(originalLogLevel), int(klog.Level(0)), "cannot get klog level")

	tests := []struct {
		name        string
		level       LogLevel
		wantLevel   klog.Level
		wantEnabled []LogLevel
		wantErr     string
	}{
		{
			name:        "unset",
			wantLevel:   0,
			wantEnabled: []LogLevel{LevelWarning},
		},
		{
			name:        "warning",
			level:       LevelWarning,
			wantLevel:   0,
			wantEnabled: []LogLevel{LevelWarning},
		},
		{
			name:        "info",
			level:       LevelInfo,
			wantLevel:   2,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo},
		},
		{
			name:        "debug",
			level:       LevelDebug,
			wantLevel:   4,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo, LevelDebug},
		},
		{
			name:        "trace",
			level:       LevelTrace,
			wantLevel:   6,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo, LevelDebug, LevelTrace},
		},
		{
			name:        "all",
			level:       LevelAll,
			wantLevel:   108,
			wantEnabled: []LogLevel{LevelWarning, LevelInfo, LevelDebug, LevelTrace, LevelAll},
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
			require.Equal(t, tt.wantLevel, getKlogLevel())

			if tt.wantEnabled != nil {
				allLevels := []LogLevel{LevelWarning, LevelInfo, LevelDebug, LevelTrace, LevelAll}
				for _, level := range allLevels {
					if contains(tt.wantEnabled, level) {
						require.Truef(t, Enabled(level), "wanted %q to be enabled", level)
					} else {
						require.False(t, Enabled(level), "did not want %q to be enabled", level)
					}
				}
			}
		})
	}

	require.Equal(t, originalLogLevel, getKlogLevel())
}

func contains(haystack []LogLevel, needle LogLevel) bool {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
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
