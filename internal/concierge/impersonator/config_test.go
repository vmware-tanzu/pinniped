// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonator

import (
	"testing"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"go.pinniped.dev/internal/here"
)

func TestNewConfig(t *testing.T) {
	// It defaults the mode.
	require.Equal(t, &Config{Mode: ModeAuto}, NewConfig())
}

func TestHasEndpoint(t *testing.T) {
	configWithoutEndpoint := Config{}
	configWithEndpoint := Config{Endpoint: "something"}
	require.False(t, configWithoutEndpoint.HasEndpoint())
	require.True(t, configWithEndpoint.HasEndpoint())
}

func TestConfigFromConfigMap(t *testing.T) {
	tests := []struct {
		name       string
		configMap  *v1.ConfigMap
		wantConfig *Config
		wantError  string
	}{
		{
			name: "fully configured, valid config",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": here.Doc(`
						mode: enabled
						endpoint: proxy.example.com:8443
					`),
				},
			},
			wantConfig: &Config{
				Mode:     "enabled",
				Endpoint: "proxy.example.com:8443",
			},
		},
		{
			name: "empty, valid config",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": "",
				},
			},
			wantConfig: &Config{
				Mode:     "auto",
				Endpoint: "",
			},
		},
		{
			name: "valid config with mode enabled",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": "mode: enabled",
				},
			},
			wantConfig: &Config{
				Mode:     "enabled",
				Endpoint: "",
			},
		},
		{
			name: "valid config with mode disabled",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": "mode: disabled",
				},
			},
			wantConfig: &Config{
				Mode:     "disabled",
				Endpoint: "",
			},
		},
		{
			name: "valid config with mode auto",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": "mode: auto",
				},
			},
			wantConfig: &Config{
				Mode:     "auto",
				Endpoint: "",
			},
		},
		{
			name: "wrong key in configmap",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"wrong-key": "",
				},
			},
			wantError: `ConfigMap is missing expected key "config.yaml"`,
		},
		{
			name: "illegal yaml in configmap",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": "this is not yaml",
				},
			},
			wantError: "decode yaml: error unmarshaling JSON: while decoding JSON: json: cannot unmarshal string into Go value of type impersonator.Config",
		},
		{
			name: "illegal value for mode in configmap",
			configMap: &v1.ConfigMap{
				TypeMeta:   metav1.TypeMeta{},
				ObjectMeta: metav1.ObjectMeta{},
				Data: map[string]string{
					"config.yaml": "mode: unexpected-value",
				},
			},
			wantError: `illegal value for "mode": unexpected-value`,
		},
	}

	for _, tt := range tests {
		test := tt
		t.Run(test.name, func(t *testing.T) {
			config, err := ConfigFromConfigMap(test.configMap)
			require.Equal(t, test.wantConfig, config)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
