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

func TestFromConfigMap(t *testing.T) {
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
					   endpoint: https://proxy.example.com:8443/
					   tls:
					     certificateAuthoritySecretName: my-ca-crt
					     tlsSecretName: my-tls-certificate-and-key
					`),
				},
			},
			wantConfig: &Config{
				Mode:     "enabled",
				Endpoint: "https://proxy.example.com:8443/",
				TLS: &TLSConfig{
					CertificateAuthoritySecretName: "my-ca-crt",
					TLSSecretName:                  "my-tls-certificate-and-key",
				},
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
				TLS:      nil,
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
	}

	for _, tt := range tests {
		test := tt
		t.Run(test.name, func(t *testing.T) {
			config, err := FromConfigMap(test.configMap)
			require.Equal(t, test.wantConfig, config)
			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
