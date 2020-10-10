// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/pkg/config/api"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantConfig *api.Config
		wantError  string
	}{
		{
			name: "Happy",
			yaml: here.Doc(`
				---
				discovery:
				  url: https://some.discovery/url
				api:
				  servingCertificate:
					durationSeconds: 3600
					renewBeforeSeconds: 2400
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuerConfig: pinniped-config
				  apiService: pinniped-api
				  kubeCertAgentPrefix: kube-cert-agent-prefix
				KubeCertAgent:
				  namePrefix: kube-cert-agent-name-prefix-
				  image: kube-cert-agent-image
				  imagePullSecrets: [kube-cert-agent-image-pull-secret]
			`),
			wantConfig: &api.Config{
				DiscoveryInfo: api.DiscoveryInfoSpec{
					URL: stringPtr("https://some.discovery/url"),
				},
				APIConfig: api.APIConfigSpec{
					ServingCertificateConfig: api.ServingCertificateConfigSpec{
						DurationSeconds:    int64Ptr(3600),
						RenewBeforeSeconds: int64Ptr(2400),
					},
				},
				NamesConfig: api.NamesConfigSpec{
					ServingCertificateSecret: "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuerConfig:   "pinniped-config",
					APIService:               "pinniped-api",
				},
				KubeCertAgentConfig: api.KubeCertAgentSpec{
					NamePrefix:       stringPtr("kube-cert-agent-name-prefix-"),
					Image:            stringPtr("kube-cert-agent-image"),
					ImagePullSecrets: []string{"kube-cert-agent-image-pull-secret"},
				},
			},
		},
		{
			name: "When only the required fields are present, causes other fields to be defaulted",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuerConfig: pinniped-config
				  apiService: pinniped-api
			`),
			wantConfig: &api.Config{
				DiscoveryInfo: api.DiscoveryInfoSpec{
					URL: nil,
				},
				APIConfig: api.APIConfigSpec{
					ServingCertificateConfig: api.ServingCertificateConfigSpec{
						DurationSeconds:    int64Ptr(60 * 60 * 24 * 365),    // about a year
						RenewBeforeSeconds: int64Ptr(60 * 60 * 24 * 30 * 9), // about 9 months
					},
				},
				NamesConfig: api.NamesConfigSpec{
					ServingCertificateSecret: "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuerConfig:   "pinniped-config",
					APIService:               "pinniped-api",
				},
				KubeCertAgentConfig: api.KubeCertAgentSpec{
					NamePrefix: stringPtr("pinniped-kube-cert-agent-"),
					Image:      stringPtr("debian:latest"),
				},
			},
		},
		{
			name:      "Empty",
			yaml:      here.Doc(``),
			wantError: "validate names: missing required names: servingCertificateSecret, credentialIssuerConfig, apiService",
		},
		{
			name: "Missing apiService name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuerConfig: pinniped-config
			`),
			wantError: "validate names: missing required names: apiService",
		},
		{
			name: "Missing credentialIssuerConfig name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  apiService: pinniped-api
			`),
			wantError: "validate names: missing required names: credentialIssuerConfig",
		},
		{
			name: "Missing servingCertificateSecret name",
			yaml: here.Doc(`
				---
				names:
				  credentialIssuerConfig: pinniped-config
				  apiService: pinniped-api
			`),
			wantError: "validate names: missing required names: servingCertificateSecret",
		},
		{
			name: "InvalidDurationRenewBefore",
			yaml: here.Doc(`
				---
				api:
				  servingCertificate:
					durationSeconds: 2400
					renewBeforeSeconds: 3600
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuerConfig: pinniped-config
				  apiService: pinniped-api
			`),
			wantError: "validate api: durationSeconds cannot be smaller than renewBeforeSeconds",
		},
		{
			name: "NegativeRenewBefore",
			yaml: here.Doc(`
				---
				api:
				  servingCertificate:
					durationSeconds: 2400
					renewBeforeSeconds: -10
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuerConfig: pinniped-config
				  apiService: pinniped-api
			`),
			wantError: "validate api: renewBefore must be positive",
		},
		{
			name: "ZeroRenewBefore",
			yaml: here.Doc(`
				---
				api:
				  servingCertificate:
					durationSeconds: 2400
					renewBeforeSeconds: -10
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuerConfig: pinniped-config
				  apiService: pinniped-api
			`),
			wantError: "validate api: renewBefore must be positive",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			// Write yaml to temp file
			f, err := ioutil.TempFile("", "pinniped-test-config-yaml-*")
			require.NoError(t, err)
			defer func() {
				err := os.Remove(f.Name())
				require.NoError(t, err)
			}()
			_, err = f.WriteString(test.yaml)
			require.NoError(t, err)
			err = f.Close()
			require.NoError(t, err)

			// Test FromPath()
			config, err := FromPath(f.Name())

			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wantConfig, config)
			}
		})
	}
}
