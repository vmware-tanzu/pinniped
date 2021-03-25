// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package concierge

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
)

func TestFromPath(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		wantConfig *Config
		wantError  string
	}{
		{
			name: "Fully filled out",
			yaml: here.Doc(`
				---
				discovery:
				  url: https://some.discovery/url
				api:
				  servingCertificate:
					durationSeconds: 3600
					renewBeforeSeconds: 2400
				apiGroupSuffix: some.suffix.com
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  kubeCertAgentPrefix: kube-cert-agent-prefix
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				kubeCertAgent:
				  namePrefix: kube-cert-agent-name-prefix-
				  image: kube-cert-agent-image
				  imagePullSecrets: [kube-cert-agent-image-pull-secret]
				logLevel: debug
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: stringPtr("https://some.discovery/url"),
				},
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    int64Ptr(3600),
						RenewBeforeSeconds: int64Ptr(2400),
					},
				},
				APIGroupSuffix: stringPtr("some.suffix.com"),
				NamesConfig: NamesConfigSpec{
					ServingCertificateSecret:          "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuer:                  "pinniped-config",
					APIService:                        "pinniped-api",
					ImpersonationConfigMap:            "impersonationConfigMap-value",
					ImpersonationLoadBalancerService:  "impersonationLoadBalancerService-value",
					ImpersonationTLSCertificateSecret: "impersonationTLSCertificateSecret-value",
					ImpersonationCACertificateSecret:  "impersonationCACertificateSecret-value",
					ImpersonationSignerSecret:         "impersonationSignerSecret-value",
				},
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix:       stringPtr("kube-cert-agent-name-prefix-"),
					Image:            stringPtr("kube-cert-agent-image"),
					ImagePullSecrets: []string{"kube-cert-agent-image-pull-secret"},
				},
				LogLevel: plog.LevelDebug,
			},
		},
		{
			name: "When only the required fields are present, causes other fields to be defaulted",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: nil,
				},
				APIGroupSuffix: stringPtr("pinniped.dev"),
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    int64Ptr(60 * 60 * 24 * 365),    // about a year
						RenewBeforeSeconds: int64Ptr(60 * 60 * 24 * 30 * 9), // about 9 months
					},
				},
				NamesConfig: NamesConfigSpec{
					ServingCertificateSecret:          "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuer:                  "pinniped-config",
					APIService:                        "pinniped-api",
					ImpersonationConfigMap:            "impersonationConfigMap-value",
					ImpersonationLoadBalancerService:  "impersonationLoadBalancerService-value",
					ImpersonationTLSCertificateSecret: "impersonationTLSCertificateSecret-value",
					ImpersonationCACertificateSecret:  "impersonationCACertificateSecret-value",
					ImpersonationSignerSecret:         "impersonationSignerSecret-value",
				},
				Labels: map[string]string{},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix: stringPtr("pinniped-kube-cert-agent-"),
					Image:      stringPtr("debian:latest"),
				},
			},
		},
		{
			name: "Empty",
			yaml: here.Doc(``),
			wantError: "validate names: missing required names: servingCertificateSecret, credentialIssuer, " +
				"apiService, impersonationConfigMap, impersonationLoadBalancerService, " +
				"impersonationTLSCertificateSecret, impersonationCACertificateSecret, " +
				"impersonationSignerSecret",
		},
		{
			name: "Missing apiService name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: apiService",
		},
		{
			name: "Missing credentialIssuer name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: credentialIssuer",
		},
		{
			name: "Missing servingCertificateSecret name",
			yaml: here.Doc(`
				---
				names:
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: servingCertificateSecret",
		},
		{
			name: "Missing impersonationConfigMap name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: impersonationConfigMap",
		},
		{
			name: "Missing impersonationLoadBalancerService name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: impersonationLoadBalancerService",
		},
		{
			name: "Missing impersonationTLSCertificateSecret name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: impersonationTLSCertificateSecret",
		},
		{
			name: "Missing impersonationCACertificateSecret name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: impersonationCACertificateSecret",
		},
		{
			name: "Missing impersonationSignerSecret name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
			`),
			wantError: "validate names: missing required names: impersonationSignerSecret",
		},
		{
			name: "Missing several required names",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate names: missing required names: impersonationConfigMap, " +
				"impersonationTLSCertificateSecret, impersonationCACertificateSecret",
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
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
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
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
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
					renewBeforeSeconds: 0
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate api: renewBefore must be positive",
		},
		{
			name: "InvalidAPIGroupSuffix",
			yaml: here.Doc(`
				---
				api:
				  servingCertificate:
					durationSeconds: 3600
					renewBeforeSeconds: 2400
				apiGroupSuffix: .starts.with.dot
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationConfigMap: impersonationConfigMap-value
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate apiGroupSuffix: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')",
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
