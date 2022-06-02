// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package concierge

import (
	"context"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/pointer"

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
				aggregatedAPIServerPort: 12345
				impersonationProxyServerPort: 4242
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  kubeCertAgentPrefix: kube-cert-agent-prefix
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  extraName: extraName-value
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
					URL: pointer.StringPtr("https://some.discovery/url"),
				},
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    pointer.Int64Ptr(3600),
						RenewBeforeSeconds: pointer.Int64Ptr(2400),
					},
				},
				APIGroupSuffix:               pointer.StringPtr("some.suffix.com"),
				AggregatedAPIServerPort:      pointer.Int64Ptr(12345),
				ImpersonationProxyServerPort: pointer.Int64Ptr(4242),
				NamesConfig: NamesConfigSpec{
					ServingCertificateSecret:          "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuer:                  "pinniped-config",
					APIService:                        "pinniped-api",
					ImpersonationLoadBalancerService:  "impersonationLoadBalancerService-value",
					ImpersonationClusterIPService:     "impersonationClusterIPService-value",
					ImpersonationTLSCertificateSecret: "impersonationTLSCertificateSecret-value",
					ImpersonationCACertificateSecret:  "impersonationCACertificateSecret-value",
					ImpersonationSignerSecret:         "impersonationSignerSecret-value",
					AgentServiceAccount:               "agentServiceAccount-value",
				},
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix:       pointer.StringPtr("kube-cert-agent-name-prefix-"),
					Image:            pointer.StringPtr("kube-cert-agent-image"),
					ImagePullSecrets: []string{"kube-cert-agent-image-pull-secret"},
				},
				LogLevel: func(level plog.LogLevel) *plog.LogLevel { return &level }(plog.LevelDebug),
				Log: plog.LogSpec{
					Level: plog.LevelDebug,
				},
			},
		},
		{
			name: "Fully filled out new log struct",
			yaml: here.Doc(`
				---
				discovery:
				  url: https://some.discovery/url
				api:
				  servingCertificate:
					durationSeconds: 3600
					renewBeforeSeconds: 2400
				apiGroupSuffix: some.suffix.com
				aggregatedAPIServerPort: 12345
				impersonationProxyServerPort: 4242
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  kubeCertAgentPrefix: kube-cert-agent-prefix
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  extraName: extraName-value
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				kubeCertAgent:
				  namePrefix: kube-cert-agent-name-prefix-
				  image: kube-cert-agent-image
				  imagePullSecrets: [kube-cert-agent-image-pull-secret]
				log:
				  level: all
				  format: json
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: pointer.StringPtr("https://some.discovery/url"),
				},
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    pointer.Int64Ptr(3600),
						RenewBeforeSeconds: pointer.Int64Ptr(2400),
					},
				},
				APIGroupSuffix:               pointer.StringPtr("some.suffix.com"),
				AggregatedAPIServerPort:      pointer.Int64Ptr(12345),
				ImpersonationProxyServerPort: pointer.Int64Ptr(4242),
				NamesConfig: NamesConfigSpec{
					ServingCertificateSecret:          "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuer:                  "pinniped-config",
					APIService:                        "pinniped-api",
					ImpersonationLoadBalancerService:  "impersonationLoadBalancerService-value",
					ImpersonationClusterIPService:     "impersonationClusterIPService-value",
					ImpersonationTLSCertificateSecret: "impersonationTLSCertificateSecret-value",
					ImpersonationCACertificateSecret:  "impersonationCACertificateSecret-value",
					ImpersonationSignerSecret:         "impersonationSignerSecret-value",
					AgentServiceAccount:               "agentServiceAccount-value",
				},
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix:       pointer.StringPtr("kube-cert-agent-name-prefix-"),
					Image:            pointer.StringPtr("kube-cert-agent-image"),
					ImagePullSecrets: []string{"kube-cert-agent-image-pull-secret"},
				},
				Log: plog.LogSpec{
					Level:  plog.LevelAll,
					Format: plog.FormatJSON,
				},
			},
		},
		{
			name: "Fully filled out old log and new log struct",
			yaml: here.Doc(`
				---
				discovery:
				  url: https://some.discovery/url
				api:
				  servingCertificate:
					durationSeconds: 3600
					renewBeforeSeconds: 2400
				apiGroupSuffix: some.suffix.com
				aggregatedAPIServerPort: 12345
				impersonationProxyServerPort: 4242
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  kubeCertAgentPrefix: kube-cert-agent-prefix
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  extraName: extraName-value
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				kubeCertAgent:
				  namePrefix: kube-cert-agent-name-prefix-
				  image: kube-cert-agent-image
				  imagePullSecrets: [kube-cert-agent-image-pull-secret]
				logLevel: debug
				log:
				  level: all
				  format: json
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: pointer.StringPtr("https://some.discovery/url"),
				},
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    pointer.Int64Ptr(3600),
						RenewBeforeSeconds: pointer.Int64Ptr(2400),
					},
				},
				APIGroupSuffix:               pointer.StringPtr("some.suffix.com"),
				AggregatedAPIServerPort:      pointer.Int64Ptr(12345),
				ImpersonationProxyServerPort: pointer.Int64Ptr(4242),
				NamesConfig: NamesConfigSpec{
					ServingCertificateSecret:          "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuer:                  "pinniped-config",
					APIService:                        "pinniped-api",
					ImpersonationLoadBalancerService:  "impersonationLoadBalancerService-value",
					ImpersonationClusterIPService:     "impersonationClusterIPService-value",
					ImpersonationTLSCertificateSecret: "impersonationTLSCertificateSecret-value",
					ImpersonationCACertificateSecret:  "impersonationCACertificateSecret-value",
					ImpersonationSignerSecret:         "impersonationSignerSecret-value",
					AgentServiceAccount:               "agentServiceAccount-value",
				},
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix:       pointer.StringPtr("kube-cert-agent-name-prefix-"),
					Image:            pointer.StringPtr("kube-cert-agent-image"),
					ImagePullSecrets: []string{"kube-cert-agent-image-pull-secret"},
				},
				LogLevel: func(level plog.LogLevel) *plog.LogLevel { return &level }(plog.LevelDebug),
				Log: plog.LogSpec{
					Level:  plog.LevelDebug,
					Format: plog.FormatJSON,
				},
			},
		},
		{
			name: "invalid log format",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				log:
				  level: all
				  format: snorlax
			`),
			wantError: "decode yaml: error unmarshaling JSON: while decoding JSON: invalid log format, valid choices are the empty string, json and text",
		},
		{
			name: "When only the required fields are present, causes other fields to be defaulted",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: nil,
				},
				APIGroupSuffix:               pointer.StringPtr("pinniped.dev"),
				AggregatedAPIServerPort:      pointer.Int64Ptr(10250),
				ImpersonationProxyServerPort: pointer.Int64Ptr(8444),
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    pointer.Int64Ptr(60 * 60 * 24 * 365),    // about a year
						RenewBeforeSeconds: pointer.Int64Ptr(60 * 60 * 24 * 30 * 9), // about 9 months
					},
				},
				NamesConfig: NamesConfigSpec{
					ServingCertificateSecret:          "pinniped-concierge-api-tls-serving-certificate",
					CredentialIssuer:                  "pinniped-config",
					APIService:                        "pinniped-api",
					ImpersonationLoadBalancerService:  "impersonationLoadBalancerService-value",
					ImpersonationClusterIPService:     "impersonationClusterIPService-value",
					ImpersonationTLSCertificateSecret: "impersonationTLSCertificateSecret-value",
					ImpersonationCACertificateSecret:  "impersonationCACertificateSecret-value",
					ImpersonationSignerSecret:         "impersonationSignerSecret-value",
					AgentServiceAccount:               "agentServiceAccount-value",
				},
				Labels: map[string]string{},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix: pointer.StringPtr("pinniped-kube-cert-agent-"),
					Image:      pointer.StringPtr("debian:latest"),
				},
			},
		},
		{
			name: "Empty",
			yaml: here.Doc(``),
			wantError: "validate names: missing required names: servingCertificateSecret, credentialIssuer, " +
				"apiService, impersonationLoadBalancerService, " +
				"impersonationClusterIPService, impersonationTLSCertificateSecret, impersonationCACertificateSecret, " +
				"impersonationSignerSecret, agentServiceAccount",
		},
		{
			name: "Missing apiService name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
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
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
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
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
			`),
			wantError: "validate names: missing required names: servingCertificateSecret",
		},
		{
			name: "Missing impersonationLoadBalancerService name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
			`),
			wantError: "validate names: missing required names: impersonationLoadBalancerService",
		},
		{
			name: "Missing impersonationClusterIPService name",
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
				  agentServiceAccount: agentServiceAccount-value
			`),
			wantError: "validate names: missing required names: impersonationClusterIPService",
		},
		{
			name: "Missing impersonationTLSCertificateSecret name",
			yaml: here.Doc(`
				---
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
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
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
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
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  agentServiceAccount: agentServiceAccount-value
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
				  impersonationClusterIPService: impersonationClusterIPService-value
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
			`),
			wantError: "validate names: missing required names: " +
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
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate api: renewBefore must be positive",
		},
		{
			name: "AggregatedAPIServerPortDefault too small",
			yaml: here.Doc(`
				---
				aggregatedAPIServerPort: 1023
			`),
			wantError: "validate aggregatedAPIServerPort: must be within range 1024 to 65535",
		},
		{
			name: "AggregatedAPIServerPortDefault too large",
			yaml: here.Doc(`
				---
				aggregatedAPIServerPort: 65536
			`),
			wantError: "validate aggregatedAPIServerPort: must be within range 1024 to 65535",
		},
		{
			name: "ImpersonationProxyServerPort too small",
			yaml: here.Doc(`
				---
				impersonationProxyServerPort: 1023
			`),
			wantError: "validate impersonationProxyServerPort: must be within range 1024 to 65535",
		},
		{
			name: "ImpersonationProxyServerPort too large",
			yaml: here.Doc(`
				---
				impersonationProxyServerPort: 65536
			`),
			wantError: "validate impersonationProxyServerPort: must be within range 1024 to 65535",
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
			// this is a serial test because it sets the global logger

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
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			config, err := FromPath(ctx, f.Name())

			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
			} else {
				require.NoError(t, err)
				require.Equal(t, test.wantConfig, config)
			}
		})
	}
}
