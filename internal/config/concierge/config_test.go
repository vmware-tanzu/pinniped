// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package concierge

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
)

func TestFromPath(t *testing.T) {
	stringOfLength253 := strings.Repeat("a", 253)
	stringOfLength254 := strings.Repeat("a", 254)

	tests := []struct {
		name                string
		yaml                string
		allowedCiphersError error
		wantConfig          *Config
		wantError           string
	}{
		{
			name: "Fully filled out",
			yaml: here.Docf(`
				---
				discovery:
				  url: https://some.discovery/url
				api:
				  servingCertificate:
					durationSeconds: 3600
					renewBeforeSeconds: 2400
				apiGroupSuffix: some.suffix.com
				aggregatedAPIServerPort: 12345
				aggregatedAPIServerDisableAdmissionPlugins:
				  - NamespaceLifecycle
				  - MutatingAdmissionWebhook
				  - ValidatingAdmissionPolicy
				  - ValidatingAdmissionWebhook
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
				  extraName: extraName-value
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				kubeCertAgent:
				  namePrefix: kube-cert-agent-name-prefix-
				  image: kube-cert-agent-image
				  imagePullSecrets: [kube-cert-agent-image-pull-secret]
				  priorityClassName: %s
				log:
				  level: debug
				tls:
				  onedottwo:
				    allowedCiphers:
				    - foo
				    - bar
					- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
				audit:
				  logUsernamesAndGroups: enabled
			`, stringOfLength253),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: ptr.To("https://some.discovery/url"),
				},
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    ptr.To[int64](3600),
						RenewBeforeSeconds: ptr.To[int64](2400),
					},
				},
				APIGroupSuffix:          ptr.To("some.suffix.com"),
				AggregatedAPIServerPort: ptr.To[int64](12345),
				AggregatedAPIServerDisableAdmissionPlugins: []string{
					"NamespaceLifecycle",
					"MutatingAdmissionWebhook",
					"ValidatingAdmissionPolicy",
					"ValidatingAdmissionWebhook",
				},
				ImpersonationProxyServerPort: ptr.To[int64](4242),
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
					ImpersonationProxyServiceAccount:  "impersonationProxyServiceAccount-value",
					ImpersonationProxyLegacySecret:    "impersonationProxyLegacySecret-value",
				},
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix:        ptr.To("kube-cert-agent-name-prefix-"),
					Image:             ptr.To("kube-cert-agent-image"),
					ImagePullSecrets:  []string{"kube-cert-agent-image-pull-secret"},
					PriorityClassName: stringOfLength253,
				},
				Log: plog.LogSpec{
					Level: plog.LevelDebug,
				},
				TLS: TLSSpec{
					OneDotTwo: TLSProtocolSpec{
						AllowedCiphers: []string{
							"foo",
							"bar",
							"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
						},
					},
				},
				Audit: AuditSpec{
					LogUsernamesAndGroups: "enabled",
				},
			},
		},
		{
			name: "fully filled out including log format",
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
				aggregatedAPIServerDisableAdmissionPlugins:
				  - NamespaceLifecycle
				  - MutatingAdmissionWebhook
				  - ValidatingAdmissionPolicy
				  - ValidatingAdmissionWebhook
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
				  extraName: extraName-value
				labels:
				  myLabelKey1: myLabelValue1
				  myLabelKey2: myLabelValue2
				kubeCertAgent:
				  namePrefix: kube-cert-agent-name-prefix-
				  image: kube-cert-agent-image
				  imagePullSecrets: [kube-cert-agent-image-pull-secret]
				  priorityClassName: kube-cert-agent-priority-class-name
				log:
				  level: all
				  format: json
				audit:
				  logUsernamesAndGroups: disabled
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: ptr.To("https://some.discovery/url"),
				},
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    ptr.To[int64](3600),
						RenewBeforeSeconds: ptr.To[int64](2400),
					},
				},
				APIGroupSuffix:          ptr.To("some.suffix.com"),
				AggregatedAPIServerPort: ptr.To[int64](12345),
				AggregatedAPIServerDisableAdmissionPlugins: []string{
					"NamespaceLifecycle",
					"MutatingAdmissionWebhook",
					"ValidatingAdmissionPolicy",
					"ValidatingAdmissionWebhook",
				},
				ImpersonationProxyServerPort: ptr.To[int64](4242),
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
					ImpersonationProxyServiceAccount:  "impersonationProxyServiceAccount-value",
					ImpersonationProxyLegacySecret:    "impersonationProxyLegacySecret-value",
				},
				Labels: map[string]string{
					"myLabelKey1": "myLabelValue1",
					"myLabelKey2": "myLabelValue2",
				},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix:        ptr.To("kube-cert-agent-name-prefix-"),
					Image:             ptr.To("kube-cert-agent-image"),
					ImagePullSecrets:  []string{"kube-cert-agent-image-pull-secret"},
					PriorityClassName: "kube-cert-agent-priority-class-name",
				},
				Log: plog.LogSpec{
					Level:  plog.LevelAll,
					Format: plog.FormatJSON,
				},
				Audit: AuditSpec{
					LogUsernamesAndGroups: "disabled",
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				log:
				  level: all
				  format: snorlax
			`),
			wantError: "decode yaml: error unmarshaling JSON: while decoding JSON: invalid log format, valid choices are the empty string or 'json'",
		},
		{
			name: "cli is a bad log format when configured by the user",
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				log:
				  level: all
				  format: cli
			`),
			wantError: "decode yaml: error unmarshaling JSON: while decoding JSON: invalid log format, valid choices are the empty string or 'json'",
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
			`),
			wantConfig: &Config{
				DiscoveryInfo: DiscoveryInfoSpec{
					URL: nil,
				},
				APIGroupSuffix:               ptr.To("pinniped.dev"),
				AggregatedAPIServerPort:      ptr.To[int64](10250),
				ImpersonationProxyServerPort: ptr.To[int64](8444),
				APIConfig: APIConfigSpec{
					ServingCertificateConfig: ServingCertificateConfigSpec{
						DurationSeconds:    ptr.To[int64](60 * 60 * 24 * 365),    // about a year
						RenewBeforeSeconds: ptr.To[int64](60 * 60 * 24 * 30 * 9), // about 9 months
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
					ImpersonationProxyServiceAccount:  "impersonationProxyServiceAccount-value",
					ImpersonationProxyLegacySecret:    "impersonationProxyLegacySecret-value",
				},
				Labels: map[string]string{},
				KubeCertAgentConfig: KubeCertAgentSpec{
					NamePrefix: ptr.To("pinniped-kube-cert-agent-"),
					Image:      ptr.To("debian:latest"),
				},
				Audit: AuditSpec{LogUsernamesAndGroups: ""},
				AggregatedAPIServerDisableAdmissionPlugins: nil,
				TLS: TLSSpec{},
				Log: plog.LogSpec{},
			},
		},
		{
			name: "Empty",
			yaml: here.Doc(``),
			wantError: "validate names: missing required names: servingCertificateSecret, credentialIssuer, " +
				"apiService, impersonationLoadBalancerService, " +
				"impersonationClusterIPService, impersonationTLSCertificateSecret, impersonationCACertificateSecret, " +
				"impersonationSignerSecret, agentServiceAccount, impersonationProxyServiceAccount, impersonationProxyLegacySecret",
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
			`),
			wantError: "validate names: missing required names: impersonationSignerSecret",
		},
		{
			name: "Missing impersonationProxyServiceAccount name",
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
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
			`),
			wantError: "validate names: missing required names: impersonationProxyServiceAccount",
		},
		{
			name: "Missing impersonationProxyLegacySecret name",
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
			`),
			wantError: "validate names: missing required names: impersonationProxyLegacySecret",
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
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
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
		{
			name: "Invalid aggregatedAPIServerDisableAdmissionPlugins",
			yaml: here.Doc(`
				---
				aggregatedAPIServerDisableAdmissionPlugins: [foobar, ValidatingAdmissionWebhook, foobaz]
				names:
				  servingCertificateSecret: pinniped-concierge-api-tls-serving-certificate
				  credentialIssuer: pinniped-config
				  apiService: pinniped-api
				  impersonationLoadBalancerService: impersonationLoadBalancerService-value
				  impersonationTLSCertificateSecret: impersonationTLSCertificateSecret-value
				  impersonationCACertificateSecret: impersonationCACertificateSecret-value
				  impersonationSignerSecret: impersonationSignerSecret-value
			`),
			wantError: "validate aggregatedAPIServerDisableAdmissionPlugins: admission plugin names not recognized: [foobar foobaz] (each must be one of [NamespaceLifecycle MutatingAdmissionPolicy MutatingAdmissionWebhook ValidatingAdmissionPolicy ValidatingAdmissionWebhook])",
		},
		{
			name: "returns setAllowedCiphers errors",
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
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
				tls:
				  onedottwo:
				    allowedCiphers:
				    - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
			`),
			allowedCiphersError: fmt.Errorf("some error from setAllowedCiphers"),
			wantError:           "validate tls: some error from setAllowedCiphers",
		},
		{
			name: "invalid audit.logUsernamesAndGroups format",
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
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
				audit:
				  logUsernamesAndGroups: this-value-is-not-allowed
			`),
			wantError: "validate audit: invalid logUsernamesAndGroups format, valid choices are 'enabled', 'disabled', or empty string (equivalent to 'disabled')",
		},
		{
			name: "invalid kubeCertAgent.priorityClassName length",
			yaml: here.Docf(`
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
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
				kubeCertAgent:
				  priorityClassName: %s
			`, stringOfLength254),
			wantError: "validate kubeCertAgent: invalid priorityClassName: must be no more than 253 characters",
		},
		{
			name: "invalid kubeCertAgent.priorityClassName format",
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
				  impersonationSignerSecret: impersonationSignerSecret-value
				  agentServiceAccount: agentServiceAccount-value
				  impersonationProxyServiceAccount: impersonationProxyServiceAccount-value
				  impersonationProxyLegacySecret: impersonationProxyLegacySecret-value
				kubeCertAgent:
				  priorityClassName: thisIsNotAValidPriorityClassName
			`),
			wantError: `validate kubeCertAgent: invalid priorityClassName: a lowercase RFC 1123 subdomain must consist of lower case alphanumeric characters, '-' or '.', and must start and end with an alphanumeric character (e.g. 'example.com', regex used for validation is '[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*')`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// this is a serial test because it sets the global logger

			// Write yaml to temp file
			f, err := os.CreateTemp("", "pinniped-test-config-yaml-*")
			require.NoError(t, err)
			t.Cleanup(func() {
				err := os.Remove(f.Name())
				require.NoError(t, err)
			})
			_, err = f.WriteString(test.yaml)
			require.NoError(t, err)
			err = f.Close()
			require.NoError(t, err)

			// Test FromPath()
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			var actualCiphers []string
			setAllowedCiphers := func(ciphers []string) error {
				actualCiphers = ciphers
				return test.allowedCiphersError
			}

			config, err := FromPath(ctx, f.Name(), setAllowedCiphers)

			if test.wantError != "" {
				require.EqualError(t, err, test.wantError)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.wantConfig, config)
			require.Equal(t, test.wantConfig.TLS.OneDotTwo.AllowedCiphers, actualCiphers)
		})
	}
}
