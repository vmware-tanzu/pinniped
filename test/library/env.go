// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	auth1alpha1 "go.pinniped.dev/generated/1.19/apis/concierge/authentication/v1alpha1"
)

type Capability string

const (
	ClusterSigningKeyIsAvailable Capability = "clusterSigningKeyIsAvailable"
)

// TestEnv captures all the external parameters consumed by our integration tests.
type TestEnv struct {
	t *testing.T

	ConciergeNamespace             string                               `json:"conciergeNamespace"`
	SupervisorNamespace            string                               `json:"supervisorNamespace"`
	ConciergeAppName               string                               `json:"conciergeAppName"`
	SupervisorAppName              string                               `json:"supervisorAppName"`
	SupervisorCustomLabels         map[string]string                    `json:"supervisorCustomLabels"`
	ConciergeCustomLabels          map[string]string                    `json:"conciergeCustomLabels"`
	Capabilities                   map[Capability]bool                  `json:"capabilities"`
	TestWebhook                    auth1alpha1.WebhookAuthenticatorSpec `json:"testWebhook"`
	SupervisorHTTPAddress          string                               `json:"supervisorHttpAddress"`
	SupervisorHTTPSAddress         string                               `json:"supervisorHttpsAddress"`
	SupervisorHTTPSIngressAddress  string                               `json:"supervisorHttpsIngressAddress"`
	SupervisorHTTPSIngressCABundle string                               `json:"supervisorHttpsIngressCABundle"`

	TestUser struct {
		Token            string   `json:"token"`
		ExpectedUsername string   `json:"expectedUsername"`
		ExpectedGroups   []string `json:"expectedGroups"`
	} `json:"testUser"`

	OIDCUpstream struct {
		Issuer        string `json:"issuer"`
		ClientID      string `json:"clientID"`
		LocalhostPort int    `json:"localhostPort"`
		Username      string `json:"username"`
		Password      string `json:"password"`
	} `json:"oidcUpstream"`
}

// IntegrationEnv gets the integration test environment from OS environment variables. This
// method also implies SkipUnlessIntegration().
func IntegrationEnv(t *testing.T) *TestEnv {
	t.Helper()
	SkipUnlessIntegration(t)

	capabilitiesDescriptionYAML := os.Getenv("PINNIPED_TEST_CLUSTER_CAPABILITY_YAML")
	capabilitiesDescriptionFile := os.Getenv("PINNIPED_TEST_CLUSTER_CAPABILITY_FILE")
	require.NotEmptyf(t,
		capabilitiesDescriptionYAML+capabilitiesDescriptionFile,
		"must specify either PINNIPED_TEST_CLUSTER_CAPABILITY_YAML or PINNIPED_TEST_CLUSTER_CAPABILITY_FILE env var for integration tests",
	)
	if capabilitiesDescriptionYAML == "" {
		bytes, err := ioutil.ReadFile(capabilitiesDescriptionFile)
		capabilitiesDescriptionYAML = string(bytes)
		require.NoError(t, err)
	}

	var result TestEnv
	err := yaml.Unmarshal([]byte(capabilitiesDescriptionYAML), &result)
	require.NoErrorf(t, err, "capabilities specification was invalid YAML")

	loadEnvVars(t, &result)

	result.t = t
	return &result
}

func needEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	require.NotEmptyf(t, value, "must specify %s env var for integration tests", key)
	return value
}

func loadEnvVars(t *testing.T, result *TestEnv) {
	t.Helper()

	result.ConciergeNamespace = needEnv(t, "PINNIPED_TEST_CONCIERGE_NAMESPACE")
	result.ConciergeAppName = needEnv(t, "PINNIPED_TEST_CONCIERGE_APP_NAME")
	result.TestUser.ExpectedUsername = needEnv(t, "PINNIPED_TEST_USER_USERNAME")
	result.TestUser.ExpectedGroups = strings.Split(strings.ReplaceAll(needEnv(t, "PINNIPED_TEST_USER_GROUPS"), " ", ""), ",")
	result.TestUser.Token = needEnv(t, "PINNIPED_TEST_USER_TOKEN")
	result.TestWebhook.Endpoint = needEnv(t, "PINNIPED_TEST_WEBHOOK_ENDPOINT")
	result.SupervisorNamespace = needEnv(t, "PINNIPED_TEST_SUPERVISOR_NAMESPACE")
	result.SupervisorAppName = needEnv(t, "PINNIPED_TEST_SUPERVISOR_APP_NAME")
	result.TestWebhook.TLS = &auth1alpha1.TLSSpec{CertificateAuthorityData: needEnv(t, "PINNIPED_TEST_WEBHOOK_CA_BUNDLE")}

	result.SupervisorHTTPAddress = os.Getenv("PINNIPED_TEST_SUPERVISOR_HTTP_ADDRESS")
	result.SupervisorHTTPSIngressAddress = os.Getenv("PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_ADDRESS")
	result.SupervisorHTTPSIngressCABundle = os.Getenv("PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_CA_BUNDLE") // optional
	require.NotEmptyf(t,
		result.SupervisorHTTPAddress+result.SupervisorHTTPSIngressAddress,
		"must specify either PINNIPED_TEST_SUPERVISOR_HTTP_ADDRESS or PINNIPED_TEST_SUPERVISOR_HTTPS_INGRESS_ADDRESS env var (or both) for integration tests",
	)
	result.SupervisorHTTPSAddress = needEnv(t, "PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS")
	require.NotRegexp(t, "^[0-9]", result.SupervisorHTTPSAddress,
		"PINNIPED_TEST_SUPERVISOR_HTTPS_ADDRESS must be a hostname with an optional port and cannot be an IP address",
	)

	conciergeCustomLabelsYAML := needEnv(t, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS")
	var conciergeCustomLabels map[string]string
	err := yaml.Unmarshal([]byte(conciergeCustomLabelsYAML), &conciergeCustomLabels)
	require.NoErrorf(t, err, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS must be a YAML map of string to string")
	result.ConciergeCustomLabels = conciergeCustomLabels
	require.NotEmpty(t, result.ConciergeCustomLabels, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS cannot be empty")
	supervisorCustomLabelsYAML := needEnv(t, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS")
	var supervisorCustomLabels map[string]string
	err = yaml.Unmarshal([]byte(supervisorCustomLabelsYAML), &supervisorCustomLabels)
	require.NoErrorf(t, err, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS must be a YAML map of string to string")
	result.SupervisorCustomLabels = supervisorCustomLabels
	require.NotEmpty(t, result.SupervisorCustomLabels, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS cannot be empty")

	result.OIDCUpstream.Issuer = needEnv(t, "PINNIPED_TEST_CLI_OIDC_ISSUER")
	result.OIDCUpstream.ClientID = needEnv(t, "PINNIPED_TEST_CLI_OIDC_CLIENT_ID")
	result.OIDCUpstream.LocalhostPort, _ = strconv.Atoi(needEnv(t, "PINNIPED_TEST_CLI_OIDC_LOCALHOST_PORT"))
	result.OIDCUpstream.Username = needEnv(t, "PINNIPED_TEST_CLI_OIDC_USERNAME")
	result.OIDCUpstream.Password = needEnv(t, "PINNIPED_TEST_CLI_OIDC_PASSWORD")
}

func (e *TestEnv) HasCapability(cap Capability) bool {
	e.t.Helper()
	isCapable, capabilityWasDescribed := e.Capabilities[cap]
	require.Truef(e.t, capabilityWasDescribed, "the %q capability of the test environment was not described", cap)
	return isCapable
}

func (e *TestEnv) WithCapability(cap Capability) *TestEnv {
	e.t.Helper()
	if !e.HasCapability(cap) {
		e.t.Skipf("skipping integration test because test environment lacks the %q capability", cap)
	}
	return e
}

func (e *TestEnv) WithoutCapability(cap Capability) *TestEnv {
	e.t.Helper()
	if e.HasCapability(cap) {
		e.t.Skipf("skipping integration test because test environment has the %q capability", cap)
	}
	return e
}
