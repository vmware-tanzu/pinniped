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

	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/idp/v1alpha1"
)

type Capability string

const (
	ClusterSigningKeyIsAvailable Capability = "clusterSigningKeyIsAvailable"
)

// TestEnv captures all the external parameters consumed by our integration tests.
type TestEnv struct {
	t *testing.T

	ConciergeNamespace     string                                  `json:"conciergeNamespace"`
	SupervisorNamespace    string                                  `json:"supervisorNamespace"`
	ConciergeAppName       string                                  `json:"conciergeAppName"`
	SupervisorAppName      string                                  `json:"supervisorAppName"`
	SupervisorCustomLabels map[string]string                       `json:"supervisorCustomLabels"`
	ConciergeCustomLabels  map[string]string                       `json:"conciergeCustomLabels"`
	Capabilities           map[Capability]bool                     `json:"capabilities"`
	TestWebhook            idpv1alpha1.WebhookIdentityProviderSpec `json:"testWebhook"`
	SupervisorHTTPAddress  string                                  `json:"supervisorAddress"`

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

	needEnv := func(key string) string {
		t.Helper()
		value := os.Getenv(key)
		require.NotEmptyf(t, value, "must specify %s env var for integration tests", key)
		return value
	}

	result.ConciergeNamespace = needEnv("PINNIPED_TEST_CONCIERGE_NAMESPACE")
	result.ConciergeAppName = needEnv("PINNIPED_TEST_CONCIERGE_APP_NAME")
	result.TestUser.ExpectedUsername = needEnv("PINNIPED_TEST_USER_USERNAME")
	result.TestUser.ExpectedGroups = strings.Split(strings.ReplaceAll(needEnv("PINNIPED_TEST_USER_GROUPS"), " ", ""), ",")
	result.TestUser.Token = needEnv("PINNIPED_TEST_USER_TOKEN")
	result.TestWebhook.Endpoint = needEnv("PINNIPED_TEST_WEBHOOK_ENDPOINT")
	result.SupervisorNamespace = needEnv("PINNIPED_TEST_SUPERVISOR_NAMESPACE")
	result.SupervisorAppName = needEnv("PINNIPED_TEST_SUPERVISOR_APP_NAME")
	result.SupervisorHTTPAddress = needEnv("PINNIPED_TEST_SUPERVISOR_HTTP_ADDRESS")
	result.TestWebhook.TLS = &idpv1alpha1.TLSSpec{CertificateAuthorityData: needEnv("PINNIPED_TEST_WEBHOOK_CA_BUNDLE")}

	conciergeCustomLabelsYAML := needEnv("PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS")
	var conciergeCustomLabels map[string]string
	err = yaml.Unmarshal([]byte(conciergeCustomLabelsYAML), &conciergeCustomLabels)
	require.NoErrorf(t, err, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS must be a YAML map of string to string")
	result.ConciergeCustomLabels = conciergeCustomLabels
	require.NotEmpty(t, result.ConciergeCustomLabels, "PINNIPED_TEST_CONCIERGE_CUSTOM_LABELS cannot be empty")
	supervisorCustomLabelsYAML := needEnv("PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS")
	var supervisorCustomLabels map[string]string
	err = yaml.Unmarshal([]byte(supervisorCustomLabelsYAML), &supervisorCustomLabels)
	require.NoErrorf(t, err, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS must be a YAML map of string to string")
	result.SupervisorCustomLabels = supervisorCustomLabels
	require.NotEmpty(t, result.SupervisorCustomLabels, "PINNIPED_TEST_SUPERVISOR_CUSTOM_LABELS cannot be empty")

	result.OIDCUpstream.Issuer = needEnv("PINNIPED_TEST_CLI_OIDC_ISSUER")
	result.OIDCUpstream.ClientID = needEnv("PINNIPED_TEST_CLI_OIDC_CLIENT_ID")
	result.OIDCUpstream.LocalhostPort, _ = strconv.Atoi(needEnv("PINNIPED_TEST_CLI_OIDC_LOCALHOST_PORT"))
	result.OIDCUpstream.Username = needEnv("PINNIPED_TEST_CLI_OIDC_USERNAME")
	result.OIDCUpstream.Password = needEnv("PINNIPED_TEST_CLI_OIDC_PASSWORD")
	result.t = t
	return &result
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
