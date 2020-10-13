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
	ClusterSigningKeyIsAvailable    Capability = "clusterSigningKeyIsAvailable"
	ExternalOIDCProviderIsAvailable Capability = "externalOIDCProviderIsAvailable"
)

// TestEnv captures all the external parameters consumed by our integration tests.
type TestEnv struct {
	t *testing.T

	ConciergeNamespace  string                                  `json:"conciergeNamespace"`
	SupervisorNamespace string                                  `json:"supervisorNamespace"`
	ConciergeAppName    string                                  `json:"conciergeAppName"`
	SupervisorAppName   string                                  `json:"supervisorAppName"`
	Capabilities        map[Capability]bool                     `json:"capabilities"`
	TestWebhook         idpv1alpha1.WebhookIdentityProviderSpec `json:"testWebhook"`
	SupervisorAddress   string                                  `json:"supervisorAddress"`

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
	result.SupervisorAddress = needEnv("PINNIPED_TEST_SUPERVISOR_ADDRESS")
	result.TestWebhook.TLS = &idpv1alpha1.TLSSpec{CertificateAuthorityData: needEnv("PINNIPED_TEST_WEBHOOK_CA_BUNDLE")}

	result.OIDCUpstream.Issuer = os.Getenv("PINNIPED_TEST_CLI_OIDC_ISSUER")
	result.OIDCUpstream.ClientID = os.Getenv("PINNIPED_TEST_CLI_OIDC_CLIENT_ID")
	result.OIDCUpstream.LocalhostPort, _ = strconv.Atoi(os.Getenv("PINNIPED_TEST_CLI_OIDC_LOCALHOST_PORT"))
	result.OIDCUpstream.Username = os.Getenv("PINNIPED_TEST_CLI_OIDC_USERNAME")
	result.OIDCUpstream.Password = os.Getenv("PINNIPED_TEST_CLI_OIDC_PASSWORD")

	result.Capabilities[ExternalOIDCProviderIsAvailable] = !(result.OIDCUpstream.Issuer == "" ||
		result.OIDCUpstream.ClientID == "" ||
		result.OIDCUpstream.Username == "" ||
		result.OIDCUpstream.Password == "")
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
