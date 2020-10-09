// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	idpv1alpha1 "go.pinniped.dev/generated/1.19/apis/idp/v1alpha1"
)

type TestClusterCapability string

const (
	ClusterSigningKeyIsAvailable = TestClusterCapability("clusterSigningKeyIsAvailable")
)

// TestEnv captures all the external parameters consumed by our integration tests.
type TestEnv struct {
	t *testing.T

	ConciergeNamespace  string                                  `json:"conciergeNamespace"`
	SupervisorNamespace string                                  `json:"supervisorNamespace"`
	ConciergeAppName    string                                  `json:"conciergeAppName"`
	SupervisorAppName   string                                  `json:"supervisorAppName"`
	Capabilities        map[TestClusterCapability]bool          `json:"capabilities"`
	TestWebhook         idpv1alpha1.WebhookIdentityProviderSpec `json:"testWebhook"`
	SupervisorAddress   string                                  `json:"supervisorAddress"`

	TestUser struct {
		Token            string   `json:"token"`
		ExpectedUsername string   `json:"expectedUsername"`
		ExpectedGroups   []string `json:"expectedGroups"`
	} `json:"testUser"`
}

// IntegrationEnv gets the integration test environment from a Kubernetes Secret in the test cluster. This
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
	result.t = t
	return &result
}

func (e *TestEnv) HasCapability(cap TestClusterCapability) bool {
	e.t.Helper()
	isCapable, capabilityWasDescribed := e.Capabilities[cap]
	require.True(e.t, capabilityWasDescribed, `the cluster's "%s" capability was not described`, cap)
	return isCapable
}

func (e *TestEnv) WithCapability(cap TestClusterCapability) *TestEnv {
	e.t.Helper()
	if !e.HasCapability(cap) {
		e.t.Skipf(`skipping integration test because cluster lacks the "%s" capability`, cap)
	}
	return e
}

func (e *TestEnv) WithoutCapability(cap TestClusterCapability) *TestEnv {
	e.t.Helper()
	if e.HasCapability(cap) {
		e.t.Skipf(`skipping integration test because cluster has the "%s" capability`, cap)
	}
	return e
}
