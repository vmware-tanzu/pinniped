// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package library

import (
	"context"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

	Namespace    string                                  `json:"namespace"`
	AppName      string                                  `json:"appName"`
	Capabilities map[TestClusterCapability]bool          `json:"capabilities"`
	TestWebhook  idpv1alpha1.WebhookIdentityProviderSpec `json:"testWebhook"`
	TestUser     struct {
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	secretNamespace := getDefaultedEnv("PINNIPED_NAMESPACE", "integration")
	secretName := getDefaultedEnv("PINNIPED_ENVIRONMENT", "pinniped-test-env")

	secret, err := NewClientset(t).CoreV1().Secrets(secretNamespace).Get(ctx, secretName, metav1.GetOptions{})
	if k8serrors.IsNotFound(err) {
		return envFromOSEnviron(t)
	}
	require.NoErrorf(t, err, "could not fetch test environment from %s/%s", secretNamespace, secretName)

	yamlEnv, ok := secret.Data["env.yaml"]
	require.True(t, ok, "test environment secret %s/%s did not contain expected 'env.yaml' key", secretNamespace, secretName)

	var result TestEnv
	err = yaml.Unmarshal(yamlEnv, &result)
	require.NoErrorf(t, err, "test environment secret %s/%s contained invalid YAML", secretNamespace, secretName)
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

func getDefaultedEnv(name, defaultValue string) string {
	if val := os.Getenv(name); val != "" {
		return val
	}
	return defaultValue
}

// envFromOSEnviron is a (temporary?) helper to pull information from os.Environ instead of the test cluster.
func envFromOSEnviron(t *testing.T) *TestEnv {
	t.Helper()

	capabilitiesDescriptionYAML := os.Getenv("PINNIPED_CLUSTER_CAPABILITY_YAML")
	capabilitiesDescriptionFile := os.Getenv("PINNIPED_CLUSTER_CAPABILITY_FILE")
	require.NotEmptyf(t,
		capabilitiesDescriptionYAML+capabilitiesDescriptionFile,
		"must specify either PINNIPED_CLUSTER_CAPABILITY_YAML or PINNIPED_CLUSTER_CAPABILITY_FILE env var for integration tests",
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

	result.Namespace = needEnv("PINNIPED_NAMESPACE")
	result.AppName = needEnv("PINNIPED_APP_NAME")
	result.TestUser.ExpectedUsername = needEnv("PINNIPED_TEST_USER_USERNAME")
	result.TestUser.ExpectedGroups = strings.Split(strings.ReplaceAll(needEnv("PINNIPED_TEST_USER_GROUPS"), " ", ""), ",")
	result.TestUser.Token = needEnv("PINNIPED_TEST_USER_TOKEN")
	result.TestWebhook.Endpoint = needEnv("PINNIPED_TEST_WEBHOOK_ENDPOINT")
	result.TestWebhook.TLS = &idpv1alpha1.TLSSpec{CertificateAuthorityData: needEnv("PINNIPED_TEST_WEBHOOK_CA_BUNDLE")}
	result.t = t
	return &result
}
