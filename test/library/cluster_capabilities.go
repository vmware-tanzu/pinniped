/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package library

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"
)

type TestClusterCapability string

const (
	ClusterSigningKeyIsAvailable = TestClusterCapability("clusterSigningKeyIsAvailable")
)

type capabilitiesConfig struct {
	Capabilities map[TestClusterCapability]bool `yaml:"capabilities,omitempty"`
}

func ClusterHasCapability(t *testing.T, capability TestClusterCapability) bool {
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

	var capabilities capabilitiesConfig
	err := yaml.Unmarshal([]byte(capabilitiesDescriptionYAML), &capabilities)
	require.NoError(t, err)

	isCapable, capabilityWasDescribed := capabilities.Capabilities[capability]
	require.True(t, capabilityWasDescribed, `the cluster's "%s" capability was not described`, capability)

	return isCapable
}

func SkipUnlessClusterHasCapability(t *testing.T, capability TestClusterCapability) {
	t.Helper()
	if !ClusterHasCapability(t, capability) {
		t.Skipf(`skipping integration test because cluster lacks the "%s" capability`, capability)
	}
}

func SkipWhenClusterHasCapability(t *testing.T, capability TestClusterCapability) {
	t.Helper()
	if ClusterHasCapability(t, capability) {
		t.Skipf(`skipping integration test because cluster has the "%s" capability`, capability)
	}
}
