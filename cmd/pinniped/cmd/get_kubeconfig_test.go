/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"bytes"
	"os"
	"testing"

	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
	"github.com/stretchr/testify/require"

	"github.com/suzerain-io/pinniped/internal/here"
)

func TestGetKubeConfig(t *testing.T) {
	spec.Run(t, "cmd.getKubeConfig", func(t *testing.T, when spec.G, it spec.S) {
		var r *require.Assertions
		var buffer *bytes.Buffer
		var fullPathToSelf string

		it.Before(func() {
			r = require.New(t)
			buffer = new(bytes.Buffer)

			var err error
			fullPathToSelf, err = os.Executable()
			r.NoError(err)
		})

		it("writes the kubeconfig to the given writer", func() {
			err := getKubeConfig(buffer, "some-token")
			r.NoError(err)

			expectedYAML := here.Docf(`
				apiVersion: v1
				clusters:
				- cluster:
					server: ""
				  name: pinniped-cluster
				contexts:
				- context:
					cluster: pinniped-cluster
					user: pinniped-user
				  name: pinniped-cluster
				current-context: pinniped-cluster
				kind: Config
				preferences: {}
				users:
				- name: pinniped-user
				  user:
					exec:
					  apiVersion: client.authentication.k8s.io/v1beta1
					  args:
					  - exchange-credential
					  command: %s
					  env:
					  - name: PINNIPED_K8S_API_ENDPOINT
						value: ""
					  - name: PINNIPED_CA_BUNDLE
						value: ""
					  - name: PINNIPED_TOKEN
						value: some-token
					  installHint: |-
						The Pinniped CLI is required to authenticate to the current cluster.
						For more information, please visit https://pinniped.dev
			`, fullPathToSelf)

			r.Equal(expectedYAML, buffer.String())
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}
