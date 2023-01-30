// Copyright 2020-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"github.com/spf13/cobra"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/auth/exec"

	"go.pinniped.dev/internal/here"
)

//nolint:gochecknoglobals
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticates with one of [oidc, static]",
	Long: here.Doc(
		`Authenticates with one of [oidc, static]

			Use "pinniped get kubeconfig" to generate a kubeconfig file which will include
			one of these login subcommands in its configuration. The oidc and static
			subcommands are not meant to be invoked directly by a user.

			The oidc and static subcommands are Kubernetes client-go credential plugins
			which are meant to be configured inside a kubeconfig file. (See the Kubernetes
			authentication documentation for more information about client-go credential
			plugins.)`,
	),
	SilenceUsage: true, // Do not print usage message when commands fail.
}

//nolint:gochecknoinits
func init() {
	rootCmd.AddCommand(loginCmd)
}

func loadClusterInfo() *clientauthv1beta1.Cluster {
	obj, _, err := exec.LoadExecCredentialFromEnv()
	if err != nil {
		return nil
	}
	cred, ok := obj.(*clientauthv1beta1.ExecCredential)
	if !ok {
		return nil
	}
	return cred.Spec.Cluster
}
