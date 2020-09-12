/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	v1 "k8s.io/client-go/tools/clientcmd/api/v1"

	"github.com/suzerain-io/pinniped/internal/here"
)

const (
	getKubeConfigCmdTokenFlagName = "token"
)

//nolint: gochecknoinits
func init() {
	getKubeConfigCmd := &cobra.Command{
		Run:   runGetKubeConfig,
		Args:  cobra.NoArgs, // do not accept positional arguments for this command
		Use:   "get-kubeconfig",
		Short: "Print a kubeconfig for authenticating into a cluster via Pinniped",
		Long: here.Doc(`
			Print a kubeconfig for authenticating into a cluster via Pinniped.
	
			Assumes that you have admin-like access to the cluster using your
			current kubeconfig context, in order to access Pinniped's metadata.
	
			Prints a kubeconfig which is suitable to access the cluster using
			Pinniped as the authentication mechanism. This kubeconfig output
			can be saved to a file and used with future kubectl commands, e.g.:
				pinniped get-kubeconfig --token $MY_TOKEN > $HOME/mycluster-kubeconfig
				kubectl --kubeconfig $HOME/mycluster-kubeconfig get pods
		`),
	}

	rootCmd.AddCommand(getKubeConfigCmd)

	getKubeConfigCmd.Flags().StringP(
		getKubeConfigCmdTokenFlagName,
		"t",
		"",
		"The credential to include in the resulting kubeconfig output (Required)",
	)
	err := getKubeConfigCmd.MarkFlagRequired(getKubeConfigCmdTokenFlagName)
	if err != nil {
		panic(err)
	}
}

func runGetKubeConfig(cmd *cobra.Command, _ []string) {
	token := cmd.Flag(getKubeConfigCmdTokenFlagName).Value.String()

	err := getKubeConfig(os.Stdout, token)

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
		os.Exit(1)
	}
}

func getKubeConfig(outputWriter io.Writer, token string) error {
	clusterName := "pinniped-cluster"
	userName := "pinniped-user"

	fullPathToSelf, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find path to self: %w", err)
	}

	config := v1.Config{
		Kind:       "Config",
		APIVersion: v1.SchemeGroupVersion.Version,
		Preferences: v1.Preferences{
			Colors:     false, // TODO what does this setting do?
			Extensions: nil,
		},
		Clusters: []v1.NamedCluster{
			{
				Name:    clusterName,
				Cluster: v1.Cluster{}, // TODO fill in server and cert authority and such
			},
		},
		AuthInfos: []v1.NamedAuthInfo{
			{
				Name: userName,
				AuthInfo: v1.AuthInfo{
					Exec: &v1.ExecConfig{
						Command: fullPathToSelf,
						Args:    []string{"exchange-credential"},
						Env: []v1.ExecEnvVar{
							{Name: "PINNIPED_K8S_API_ENDPOINT", Value: ""}, // TODO fill in value
							{Name: "PINNIPED_CA_BUNDLE", Value: ""},        // TODO fill in value
							{Name: "PINNIPED_TOKEN", Value: token},
						},
						APIVersion: clientauthenticationv1beta1.SchemeGroupVersion.String(),
						InstallHint: "The Pinniped CLI is required to authenticate to the current cluster.\n" +
							"For more information, please visit https://pinniped.dev",
					},
				},
			},
		},
		Contexts: []v1.NamedContext{
			{
				Name: clusterName,
				Context: v1.Context{
					Cluster:  clusterName,
					AuthInfo: userName,
				},
			},
		},
		CurrentContext: clusterName,
		Extensions:     nil,
	}

	output, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("YAML serialization error: %w", err)
	}

	_, err = fmt.Fprint(outputWriter, string(output))
	if err != nil {
		return fmt.Errorf("output write error: %w", err)
	}

	return nil
}
