// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(legacyGetKubeconfigCommand(kubeconfigRealDeps()))
	rootCmd.AddCommand(legacyExchangeTokenCommand(staticLoginRealDeps()))
}

func legacyGetKubeconfigCommand(deps kubeconfigDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Hidden:     true,
			Deprecated: "Please use `pinniped get kubeconfig` instead.",

			Args:  cobra.NoArgs, // do not accept positional arguments for this command
			Use:   "get-kubeconfig",
			Short: "Print a kubeconfig for authenticating into a cluster via Pinniped",
			Long: here.Doc(`
			Print a kubeconfig for authenticating into a cluster via Pinniped.
			Requires admin-like access to the cluster using the current
			kubeconfig context in order to access Pinniped's metadata.
			The current kubeconfig is found similar to how kubectl finds it:
			using the value of the --kubeconfig option, or if that is not
			specified then from the value of the KUBECONFIG environment
			variable, or if that is not specified then it defaults to
			.kube/config in your home directory.
			Prints a kubeconfig which is suitable to access the cluster using
			Pinniped as the authentication mechanism. This kubeconfig output
			can be saved to a file and used with future kubectl commands, e.g.:
				pinniped get-kubeconfig --token $MY_TOKEN > $HOME/mycluster-kubeconfig
				kubectl --kubeconfig $HOME/mycluster-kubeconfig get pods
		`),
		}
		token             string
		kubeconfig        string
		contextOverride   string
		namespace         string
		authenticatorType string
		authenticatorName string
		apiGroupSuffix    string
	)

	cmd.Flags().StringVar(&token, "token", "", "Credential to include in the resulting kubeconfig output (Required)")
	cmd.Flags().StringVar(&kubeconfig, "kubeconfig", "", "Path to the kubeconfig file")
	cmd.Flags().StringVar(&contextOverride, "kubeconfig-context", "", "Kubeconfig context override")
	cmd.Flags().StringVar(&namespace, "pinniped-namespace", "pinniped-concierge", "Namespace in which Pinniped was installed")
	cmd.Flags().StringVar(&authenticatorType, "authenticator-type", "", "Authenticator type (e.g., 'webhook', 'jwt')")
	cmd.Flags().StringVar(&authenticatorName, "authenticator-name", "", "Authenticator name")
	cmd.Flags().StringVar(&apiGroupSuffix, "api-group-suffix", "pinniped.dev", "Concierge API group suffix")

	mustMarkRequired(cmd, "token")
	plog.RemoveKlogGlobalFlags()
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return runGetKubeconfig(cmd.OutOrStdout(), deps, getKubeconfigParams{
			kubeconfigPath:            kubeconfig,
			kubeconfigContextOverride: contextOverride,
			staticToken:               token,
			concierge: getKubeconfigConciergeParams{
				namespace:         namespace,
				authenticatorName: authenticatorName,
				authenticatorType: authenticatorType,
				apiGroupSuffix:    apiGroupSuffix,
			},
		})
	}
	return cmd
}

func legacyExchangeTokenCommand(deps staticLoginDeps) *cobra.Command {
	cmd := &cobra.Command{
		Hidden:     true,
		Deprecated: "Please use `pinniped login static` instead.",

		Args:  cobra.NoArgs, // do not accept positional arguments for this command
		Use:   "exchange-credential",
		Short: "Exchange a credential for a cluster-specific access credential",
		Long: here.Doc(`
			Exchange a credential which proves your identity for a time-limited,
			cluster-specific access credential.
			Designed to be conveniently used as an credential plugin for kubectl.
			See the help message for 'pinniped get-kubeconfig' for more
			information about setting up a kubeconfig file using Pinniped.
			Requires all of the following environment variables, which are
			typically set in the kubeconfig:
			  - PINNIPED_TOKEN: the token to send to Pinniped for exchange
			  - PINNIPED_NAMESPACE: the namespace of the authenticator to authenticate
			    against
			  - PINNIPED_AUTHENTICATOR_TYPE: the type of authenticator to authenticate
			    against (e.g., "webhook", "jwt")
			  - PINNIPED_AUTHENTICATOR_NAME: the name of the authenticator to authenticate
			    against
			  - PINNIPED_CA_BUNDLE: the CA bundle to trust when calling
				Pinniped's HTTPS endpoint
			  - PINNIPED_K8S_API_ENDPOINT: the URL for the Pinniped credential
				exchange API
			For more information about credential plugins in general, see
			https://kubernetes.io/docs/reference/access-authn-authz/authentication/#client-go-credential-plugins
		`),
	}
	plog.RemoveKlogGlobalFlags()
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Make a little helper to grab OS environment variables and keep a list that were missing.
		var missing []string
		getEnv := func(name string) string {
			value, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return value
		}
		flags := staticLoginParams{
			staticToken:                getEnv("PINNIPED_TOKEN"),
			conciergeEnabled:           true,
			conciergeNamespace:         getEnv("PINNIPED_NAMESPACE"),
			conciergeAuthenticatorType: getEnv("PINNIPED_AUTHENTICATOR_TYPE"),
			conciergeAuthenticatorName: getEnv("PINNIPED_AUTHENTICATOR_NAME"),
			conciergeEndpoint:          getEnv("PINNIPED_K8S_API_ENDPOINT"),
			conciergeCABundle:          base64.StdEncoding.EncodeToString([]byte(getEnv("PINNIPED_CA_BUNDLE"))),
		}
		if len(missing) > 0 {
			return fmt.Errorf("failed to get credential: required environment variable(s) not set: %v", missing)
		}
		return runStaticLogin(cmd.OutOrStdout(), deps, flags)
	}
	return cmd
}
