// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/execcredcache"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

//nolint:gochecknoinits
func init() {
	loginCmd.AddCommand(staticLoginCommand(staticLoginRealDeps()))
}

type staticLoginDeps struct {
	lookupEnv     func(string) (string, bool)
	exchangeToken func(context.Context, *conciergeclient.Client, string) (*clientauthv1beta1.ExecCredential, error)
}

func staticLoginRealDeps() staticLoginDeps {
	return staticLoginDeps{
		lookupEnv: os.LookupEnv,
		exchangeToken: func(ctx context.Context, client *conciergeclient.Client, token string) (*clientauthv1beta1.ExecCredential, error) {
			return client.ExchangeToken(ctx, token)
		},
	}
}

type staticLoginParams struct {
	staticToken                string
	staticTokenEnvName         string
	conciergeEnabled           bool
	conciergeAuthenticatorType string
	conciergeAuthenticatorName string
	conciergeEndpoint          string
	conciergeCABundle          string
	conciergeAPIGroupSuffix    string
	credentialCachePath        string
}

func staticLoginCommand(deps staticLoginDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Args:  cobra.NoArgs,
			Use:   "static [--token TOKEN] [--token-env TOKEN_NAME]",
			Short: "Login using a static token",
			Long: here.Doc(
				`Login using a static token

					Use "pinniped get kubeconfig" to generate a kubeconfig file which includes this
					login command in its configuration. This login command is not meant to be
					invoked directly by a user.

					This login command is a Kubernetes client-go credential plugin which is meant to
					be configured inside a kubeconfig file. (See the Kubernetes authentication
					documentation for more information about client-go credential plugins.)`,
			),
			SilenceUsage: true, // do not print usage message when commands fail
		}
		flags              staticLoginParams
		conciergeNamespace string // unused now
	)
	cmd.Flags().StringVar(&flags.staticToken, "token", "", "Static token to present during login")
	cmd.Flags().StringVar(&flags.staticTokenEnvName, "token-env", "", "Environment variable containing a static token")
	cmd.Flags().BoolVar(&flags.conciergeEnabled, "enable-concierge", false, "Use the Concierge to login")
	cmd.Flags().StringVar(&conciergeNamespace, "concierge-namespace", "pinniped-concierge", "Namespace in which the Concierge was installed")
	cmd.Flags().StringVar(&flags.conciergeAuthenticatorType, "concierge-authenticator-type", "", "Concierge authenticator type (e.g., 'webhook', 'jwt')")
	cmd.Flags().StringVar(&flags.conciergeAuthenticatorName, "concierge-authenticator-name", "", "Concierge authenticator name")
	cmd.Flags().StringVar(&flags.conciergeEndpoint, "concierge-endpoint", "", "API base for the Concierge endpoint")
	cmd.Flags().StringVar(&flags.conciergeCABundle, "concierge-ca-bundle-data", "", "CA bundle to use when connecting to the Concierge")
	cmd.Flags().StringVar(&flags.conciergeAPIGroupSuffix, "concierge-api-group-suffix", groupsuffix.PinnipedDefaultSuffix, "Concierge API group suffix")
	cmd.Flags().StringVar(&flags.credentialCachePath, "credential-cache", filepath.Join(mustGetConfigDir(), "credentials.yaml"), "Path to cluster-specific credentials cache (\"\" disables the cache)")

	cmd.RunE = func(cmd *cobra.Command, _args []string) error { return runStaticLogin(cmd, deps, flags) }

	mustMarkDeprecated(cmd, "concierge-namespace", "not needed anymore")
	mustMarkHidden(cmd, "concierge-namespace")

	return cmd
}

func runStaticLogin(cmd *cobra.Command, deps staticLoginDeps, flags staticLoginParams) error {
	out := cmd.OutOrStdout()
	pLogger, err := SetLogLevel(cmd.Context(), deps.lookupEnv)
	if err != nil {
		plog.WarningErr("Received error while setting log level", err)
	}

	if flags.staticToken == "" && flags.staticTokenEnvName == "" {
		return fmt.Errorf("one of --token or --token-env must be set")
	}

	var concierge *conciergeclient.Client
	if flags.conciergeEnabled {
		var err error
		concierge, err = conciergeclient.New(
			conciergeclient.WithEndpoint(flags.conciergeEndpoint),
			conciergeclient.WithBase64CABundle(flags.conciergeCABundle),
			conciergeclient.WithAuthenticator(flags.conciergeAuthenticatorType, flags.conciergeAuthenticatorName),
			conciergeclient.WithAPIGroupSuffix(flags.conciergeAPIGroupSuffix),
			conciergeclient.WithTransportWrapper(LogAuditIDTransportWrapper),
		)
		if err != nil {
			return fmt.Errorf("invalid Concierge parameters: %w", err)
		}
	}

	var token string
	if flags.staticToken != "" {
		token = flags.staticToken
	}
	if flags.staticTokenEnvName != "" {
		var ok bool
		token, ok = deps.lookupEnv(flags.staticTokenEnvName)
		if !ok {
			return fmt.Errorf("--token-env variable %q is not set", flags.staticTokenEnvName)
		}
		if token == "" {
			return fmt.Errorf("--token-env variable %q is empty", flags.staticTokenEnvName)
		}
	}
	cred := tokenCredential(&oidctypes.IDToken{Token: token})

	// Look up cached credentials based on a hash of all the CLI arguments, the current token value, and the cluster info.
	cacheKey := struct {
		Args        []string                   `json:"args"`
		Token       string                     `json:"token"`
		ClusterInfo *clientauthv1beta1.Cluster `json:"cluster"`
	}{
		Args:        os.Args[1:],
		Token:       token,
		ClusterInfo: loadClusterInfo(),
	}
	var credCache *execcredcache.Cache
	if flags.credentialCachePath != "" {
		credCache = execcredcache.New(flags.credentialCachePath)
		if cred := credCache.Get(cacheKey); cred != nil {
			pLogger.Debug("using cached cluster credential.")
			return json.NewEncoder(out).Encode(cred)
		}
	}

	// If the concierge was configured, exchange the credential for a separate short-lived, cluster-specific credential.
	if concierge != nil {
		pLogger.Debug("exchanging static token for cluster credential", "endpoint", flags.conciergeEndpoint, "authenticator type", flags.conciergeAuthenticatorType, "authenticator name", flags.conciergeAuthenticatorName)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var err error
		cred, err = deps.exchangeToken(ctx, concierge, token)
		if err != nil {
			return fmt.Errorf("could not complete Concierge credential exchange: %w", err)
		}
		pLogger.Debug("exchanged static token for cluster credential")
	}

	// If there was a credential cache, save the resulting credential for future use. We only save to the cache if
	// the credential came from the concierge, since that's the only static token case where the cache is useful.
	if credCache != nil && concierge != nil {
		credCache.Put(cacheKey, cred)
	}

	return json.NewEncoder(out).Encode(cred)
}
