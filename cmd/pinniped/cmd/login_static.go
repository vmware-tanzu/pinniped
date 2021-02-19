// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

//nolint: gochecknoinits
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
}

func staticLoginCommand(deps staticLoginDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "static [--token TOKEN] [--token-env TOKEN_NAME]",
			Short:        "Login using a static token",
			SilenceUsage: true,
		}
		flags              staticLoginParams
		conciergeNamespace string // unused now
	)
	cmd.Flags().StringVar(&flags.staticToken, "token", "", "Static token to present during login")
	cmd.Flags().StringVar(&flags.staticTokenEnvName, "token-env", "", "Environment variable containing a static token")
	cmd.Flags().BoolVar(&flags.conciergeEnabled, "enable-concierge", false, "Exchange the token with the Pinniped concierge during login")
	cmd.Flags().StringVar(&conciergeNamespace, "concierge-namespace", "pinniped-concierge", "Namespace in which the concierge was installed")
	cmd.Flags().StringVar(&flags.conciergeAuthenticatorType, "concierge-authenticator-type", "", "Concierge authenticator type (e.g., 'webhook', 'jwt')")
	cmd.Flags().StringVar(&flags.conciergeAuthenticatorName, "concierge-authenticator-name", "", "Concierge authenticator name")
	cmd.Flags().StringVar(&flags.conciergeEndpoint, "concierge-endpoint", "", "API base for the Pinniped concierge endpoint")
	cmd.Flags().StringVar(&flags.conciergeCABundle, "concierge-ca-bundle-data", "", "CA bundle to use when connecting to the concierge")
	cmd.Flags().StringVar(&flags.conciergeAPIGroupSuffix, "concierge-api-group-suffix", groupsuffix.PinnipedDefaultSuffix, "Concierge API group suffix")
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return runStaticLogin(cmd.OutOrStdout(), deps, flags) }

	mustMarkDeprecated(cmd, "concierge-namespace", "not needed anymore")
	mustMarkHidden(cmd, "concierge-namespace")

	return cmd
}

func runStaticLogin(out io.Writer, deps staticLoginDeps, flags staticLoginParams) error {
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
		)
		if err != nil {
			return fmt.Errorf("invalid concierge parameters: %w", err)
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
	cred := tokenCredential(&oidctypes.Token{IDToken: &oidctypes.IDToken{Token: token}})

	// Exchange that token with the concierge, if configured.
	if concierge != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		var err error
		cred, err = deps.exchangeToken(ctx, concierge, token)
		if err != nil {
			return fmt.Errorf("could not complete concierge credential exchange: %w", err)
		}
	}
	return json.NewEncoder(out).Encode(cred)
}
