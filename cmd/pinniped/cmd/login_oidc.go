// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/coreos/go-oidc"
	"github.com/pkg/browser"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"

	"go.pinniped.dev/internal/oidc/pkce"
	"go.pinniped.dev/internal/oidc/state"
)

//nolint: gochecknoinits
func init() {
	loginCmd.AddCommand((&oidcLoginParams{
		generateState: state.Generate,
		generatePKCE:  pkce.Generate,
		openURL:       browser.OpenURL,
	}).cmd())
}

type oidcLoginParams struct {
	// These parameters capture CLI flags.
	issuer      string
	clientID    string
	listenPort  uint16
	scopes      []string
	skipBrowser bool
	usePKCE     bool

	// These parameters capture dependencies that we want to mock during testing.
	generateState func() (state.State, error)
	generatePKCE  func() (pkce.Code, error)
	openURL       func(string) error
}

func (o *oidcLoginParams) cmd() *cobra.Command {
	cmd := cobra.Command{
		Args:         cobra.NoArgs,
		Use:          "oidc --issuer ISSUER --client-id CLIENT_ID",
		Short:        "Login using an OpenID Connect provider",
		RunE:         o.runE,
		SilenceUsage: true,
	}
	cmd.Flags().StringVar(&o.issuer, "issuer", "", "OpenID Connect issuer URL.")
	cmd.Flags().StringVar(&o.clientID, "client-id", "", "OpenID Connect client ID.")
	cmd.Flags().Uint16Var(&o.listenPort, "listen-port", 48095, "TCP port for localhost listener (authorization code flow only).")
	cmd.Flags().StringSliceVar(&o.scopes, "scopes", []string{"offline_access", "openid", "email", "profile"}, "OIDC scopes to request during login.")
	cmd.Flags().BoolVar(&o.skipBrowser, "skip-browser", false, "Skip opening the browser (just print the URL).")
	cmd.Flags().BoolVar(&o.usePKCE, "use-pkce", true, "Use Proof Key for Code Exchange (RFC 7636) during login.")
	mustMarkRequired(&cmd, "issuer", "client-id")
	return &cmd
}

func (o *oidcLoginParams) runE(cmd *cobra.Command, args []string) error {
	metadata, err := oidc.NewProvider(cmd.Context(), o.issuer)
	if err != nil {
		return fmt.Errorf("could not perform OIDC discovery for %q: %w", o.issuer, err)
	}

	cfg := oauth2.Config{
		ClientID:    o.clientID,
		Endpoint:    metadata.Endpoint(),
		RedirectURL: fmt.Sprintf("http://localhost:%d/callback", o.listenPort),
		Scopes:      o.scopes,
	}

	authCodeOptions := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

	stateParam, err := o.generateState()
	if err != nil {
		return fmt.Errorf("could not generate OIDC state parameter: %w", err)
	}

	var pkceCode pkce.Code
	if o.usePKCE {
		pkceCode, err = o.generatePKCE()
		if err != nil {
			return fmt.Errorf("could not generate OIDC PKCE parameter: %w", err)
		}
		authCodeOptions = append(authCodeOptions, pkceCode.Challenge(), pkceCode.Method())
	}

	// If --skip-browser was passed, override the default browser open function with a Printf() call.
	openURL := o.openURL
	if o.skipBrowser {
		openURL = func(s string) error {
			cmd.PrintErr("Please log in: ", s, "\n")
			return nil
		}
	}

	authorizeURL := cfg.AuthCodeURL(stateParam.String(), authCodeOptions...)
	if err := openURL(authorizeURL); err != nil {
		return fmt.Errorf("could not open browser (run again with --skip-browser?): %w", err)
	}

	return nil
}
