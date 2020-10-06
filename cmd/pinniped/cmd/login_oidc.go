// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	"go.pinniped.dev/internal/oidcclient/login"
)

//nolint: gochecknoinits
func init() {
	loginCmd.AddCommand(oidcLoginCommand(login.Run))
}

func oidcLoginCommand(loginFunc func(issuer string, clientID string, opts ...login.Option) (*login.Token, error)) *cobra.Command {
	var (
		cmd = cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "oidc --issuer ISSUER --client-id CLIENT_ID",
			Short:        "Login using an OpenID Connect provider",
			SilenceUsage: true,
		}
		issuer      string
		clientID    string
		listenPort  uint16
		scopes      []string
		skipBrowser bool
	)
	cmd.Flags().StringVar(&issuer, "issuer", "", "OpenID Connect issuer URL.")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OpenID Connect client ID.")
	cmd.Flags().Uint16Var(&listenPort, "listen-port", 0, "TCP port for localhost listener (authorization code flow only).")
	cmd.Flags().StringSliceVar(&scopes, "scopes", []string{"offline_access", "openid", "email", "profile"}, "OIDC scopes to request during login.")
	cmd.Flags().BoolVar(&skipBrowser, "skip-browser", false, "Skip opening the browser (just print the URL).")
	mustMarkRequired(&cmd, "issuer", "client-id")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		opts := []login.Option{
			login.WithContext(cmd.Context()),
			login.WithScopes(scopes),
		}

		if listenPort != 0 {
			opts = append(opts, login.WithListenPort(listenPort))
		}

		// --skip-browser replaces the default "browser open" function with one that prints to stderr.
		if skipBrowser {
			opts = append(opts, login.WithBrowserOpen(func(url string) error {
				cmd.PrintErr("Please log in: ", url, "\n")
				return nil
			}))
		}

		tok, err := loginFunc(issuer, clientID, opts...)
		if err != nil {
			return err
		}

		// Convert the token out to Kubernetes ExecCredential JSON format for output.
		return json.NewEncoder(cmd.OutOrStdout()).Encode(&clientauthenticationv1beta1.ExecCredential{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ExecCredential",
				APIVersion: "client.authentication.k8s.io/v1beta1",
			},
			Status: &clientauthenticationv1beta1.ExecCredentialStatus{
				ExpirationTimestamp: &metav1.Time{Time: tok.IDTokenExpiry},
				Token:               tok.IDToken,
			},
		})
	}
	return &cmd
}
