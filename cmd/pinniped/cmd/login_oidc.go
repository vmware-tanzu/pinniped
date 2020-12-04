// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/klog/v2/klogr"

	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

//nolint: gochecknoinits
func init() {
	loginCmd.AddCommand(oidcLoginCommand(oidcclient.Login))
}

func oidcLoginCommand(loginFunc func(issuer string, clientID string, opts ...oidcclient.Option) (*oidctypes.Token, error)) *cobra.Command {
	var (
		cmd = cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "oidc --issuer ISSUER --client-id CLIENT_ID",
			Short:        "Login using an OpenID Connect provider",
			SilenceUsage: true,
		}
		issuer            string
		clientID          string
		listenPort        uint16
		scopes            []string
		skipBrowser       bool
		sessionCachePath  string
		caBundlePaths     []string
		debugSessionCache bool
		requestAudience   string
	)
	cmd.Flags().StringVar(&issuer, "issuer", "", "OpenID Connect issuer URL.")
	cmd.Flags().StringVar(&clientID, "client-id", "", "OpenID Connect client ID.")
	cmd.Flags().Uint16Var(&listenPort, "listen-port", 0, "TCP port for localhost listener (authorization code flow only).")
	cmd.Flags().StringSliceVar(&scopes, "scopes", []string{"offline_access", "openid"}, "OIDC scopes to request during login.")
	cmd.Flags().BoolVar(&skipBrowser, "skip-browser", false, "Skip opening the browser (just print the URL).")
	cmd.Flags().StringVar(&sessionCachePath, "session-cache", filepath.Join(mustGetConfigDir(), "sessions.yaml"), "Path to session cache file.")
	cmd.Flags().StringSliceVar(&caBundlePaths, "ca-bundle", nil, "Path to TLS certificate authority bundle (PEM format, optional, can be repeated).")
	cmd.Flags().BoolVar(&debugSessionCache, "debug-session-cache", false, "Print debug logs related to the session cache.")
	cmd.Flags().StringVar(&requestAudience, "request-audience", "", "Request a token with an alternate audience using RF8693 token exchange.")
	mustMarkHidden(&cmd, "debug-session-cache")
	mustMarkRequired(&cmd, "issuer", "client-id")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		// Initialize the session cache.
		var sessionOptions []filesession.Option

		// If the hidden --debug-session-cache option is passed, log all the errors from the session cache with klog.
		if debugSessionCache {
			logger := klogr.New().WithName("session")
			sessionOptions = append(sessionOptions, filesession.WithErrorReporter(func(err error) {
				logger.Error(err, "error during session cache operation")
			}))
		}
		sessionCache := filesession.New(sessionCachePath, sessionOptions...)

		// Initialize the login handler.
		opts := []oidcclient.Option{
			oidcclient.WithContext(cmd.Context()),
			oidcclient.WithScopes(scopes),
			oidcclient.WithSessionCache(sessionCache),
		}

		if listenPort != 0 {
			opts = append(opts, oidcclient.WithListenPort(listenPort))
		}

		if requestAudience != "" {
			opts = append(opts, oidcclient.WithRequestAudience(requestAudience))
		}

		// --skip-browser replaces the default "browser open" function with one that prints to stderr.
		if skipBrowser {
			opts = append(opts, oidcclient.WithBrowserOpen(func(url string) error {
				cmd.PrintErr("Please log in: ", url, "\n")
				return nil
			}))
		}

		if len(caBundlePaths) > 0 {
			pool := x509.NewCertPool()
			for _, p := range caBundlePaths {
				pem, err := ioutil.ReadFile(p)
				if err != nil {
					return fmt.Errorf("could not read --ca-bundle: %w", err)
				}
				pool.AppendCertsFromPEM(pem)
			}
			tlsConfig := tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			}
			opts = append(opts, oidcclient.WithClient(&http.Client{
				Transport: &http.Transport{
					Proxy:           http.ProxyFromEnvironment,
					TLSClientConfig: &tlsConfig,
				},
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
				ExpirationTimestamp: &tok.IDToken.Expiry,
				Token:               tok.IDToken.Token,
			},
		})
	}
	return &cmd
}

// mustGetConfigDir returns a directory that follows the XDG base directory convention:
//   $XDG_CONFIG_HOME defines the base directory relative to which user specific configuration files should
//   be stored. If $XDG_CONFIG_HOME is either not set or empty, a default equal to $HOME/.config should be used.
// [1] https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
func mustGetConfigDir() string {
	const xdgAppName = "pinniped"

	if path := os.Getenv("XDG_CONFIG_HOME"); path != "" {
		return filepath.Join(path, xdgAppName)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		panic(err)
	}
	return filepath.Join(home, ".config", xdgAppName)
}
