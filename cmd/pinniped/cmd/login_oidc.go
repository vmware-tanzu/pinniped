// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/klog/v2/klogr"

	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

//nolint: gochecknoinits
func init() {
	loginCmd.AddCommand(oidcLoginCommand(oidcLoginCommandRealDeps()))
}

type oidcLoginCommandDeps struct {
	login         func(string, string, ...oidcclient.Option) (*oidctypes.Token, error)
	exchangeToken func(context.Context, *conciergeclient.Client, string) (*clientauthv1beta1.ExecCredential, error)
}

func oidcLoginCommandRealDeps() oidcLoginCommandDeps {
	return oidcLoginCommandDeps{
		login: oidcclient.Login,
		exchangeToken: func(ctx context.Context, client *conciergeclient.Client, token string) (*clientauthv1beta1.ExecCredential, error) {
			return client.ExchangeToken(ctx, token)
		},
	}
}

type oidcLoginFlags struct {
	issuer                     string
	clientID                   string
	listenPort                 uint16
	scopes                     []string
	skipBrowser                bool
	sessionCachePath           string
	caBundlePaths              []string
	caBundleData               []string
	debugSessionCache          bool
	requestAudience            string
	conciergeEnabled           bool
	conciergeAuthenticatorType string
	conciergeAuthenticatorName string
	conciergeEndpoint          string
	conciergeCABundle          string
	conciergeAPIGroupSuffix    string
	conciergeMode              conciergeMode
}

func oidcLoginCommand(deps oidcLoginCommandDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "oidc --issuer ISSUER",
			Short:        "Login using an OpenID Connect provider",
			SilenceUsage: true,
		}
		flags              oidcLoginFlags
		conciergeNamespace string // unused now
	)
	cmd.Flags().StringVar(&flags.issuer, "issuer", "", "OpenID Connect issuer URL")
	cmd.Flags().StringVar(&flags.clientID, "client-id", "pinniped-cli", "OpenID Connect client ID")
	cmd.Flags().Uint16Var(&flags.listenPort, "listen-port", 0, "TCP port for localhost listener (authorization code flow only)")
	cmd.Flags().StringSliceVar(&flags.scopes, "scopes", []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID, "pinniped:request-audience"}, "OIDC scopes to request during login")
	cmd.Flags().BoolVar(&flags.skipBrowser, "skip-browser", false, "Skip opening the browser (just print the URL)")
	cmd.Flags().StringVar(&flags.sessionCachePath, "session-cache", filepath.Join(mustGetConfigDir(), "sessions.yaml"), "Path to session cache file")
	cmd.Flags().StringSliceVar(&flags.caBundlePaths, "ca-bundle", nil, "Path to TLS certificate authority bundle (PEM format, optional, can be repeated)")
	cmd.Flags().StringSliceVar(&flags.caBundleData, "ca-bundle-data", nil, "Base64 encoded TLS certificate authority bundle (base64 encoded PEM format, optional, can be repeated)")
	cmd.Flags().BoolVar(&flags.debugSessionCache, "debug-session-cache", false, "Print debug logs related to the session cache")
	cmd.Flags().StringVar(&flags.requestAudience, "request-audience", "", "Request a token with an alternate audience using RFC8693 token exchange")
	cmd.Flags().BoolVar(&flags.conciergeEnabled, "enable-concierge", false, "Use the Concierge to login")
	cmd.Flags().StringVar(&conciergeNamespace, "concierge-namespace", "pinniped-concierge", "Namespace in which the Concierge was installed")
	cmd.Flags().StringVar(&flags.conciergeAuthenticatorType, "concierge-authenticator-type", "", "Concierge authenticator type (e.g., 'webhook', 'jwt')")
	cmd.Flags().StringVar(&flags.conciergeAuthenticatorName, "concierge-authenticator-name", "", "Concierge authenticator name")
	cmd.Flags().StringVar(&flags.conciergeEndpoint, "concierge-endpoint", "", "API base for the Concierge endpoint")
	cmd.Flags().StringVar(&flags.conciergeCABundle, "concierge-ca-bundle-data", "", "CA bundle to use when connecting to the Concierge")
	cmd.Flags().StringVar(&flags.conciergeAPIGroupSuffix, "concierge-api-group-suffix", groupsuffix.PinnipedDefaultSuffix, "Concierge API group suffix")
	cmd.Flags().Var(&flags.conciergeMode, "concierge-mode", "Concierge mode of operation")

	mustMarkHidden(cmd, "debug-session-cache")
	mustMarkRequired(cmd, "issuer")
	cmd.RunE = func(cmd *cobra.Command, args []string) error { return runOIDCLogin(cmd, deps, flags) }

	mustMarkDeprecated(cmd, "concierge-namespace", "not needed anymore")
	mustMarkHidden(cmd, "concierge-namespace")

	return cmd
}

func runOIDCLogin(cmd *cobra.Command, deps oidcLoginCommandDeps, flags oidcLoginFlags) error {
	// Initialize the session cache.
	var sessionOptions []filesession.Option

	// If the hidden --debug-session-cache option is passed, log all the errors from the session cache with klog.
	if flags.debugSessionCache {
		logger := klogr.New().WithName("session")
		sessionOptions = append(sessionOptions, filesession.WithErrorReporter(func(err error) {
			logger.Error(err, "error during session cache operation")
		}))
	}
	sessionCache := filesession.New(flags.sessionCachePath, sessionOptions...)

	// Initialize the login handler.
	opts := []oidcclient.Option{
		oidcclient.WithContext(cmd.Context()),
		oidcclient.WithScopes(flags.scopes),
		oidcclient.WithSessionCache(sessionCache),
	}

	if flags.listenPort != 0 {
		opts = append(opts, oidcclient.WithListenPort(flags.listenPort))
	}

	if flags.requestAudience != "" {
		opts = append(opts, oidcclient.WithRequestAudience(flags.requestAudience))
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

	// --skip-browser replaces the default "browser open" function with one that prints to stderr.
	if flags.skipBrowser {
		opts = append(opts, oidcclient.WithBrowserOpen(func(url string) error {
			cmd.PrintErr("Please log in: ", url, "\n")
			return nil
		}))
	}

	if len(flags.caBundlePaths) > 0 || len(flags.caBundleData) > 0 {
		client, err := makeClient(flags.caBundlePaths, flags.caBundleData)
		if err != nil {
			return err
		}
		opts = append(opts, oidcclient.WithClient(client))
	}

	// Do the basic login to get an OIDC token.
	token, err := deps.login(flags.issuer, flags.clientID, opts...)
	if err != nil {
		return fmt.Errorf("could not complete Pinniped login: %w", err)
	}
	cred := tokenCredential(token)

	// If there is no concierge configuration, return the credential directly.
	if concierge == nil {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(cred)
	}

	// If the concierge was configured, we need to do extra steps to make the credential usable.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The exact behavior depends on in which mode the Concierge is operating.
	switch flags.conciergeMode {
	case modeUnknown, modeTokenCredentialRequestAPI:
		// do a credential exchange request
		cred, err := deps.exchangeToken(ctx, concierge, token.IDToken.Token)
		if err != nil {
			return fmt.Errorf("could not complete concierge credential exchange: %w", err)
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(cred)

	case modeImpersonationProxy:
		// Put the token into a TokenCredentialRequest
		// put the TokenCredentialRequest in an ExecCredential
		req, err := execCredentialForImpersonationProxy(token.IDToken.Token, flags.conciergeAuthenticatorType, flags.conciergeAuthenticatorName, &token.IDToken.Expiry)
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(req)

	default:
		return fmt.Errorf("unsupported Concierge mode %q", flags.conciergeMode.String())
	}
}

func makeClient(caBundlePaths []string, caBundleData []string) (*http.Client, error) {
	pool := x509.NewCertPool()
	for _, p := range caBundlePaths {
		pem, err := ioutil.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("could not read --ca-bundle: %w", err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	for _, d := range caBundleData {
		pem, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			return nil, fmt.Errorf("could not read --ca-bundle-data: %w", err)
		}
		pool.AppendCertsFromPEM(pem)
	}
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
			},
		},
	}, nil
}

func tokenCredential(token *oidctypes.Token) *clientauthv1beta1.ExecCredential {
	cred := clientauthv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &clientauthv1beta1.ExecCredentialStatus{
			Token: token.IDToken.Token,
		},
	}
	if !token.IDToken.Expiry.IsZero() {
		cred.Status.ExpirationTimestamp = &token.IDToken.Expiry
	}
	return &cred
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

func execCredentialForImpersonationProxy(
	idToken string,
	conciergeAuthenticatorType string,
	conciergeAuthenticatorName string,
	tokenExpiry *metav1.Time,
) (*clientauthv1beta1.ExecCredential, error) {
	// TODO maybe de-dup this with conciergeclient.go
	// TODO reuse code from internal/testutil/impersonationtoken here to create token
	var kind string
	switch strings.ToLower(conciergeAuthenticatorType) {
	case "webhook":
		kind = "WebhookAuthenticator"
	case "jwt":
		kind = "JWTAuthenticator"
	default:
		return nil, fmt.Errorf(`invalid authenticator type: %q, supported values are "webhook" and "jwt"`, kind)
	}
	reqJSON, err := json.Marshal(&loginv1alpha1.TokenCredentialRequest{
		TypeMeta: metav1.TypeMeta{
			Kind:       "TokenCredentialRequest",
			APIVersion: loginv1alpha1.GroupName + "/v1alpha1",
		},
		Spec: loginv1alpha1.TokenCredentialRequestSpec{
			Token: idToken, // TODO
			Authenticator: corev1.TypedLocalObjectReference{
				APIGroup: &authenticationv1alpha1.SchemeGroupVersion.Group,
				Kind:     kind,
				Name:     conciergeAuthenticatorName,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error creating TokenCredentialRequest for impersonation proxy: %w", err)
	}
	encodedToken := base64.StdEncoding.EncodeToString(reqJSON)
	cred := &clientauthv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &clientauthv1beta1.ExecCredentialStatus{
			Token: encodedToken,
		},
	}
	if !tokenExpiry.IsZero() {
		cred.Status.ExpirationTimestamp = tokenExpiry
	}
	return cred, nil
}
