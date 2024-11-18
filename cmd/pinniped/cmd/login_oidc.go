// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"

	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	"go.pinniped.dev/internal/execcredcache"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/pkg/conciergeclient"
	"go.pinniped.dev/pkg/oidcclient"
	"go.pinniped.dev/pkg/oidcclient/filesession"
	"go.pinniped.dev/pkg/oidcclient/oidctypes"
)

const (
	// The user may override the flow selection made by `--upstream-identity-provider-flow` using an env var.
	// This allows the user to override their default flow selected inside their Pinniped-compatible kubeconfig file.
	// A user might want to use this env var, for example, to choose the "browser_authcode" flow when using a kubeconfig
	// which specifies "cli_password" when using an IDE plugin where there is no interactive CLI available. This allows
	// the user to use one kubeconfig file for both flows.
	upstreamIdentityProviderFlowEnvVarName = "PINNIPED_UPSTREAM_IDENTITY_PROVIDER_FLOW"

	// When using a browser-based login flow, the user may skip printing the login URL to the screen in the case
	// where the browser was launched with the login URL. This can be useful, for example, when using a console-based
	// UI like k9s, to avoid having any output to stderr which may confuse the UI. Set this env var to "true" to
	// skip printing the URL.
	skipPrintLoginURLEnvVarName = "PINNIPED_SKIP_PRINT_LOGIN_URL"

	// Set this env var to "true" to cause debug logs to be printed to stderr.
	debugEnvVarName = "PINNIPED_DEBUG"

	// The value to use for true/false env vars to enable the behavior caused by the env var.
	envVarTruthyValue = "true"
)

//nolint:gochecknoinits
func init() {
	loginCmd.AddCommand(oidcLoginCommand(oidcLoginCommandRealDeps()))
}

type oidcLoginCommandDeps struct {
	lookupEnv      func(string) (string, bool)
	login          func(string, string, ...oidcclient.Option) (*oidctypes.Token, error)
	exchangeToken  func(context.Context, *conciergeclient.Client, string) (*clientauthv1beta1.ExecCredential, error)
	optionsFactory OIDCClientOptions
}

func oidcLoginCommandRealDeps() oidcLoginCommandDeps {
	return oidcLoginCommandDeps{
		lookupEnv: os.LookupEnv,
		login:     oidcclient.Login,
		exchangeToken: func(ctx context.Context, client *conciergeclient.Client, token string) (*clientauthv1beta1.ExecCredential, error) {
			return client.ExchangeToken(ctx, token)
		},
		optionsFactory: &clientOptions{},
	}
}

type oidcLoginFlags struct {
	issuer                       string
	clientID                     string
	listenPort                   uint16
	scopes                       []string
	skipBrowser                  bool
	skipListen                   bool
	sessionCachePath             string
	caBundlePaths                []string
	caBundleData                 []string
	debugSessionCache            bool
	requestAudience              string
	conciergeEnabled             bool
	conciergeAuthenticatorType   string
	conciergeAuthenticatorName   string
	conciergeEndpoint            string
	conciergeCABundle            string
	conciergeAPIGroupSuffix      string
	credentialCachePath          string
	upstreamIdentityProviderName string
	upstreamIdentityProviderType string
	upstreamIdentityProviderFlow string
}

func oidcLoginCommand(deps oidcLoginCommandDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Args:  cobra.NoArgs,
			Use:   "oidc --issuer ISSUER",
			Short: "Login using an OpenID Connect provider",
			Long: here.Doc(
				`Login using an OpenID Connect provider

					Use "pinniped get kubeconfig" to generate a kubeconfig file which includes this
					login command in its configuration. This login command is not meant to be
					invoked directly by a user.

					This login command is a Kubernetes client-go credential plugin which is meant to
					be configured inside a kubeconfig file. (See the Kubernetes authentication
					documentation for more information about client-go credential plugins.)`,
			),
			SilenceUsage: true, // do not print usage message when commands fail
		}
		flags              oidcLoginFlags
		conciergeNamespace string // unused now
	)
	cmd.Flags().StringVar(&flags.issuer, "issuer", "", "OpenID Connect issuer URL")
	cmd.Flags().StringVar(&flags.clientID, "client-id", oidcapi.ClientIDPinnipedCLI, "OpenID Connect client ID")
	cmd.Flags().Uint16Var(&flags.listenPort, "listen-port", 0, "TCP port for localhost listener (authorization code flow only)")
	cmd.Flags().StringSliceVar(&flags.scopes, "scopes", []string{oidcapi.ScopeOfflineAccess, oidcapi.ScopeOpenID, oidcapi.ScopeRequestAudience, oidcapi.ScopeUsername, oidcapi.ScopeGroups}, "OIDC scopes to request during login")
	cmd.Flags().BoolVar(&flags.skipBrowser, "skip-browser", false, "Skip opening the browser (just print the URL)")
	cmd.Flags().BoolVar(&flags.skipListen, "skip-listen", false, "Skip starting a localhost callback listener (manual copy/paste flow only)")
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
	cmd.Flags().StringVar(&flags.credentialCachePath, "credential-cache", filepath.Join(mustGetConfigDir(), "credentials.yaml"), "Path to cluster-specific credentials cache (\"\" disables the cache)")
	cmd.Flags().StringVar(&flags.upstreamIdentityProviderName, "upstream-identity-provider-name", "", "The name of the upstream identity provider used during login with a Supervisor")
	cmd.Flags().StringVar(&flags.upstreamIdentityProviderType,
		"upstream-identity-provider-type",
		idpdiscoveryv1alpha1.IDPTypeOIDC.String(),
		fmt.Sprintf(
			"The type of the upstream identity provider used during login with a Supervisor (e.g. '%s', '%s', '%s', '%s')",
			idpdiscoveryv1alpha1.IDPTypeOIDC,
			idpdiscoveryv1alpha1.IDPTypeLDAP,
			idpdiscoveryv1alpha1.IDPTypeActiveDirectory,
			idpdiscoveryv1alpha1.IDPTypeGitHub,
		))
	cmd.Flags().StringVar(&flags.upstreamIdentityProviderFlow, "upstream-identity-provider-flow", "", fmt.Sprintf("The type of client flow to use with the upstream identity provider during login with a Supervisor (e.g. '%s', '%s')", idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode, idpdiscoveryv1alpha1.IDPFlowCLIPassword))

	// --skip-listen is mainly needed for testing. We'll leave it hidden until we have a non-testing use case.
	mustMarkHidden(cmd, "skip-listen")
	mustMarkHidden(cmd, "debug-session-cache")
	mustMarkRequired(cmd, "issuer")
	cmd.RunE = func(cmd *cobra.Command, _args []string) error { return runOIDCLogin(cmd, deps, flags) }

	mustMarkDeprecated(cmd, "concierge-namespace", "not needed anymore")
	mustMarkHidden(cmd, "concierge-namespace")

	return cmd
}

func runOIDCLogin(cmd *cobra.Command, deps oidcLoginCommandDeps, flags oidcLoginFlags) error { //nolint:funlen
	pLogger, err := SetLogLevel(cmd.Context(), deps.lookupEnv)
	if err != nil {
		plog.WarningErr("Received error while setting log level", err)
	}

	// Initialize the session cache.
	var sessionOptions []filesession.Option

	// If the hidden --debug-session-cache option is passed, log all the errors from the session cache.
	if flags.debugSessionCache {
		sessionOptions = append(sessionOptions, filesession.WithErrorReporter(func(err error) {
			pLogger.Error("error during session cache operation", err)
		}))
	}
	sessionCache := filesession.New(flags.sessionCachePath, sessionOptions...)

	// Initialize the login handler.
	opts := []oidcclient.Option{
		deps.optionsFactory.WithContext(cmd.Context()),
		deps.optionsFactory.WithLoginLogger(pLogger),
		deps.optionsFactory.WithScopes(flags.scopes),
		deps.optionsFactory.WithSessionCache(sessionCache),
	}

	skipPrintLoginURL, _ := deps.lookupEnv(skipPrintLoginURLEnvVarName)
	if skipPrintLoginURL == envVarTruthyValue {
		opts = append(opts, deps.optionsFactory.WithSkipPrintLoginURL())
	}

	if flags.listenPort != 0 {
		opts = append(opts, deps.optionsFactory.WithListenPort(flags.listenPort))
	}

	if flags.requestAudience != "" {
		opts = append(opts, deps.optionsFactory.WithRequestAudience(flags.requestAudience))
	}

	if flags.upstreamIdentityProviderName != "" {
		opts = append(opts, deps.optionsFactory.WithUpstreamIdentityProvider(
			flags.upstreamIdentityProviderName, flags.upstreamIdentityProviderType))
	}

	requestedFlow, flowSource := idpdiscoveryv1alpha1.IDPFlow(flags.upstreamIdentityProviderFlow), "--upstream-identity-provider-flow"
	if flowOverride, hasFlowOverride := deps.lookupEnv(upstreamIdentityProviderFlowEnvVarName); hasFlowOverride {
		requestedFlow, flowSource = idpdiscoveryv1alpha1.IDPFlow(flowOverride), upstreamIdentityProviderFlowEnvVarName
	}
	if requestedFlow != "" {
		opts = append(opts, deps.optionsFactory.WithLoginFlow(requestedFlow, flowSource))
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

	// --skip-browser skips opening the browser.
	if flags.skipBrowser {
		opts = append(opts, deps.optionsFactory.WithSkipBrowserOpen())
	}

	// --skip-listen skips starting the localhost callback listener.
	if flags.skipListen {
		opts = append(opts, deps.optionsFactory.WithSkipListen())
	}

	if len(flags.caBundlePaths) > 0 || len(flags.caBundleData) > 0 {
		client, err := makeClient(flags.caBundlePaths, flags.caBundleData)
		if err != nil {
			return err
		}
		opts = append(opts, deps.optionsFactory.WithClient(client))
	}
	// Look up cached credentials based on a hash of all the CLI arguments and the cluster info.
	cacheKey := struct {
		Args        []string                   `json:"args"`
		ClusterInfo *clientauthv1beta1.Cluster `json:"cluster"`
	}{
		Args:        os.Args[1:],
		ClusterInfo: loadClusterInfo(),
	}
	var credCache *execcredcache.Cache
	if flags.credentialCachePath != "" {
		credCache = execcredcache.New(flags.credentialCachePath)
		if cred := credCache.Get(cacheKey); cred != nil {
			pLogger.Debug("using cached cluster credential.")
			return json.NewEncoder(cmd.OutOrStdout()).Encode(cred)
		}
	}

	pLogger.Debug("Performing OIDC login", "issuer", flags.issuer, "client id", flags.clientID)
	// Do the basic login to get an OIDC token. Although this can return several tokens, we only need the ID token here.
	token, err := deps.login(flags.issuer, flags.clientID, opts...)
	if err != nil {
		return fmt.Errorf("could not complete Pinniped login: %w", err)
	}
	cred := tokenCredential(token.IDToken)

	// If the concierge was configured, exchange the credential for a separate short-lived, cluster-specific credential.
	if concierge != nil {
		pLogger.Debug("Exchanging token for cluster credential", "endpoint", flags.conciergeEndpoint, "authenticator type", flags.conciergeAuthenticatorType, "authenticator name", flags.conciergeAuthenticatorName)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		cred, err = deps.exchangeToken(ctx, concierge, token.IDToken.Token)
		if err != nil {
			return fmt.Errorf("could not complete Concierge credential exchange: %w", err)
		}
		pLogger.Debug("Successfully exchanged token for cluster credential.")
	} else {
		pLogger.Debug("No concierge configured, skipping token credential exchange")
	}

	// If there was a credential cache, save the resulting credential for future use.
	if credCache != nil {
		pLogger.Debug("caching cluster credential for future use.")
		credCache.Put(cacheKey, cred)
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(cred)
}

func makeClient(caBundlePaths []string, caBundleData []string) (*http.Client, error) {
	pool := x509.NewCertPool()
	for _, p := range caBundlePaths {
		pem, err := os.ReadFile(p)
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
	return phttp.Default(pool), nil
}

func tokenCredential(idToken *oidctypes.IDToken) *clientauthv1beta1.ExecCredential {
	cred := clientauthv1beta1.ExecCredential{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ExecCredential",
			APIVersion: "client.authentication.k8s.io/v1beta1",
		},
		Status: &clientauthv1beta1.ExecCredentialStatus{
			Token: idToken.Token,
		},
	}
	if !idToken.Expiry.IsZero() {
		cred.Status.ExpirationTimestamp = &idToken.Expiry
	}
	return &cred
}

func SetLogLevel(ctx context.Context, lookupEnv func(string) (string, bool)) (plog.Logger, error) {
	debug, _ := lookupEnv(debugEnvVarName)
	if debug == envVarTruthyValue {
		err := plog.ValidateAndSetLogLevelAndFormatGlobally(ctx, plog.LogSpec{Level: plog.LevelDebug, Format: plog.FormatCLI})
		if err != nil {
			return nil, err
		}
	}
	return plog.New(), nil
}

/*
mustGetConfigDir returns a directory that follows the XDG base directory convention:

	$XDG_CONFIG_HOME defines the base directory relative to which user specific configuration files should
	be stored. If $XDG_CONFIG_HOME is either not set or empty, a default equal to $HOME/.config should be used.

[1] https://specifications.freedesktop.org/basedir-spec/basedir-spec-latest.html
*/
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
