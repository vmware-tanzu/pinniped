// Copyright 2020-2025 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Adds handlers for various dynamic auth plugins in client-go
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	aggregatorclient "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	idpdiscoveryv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idpdiscovery/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
)

type kubeconfigDeps struct {
	getenv        func(key string) string
	getPathToSelf func() (string, error)
	getClientsets getClientsetsFunc
	log           plog.MinLogger
}

func kubeconfigRealDeps() kubeconfigDeps {
	return kubeconfigDeps{
		getenv:        os.Getenv,
		getPathToSelf: os.Executable,
		getClientsets: getRealClientsets,
		log:           plog.New(),
	}
}

//nolint:gochecknoinits
func init() {
	getCmd.AddCommand(kubeconfigCommand(kubeconfigRealDeps()))
}

type getKubeconfigOIDCParams struct {
	issuer            string
	clientID          string
	listenPort        uint16
	scopes            []string
	skipBrowser       bool
	skipListen        bool
	sessionCachePath  string
	debugSessionCache bool
	caBundle          caBundleFlag
	requestAudience   string
	upstreamIDPName   string
	upstreamIDPType   string
	upstreamIDPFlow   string
}

type getKubeconfigConciergeParams struct {
	disabled          bool
	credentialIssuer  string
	authenticatorName string
	authenticatorType string
	apiGroupSuffix    string
	caBundle          caBundleFlag
	endpoint          string
	mode              conciergeModeFlag
	skipWait          bool
}

type getKubeconfigParams struct {
	kubeconfigPath            string
	kubeconfigContextOverride string
	skipValidate              bool
	timeout                   time.Duration
	outputPath                string
	staticToken               string
	staticTokenEnvName        string
	oidc                      getKubeconfigOIDCParams
	concierge                 getKubeconfigConciergeParams
	generatedNameSuffix       string
	credentialCachePath       string
	credentialCachePathSet    bool
	installHint               string
	pinnipedCliPath           string
}

type discoveryResponseScopesSupported struct {
	// Same as ScopesSupported in the Supervisor's discovery handler's struct.
	ScopesSupported []string `json:"scopes_supported"`
}

func kubeconfigCommand(deps kubeconfigDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "kubeconfig",
			Short:        "Generate a Pinniped-based kubeconfig for a cluster",
			SilenceUsage: true, // do not print usage message when commands fail
		}
		flags     getKubeconfigParams
		namespace string // unused now
	)

	f := cmd.Flags()
	f.StringVar(&flags.staticToken, "static-token", "", "Instead of doing an OIDC-based login, specify a static token")
	f.StringVar(&flags.staticTokenEnvName, "static-token-env", "", "Instead of doing an OIDC-based login, read a static token from the environment")

	f.BoolVar(&flags.concierge.disabled, "no-concierge", false, "Generate a configuration which does not use the Concierge, but sends the credential to the cluster directly")
	f.StringVar(&namespace, "concierge-namespace", "pinniped-concierge", "Namespace in which the Concierge was installed")
	f.StringVar(&flags.concierge.credentialIssuer, "concierge-credential-issuer", "", "Concierge CredentialIssuer object to use for autodiscovery (default: autodiscover)")
	f.StringVar(&flags.concierge.authenticatorType, "concierge-authenticator-type", "", "Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)")
	f.StringVar(&flags.concierge.authenticatorName, "concierge-authenticator-name", "", "Concierge authenticator name (default: autodiscover)")
	f.StringVar(&flags.concierge.apiGroupSuffix, "concierge-api-group-suffix", groupsuffix.PinnipedDefaultSuffix, "Concierge API group suffix")
	f.BoolVar(&flags.concierge.skipWait, "concierge-skip-wait", false, "Skip waiting for any pending Concierge strategies to become ready (default: false)")

	f.Var(&flags.concierge.caBundle, "concierge-ca-bundle", "Path to TLS certificate authority bundle (PEM format, optional, can be repeated) to use when connecting to the Concierge")
	f.StringVar(&flags.concierge.endpoint, "concierge-endpoint", "", "API base for the Concierge endpoint")
	f.Var(&flags.concierge.mode, "concierge-mode", "Concierge mode of operation")

	f.StringVar(&flags.oidc.issuer, "oidc-issuer", "", "OpenID Connect issuer URL (default: autodiscover)")
	f.StringVar(&flags.oidc.clientID, "oidc-client-id", oidcapi.ClientIDPinnipedCLI, "OpenID Connect client ID (default: autodiscover)")
	f.Uint16Var(&flags.oidc.listenPort, "oidc-listen-port", 0, "TCP port for localhost listener (authorization code flow only)")
	f.StringSliceVar(&flags.oidc.scopes, "oidc-scopes", []string{oidcapi.ScopeOfflineAccess, oidcapi.ScopeOpenID, oidcapi.ScopeRequestAudience, oidcapi.ScopeUsername, oidcapi.ScopeGroups}, "OpenID Connect scopes to request during login")
	f.BoolVar(&flags.oidc.skipBrowser, "oidc-skip-browser", false, "During OpenID Connect login, skip opening the browser (just print the URL)")
	f.BoolVar(&flags.oidc.skipListen, "oidc-skip-listen", false, "During OpenID Connect login, skip starting a localhost callback listener (manual copy/paste flow only)")
	f.StringVar(&flags.oidc.sessionCachePath, "oidc-session-cache", "", "Path to OpenID Connect session cache file")
	f.Var(&flags.oidc.caBundle, "oidc-ca-bundle", "Path to TLS certificate authority bundle (PEM format, optional, can be repeated)")
	f.BoolVar(&flags.oidc.debugSessionCache, "oidc-debug-session-cache", false, "Print debug logs related to the OpenID Connect session cache")
	f.StringVar(&flags.oidc.requestAudience, "oidc-request-audience", "", "Request a token with an alternate audience using RFC8693 token exchange")
	f.StringVar(&flags.oidc.upstreamIDPName, "upstream-identity-provider-name", "", "The name of the upstream identity provider used during login with a Supervisor")
	f.StringVar(
		&flags.oidc.upstreamIDPType,
		"upstream-identity-provider-type",
		"",
		fmt.Sprintf(
			"The type of the upstream identity provider used during login with a Supervisor (e.g. '%s', '%s', '%s', '%s')",
			idpdiscoveryv1alpha1.IDPTypeOIDC,
			idpdiscoveryv1alpha1.IDPTypeLDAP,
			idpdiscoveryv1alpha1.IDPTypeActiveDirectory,
			idpdiscoveryv1alpha1.IDPTypeGitHub,
		),
	)
	f.StringVar(&flags.oidc.upstreamIDPFlow, "upstream-identity-provider-flow", "", fmt.Sprintf("The type of client flow to use with the upstream identity provider during login with a Supervisor (e.g. '%s', '%s')", idpdiscoveryv1alpha1.IDPFlowCLIPassword, idpdiscoveryv1alpha1.IDPFlowBrowserAuthcode))
	f.StringVar(&flags.kubeconfigPath, "kubeconfig", deps.getenv("KUBECONFIG"), "Path to kubeconfig file")
	f.StringVar(&flags.kubeconfigContextOverride, "kubeconfig-context", "", "Kubeconfig context name (default: current active context)")
	f.BoolVar(&flags.skipValidate, "skip-validation", false, "Skip final validation of the kubeconfig (default: false)")
	f.DurationVar(&flags.timeout, "timeout", 10*time.Minute, "Timeout for autodiscovery and validation")
	f.StringVarP(&flags.outputPath, "output", "o", "", "Output file path (default: stdout)")
	f.StringVar(&flags.generatedNameSuffix, "generated-name-suffix", "-pinniped", "Suffix to append to generated cluster, context, user kubeconfig entries")
	f.StringVar(&flags.credentialCachePath, "credential-cache", "", "Path to cluster-specific credentials cache")
	f.StringVar(&flags.pinnipedCliPath, "pinniped-cli-path", "", "Full path or executable name for the Pinniped CLI binary to be embedded in the resulting kubeconfig output (e.g. 'pinniped') (default: full path of the binary used to execute this command)")
	f.StringVar(&flags.installHint, "install-hint", "The pinniped CLI does not appear to be installed.  See https://get.pinniped.dev/cli for more details", "This text is shown to the user when the pinniped CLI is not installed.")

	mustMarkHidden(cmd,
		"oidc-debug-session-cache",
		"oidc-skip-listen", // --oidc-skip-listen is mainly needed for testing. We'll leave it hidden until we have a non-testing use case.
		"concierge-namespace",
	)

	mustMarkDeprecated(cmd, "concierge-namespace", "not needed anymore")

	cmd.RunE = func(cmd *cobra.Command, _args []string) error {
		if flags.outputPath != "" {
			out, err := os.Create(flags.outputPath)
			if err != nil {
				return fmt.Errorf("could not open output file: %w", err)
			}
			defer func() { _ = out.Close() }()
			cmd.SetOut(out)
		}
		flags.credentialCachePathSet = cmd.Flags().Changed("credential-cache")
		return runGetKubeconfig(cmd.Context(), cmd.OutOrStdout(), deps, flags)
	}
	return cmd
}

func runGetKubeconfig(ctx context.Context, out io.Writer, deps kubeconfigDeps, flags getKubeconfigParams) error {
	ctx, cancel := context.WithTimeout(ctx, flags.timeout)
	defer cancel()

	// the log statements in this file assume that Info logs are unconditionally printed, so we set the global level to info
	if err := plog.ValidateAndSetLogLevelAndFormatGlobally(ctx, plog.LogSpec{Level: plog.LevelInfo, Format: plog.FormatCLI}); err != nil {
		return err
	}

	// Validate api group suffix and immediately return an error if it is invalid.
	if err := groupsuffix.Validate(flags.concierge.apiGroupSuffix); err != nil {
		return fmt.Errorf("invalid API group suffix: %w", err)
	}

	clientConfig := newClientConfig(flags.kubeconfigPath, flags.kubeconfigContextOverride)
	currentKubeConfig, err := clientConfig.RawConfig()
	if err != nil {
		return fmt.Errorf("could not load --kubeconfig: %w", err)
	}
	currentKubeconfigNames, err := getCurrentContext(currentKubeConfig, flags)
	if err != nil {
		return fmt.Errorf("could not load --kubeconfig/--kubeconfig-context: %w", err)
	}
	cluster := currentKubeConfig.Clusters[currentKubeconfigNames.ClusterName]
	conciergeClient, kubeClient, aggregatorClient, err := deps.getClientsets(clientConfig, flags.concierge.apiGroupSuffix)
	if err != nil {
		return fmt.Errorf("could not configure Kubernetes client: %w", err)
	}

	// Generate the new context/cluster/user names by appending the --generated-name-suffix to the original values.
	newKubeconfigNames := &kubeconfigNames{
		ContextName: currentKubeconfigNames.ContextName + flags.generatedNameSuffix,
		UserName:    currentKubeconfigNames.UserName + flags.generatedNameSuffix,
		ClusterName: currentKubeconfigNames.ClusterName + flags.generatedNameSuffix,
	}

	if !flags.concierge.disabled {
		// Look up the Concierge's CredentialIssuer, and optionally wait for it to have no pending strategies showing in its status.
		credentialIssuer, err := waitForCredentialIssuer(ctx, conciergeClient, flags, deps)
		if err != nil {
			return err
		}

		// Decide which Concierge authenticator should be used in the resulting kubeconfig.
		authenticator, err := lookupAuthenticator(
			conciergeClient,
			flags.concierge.authenticatorType,
			flags.concierge.authenticatorName,
			deps.log,
		)
		if err != nil {
			return err
		}

		// Discover from the CredentialIssuer how the resulting kubeconfig should be configured to talk to this Concierge.
		if err := discoverConciergeParams(credentialIssuer, &flags, cluster, deps.log); err != nil {
			return err
		}

		// Discover how the resulting kubeconfig should interact with the selected authenticator.
		// For a JWTAuthenticator, this includes discovering how to talk to the OIDC issuer configured in its spec fields.
		if err := discoverAuthenticatorParams(ctx, authenticator, &flags, kubeClient, aggregatorClient, deps.log); err != nil {
			return err
		}

		// Point kubectl at the concierge endpoint.
		cluster.Server = flags.concierge.endpoint
		cluster.CertificateAuthorityData = flags.concierge.caBundle
	}

	if len(flags.oidc.issuer) > 0 {
		// The OIDC provider may or may not be a Pinniped Supervisor. Find out.
		err = pinnipedSupervisorDiscovery(ctx, &flags, deps.log)
		if err != nil {
			return err
		}
	}

	execConfig, err := newExecConfig(deps, flags)
	if err != nil {
		return err
	}

	kubeconfig := newExecKubeconfig(cluster, execConfig, newKubeconfigNames)
	if err := validateKubeconfig(ctx, flags, kubeconfig, deps.log); err != nil {
		return err
	}

	return writeConfigAsYAML(out, kubeconfig)
}

func newExecConfig(deps kubeconfigDeps, flags getKubeconfigParams) (*clientcmdapi.ExecConfig, error) {
	execConfig := &clientcmdapi.ExecConfig{
		APIVersion:         clientauthenticationv1beta1.SchemeGroupVersion.String(),
		Args:               []string{},
		Env:                []clientcmdapi.ExecEnvVar{},
		ProvideClusterInfo: true,
	}

	execConfig.InstallHint = flags.installHint
	var err error
	execConfig.Command, err = func() (string, error) {
		if flags.pinnipedCliPath != "" {
			return flags.pinnipedCliPath, nil
		}
		return deps.getPathToSelf()
	}()
	if err != nil {
		return nil, fmt.Errorf("could not determine the Pinniped executable path: %w", err)
	}

	if !flags.concierge.disabled {
		// Append the flags to configure the Concierge credential exchange at runtime.
		execConfig.Args = append(execConfig.Args,
			"--enable-concierge",
			"--concierge-api-group-suffix="+flags.concierge.apiGroupSuffix,
			"--concierge-authenticator-name="+flags.concierge.authenticatorName,
			"--concierge-authenticator-type="+flags.concierge.authenticatorType,
			"--concierge-endpoint="+flags.concierge.endpoint,
			"--concierge-ca-bundle-data="+base64.StdEncoding.EncodeToString(flags.concierge.caBundle),
		)
	}

	// If --credential-cache is set, pass it through.
	if flags.credentialCachePathSet {
		execConfig.Args = append(execConfig.Args, "--credential-cache="+flags.credentialCachePath)
	}

	// If one of the --static-* flags was passed, output a config that runs `pinniped login static`.
	if flags.staticToken != "" || flags.staticTokenEnvName != "" {
		if flags.staticToken != "" && flags.staticTokenEnvName != "" {
			return nil, fmt.Errorf("only one of --static-token and --static-token-env can be specified")
		}
		execConfig.Args = slices.Concat([]string{"login", "static"}, execConfig.Args)
		if flags.staticToken != "" {
			execConfig.Args = append(execConfig.Args, "--token="+flags.staticToken)
		}
		if flags.staticTokenEnvName != "" {
			execConfig.Args = append(execConfig.Args, "--token-env="+flags.staticTokenEnvName)
		}
		return execConfig, nil
	}

	// Otherwise continue to parse the OIDC-related flags and output a config that runs `pinniped login oidc`.
	execConfig.Args = slices.Concat([]string{"login", "oidc"}, execConfig.Args)
	if flags.oidc.issuer == "" {
		return nil, fmt.Errorf("could not autodiscover --oidc-issuer and none was provided")
	}
	execConfig.Args = append(execConfig.Args,
		"--issuer="+flags.oidc.issuer,
		"--client-id="+flags.oidc.clientID,
		"--scopes="+strings.Join(flags.oidc.scopes, ","),
	)
	if flags.oidc.skipBrowser {
		execConfig.Args = append(execConfig.Args, "--skip-browser")
	}
	if flags.oidc.skipListen {
		execConfig.Args = append(execConfig.Args, "--skip-listen")
	}
	if flags.oidc.listenPort != 0 {
		execConfig.Args = append(execConfig.Args, "--listen-port="+strconv.Itoa(int(flags.oidc.listenPort)))
	}
	if len(flags.oidc.caBundle) != 0 {
		execConfig.Args = append(execConfig.Args, "--ca-bundle-data="+base64.StdEncoding.EncodeToString(flags.oidc.caBundle))
	}
	if flags.oidc.sessionCachePath != "" {
		execConfig.Args = append(execConfig.Args, "--session-cache="+flags.oidc.sessionCachePath)
	}
	if flags.oidc.debugSessionCache {
		execConfig.Args = append(execConfig.Args, "--debug-session-cache")
	}
	if flags.oidc.requestAudience != "" {
		if strings.Contains(flags.oidc.requestAudience, ".pinniped.dev") {
			return nil, fmt.Errorf("request audience is not allowed to include the substring '.pinniped.dev': %s", flags.oidc.requestAudience)
		}
		execConfig.Args = append(execConfig.Args, "--request-audience="+flags.oidc.requestAudience)
	}
	if flags.oidc.upstreamIDPName != "" {
		execConfig.Args = append(execConfig.Args, "--upstream-identity-provider-name="+flags.oidc.upstreamIDPName)
	}
	if flags.oidc.upstreamIDPType != "" {
		execConfig.Args = append(execConfig.Args, "--upstream-identity-provider-type="+flags.oidc.upstreamIDPType)
	}
	if flags.oidc.upstreamIDPFlow != "" {
		execConfig.Args = append(execConfig.Args, "--upstream-identity-provider-flow="+flags.oidc.upstreamIDPFlow)
	}

	return execConfig, nil
}

type kubeconfigNames struct{ ContextName, UserName, ClusterName string }

func getCurrentContext(currentKubeConfig clientcmdapi.Config, flags getKubeconfigParams) (*kubeconfigNames, error) {
	contextName := currentKubeConfig.CurrentContext
	if flags.kubeconfigContextOverride != "" {
		contextName = flags.kubeconfigContextOverride
	}
	ctx := currentKubeConfig.Contexts[contextName]
	if ctx == nil {
		return nil, fmt.Errorf("no such context %q", contextName)
	}
	if _, exists := currentKubeConfig.Clusters[ctx.Cluster]; !exists {
		return nil, fmt.Errorf("no such cluster %q", ctx.Cluster)
	}
	if _, exists := currentKubeConfig.AuthInfos[ctx.AuthInfo]; !exists {
		return nil, fmt.Errorf("no such user %q", ctx.AuthInfo)
	}
	return &kubeconfigNames{ContextName: contextName, UserName: ctx.AuthInfo, ClusterName: ctx.Cluster}, nil
}

func waitForCredentialIssuer(ctx context.Context, clientset conciergeclientset.Interface, flags getKubeconfigParams, deps kubeconfigDeps) (*conciergeconfigv1alpha1.CredentialIssuer, error) {
	credentialIssuer, err := lookupCredentialIssuer(clientset, flags.concierge.credentialIssuer, deps.log)
	if err != nil {
		return nil, err
	}

	if !flags.concierge.skipWait {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		deadline, _ := ctx.Deadline()
		attempts := 1

		for hasPendingStrategy(credentialIssuer) {
			logStrategies(credentialIssuer, deps.log)
			deps.log.Info("waiting for CredentialIssuer pending strategies to finish",
				"attempts", attempts,
				"remaining", time.Until(deadline).Round(time.Second).String(),
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-ticker.C:
				credentialIssuer, err = lookupCredentialIssuer(clientset, flags.concierge.credentialIssuer, deps.log)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return credentialIssuer, nil
}

func discoverConciergeParams(credentialIssuer *conciergeconfigv1alpha1.CredentialIssuer, flags *getKubeconfigParams, v1Cluster *clientcmdapi.Cluster, log plog.MinLogger) error {
	// Autodiscover the --concierge-mode.
	frontend, err := getConciergeFrontend(credentialIssuer, flags.concierge.mode)
	if err != nil {
		logStrategies(credentialIssuer, log)
		return err
	}

	// Auto-set --concierge-mode if it wasn't explicitly set.
	if flags.concierge.mode == modeUnknown {
		switch frontend.Type {
		case conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType:
			log.Info("discovered Concierge operating in TokenCredentialRequest API mode")
			flags.concierge.mode = modeTokenCredentialRequestAPI
		case conciergeconfigv1alpha1.ImpersonationProxyFrontendType:
			log.Info("discovered Concierge operating in impersonation proxy mode")
			flags.concierge.mode = modeImpersonationProxy
		}
	}

	// Auto-set --concierge-endpoint if it wasn't explicitly set.
	if flags.concierge.endpoint == "" {
		switch frontend.Type {
		case conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType:
			flags.concierge.endpoint = v1Cluster.Server
		case conciergeconfigv1alpha1.ImpersonationProxyFrontendType:
			flags.concierge.endpoint = frontend.ImpersonationProxyInfo.Endpoint
		}
		log.Info("discovered Concierge endpoint", "endpoint", flags.concierge.endpoint)
	}

	// Auto-set --concierge-ca-bundle if it wasn't explicitly set..
	if len(flags.concierge.caBundle) == 0 {
		switch frontend.Type {
		case conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType:
			flags.concierge.caBundle = v1Cluster.CertificateAuthorityData
		case conciergeconfigv1alpha1.ImpersonationProxyFrontendType:
			data, err := base64.StdEncoding.DecodeString(frontend.ImpersonationProxyInfo.CertificateAuthorityData)
			if err != nil {
				return fmt.Errorf("autodiscovered Concierge CA bundle is invalid: %w", err)
			}
			flags.concierge.caBundle = data
		}
		log.Info("discovered Concierge certificate authority bundle", "roots", countCACerts(flags.concierge.caBundle))
	}
	return nil
}

func logStrategies(credentialIssuer *conciergeconfigv1alpha1.CredentialIssuer, log plog.MinLogger) {
	for _, strategy := range credentialIssuer.Status.Strategies {
		log.Info("found CredentialIssuer strategy",
			"type", strategy.Type,
			"status", strategy.Status,
			"reason", strategy.Reason,
			"message", strategy.Message,
		)
	}
}

func discoverAuthenticatorParams(
	ctx context.Context,
	authenticator metav1.Object,
	flags *getKubeconfigParams,
	kubeClient kubernetes.Interface,
	aggregatorClient aggregatorclient.Interface,
	log plog.MinLogger,
) error {
	switch auth := authenticator.(type) {
	case *authenticationv1alpha1.WebhookAuthenticator:
		// If the --concierge-authenticator-type/--concierge-authenticator-name flags were not set explicitly, set
		// them to point at the discovered WebhookAuthenticator.
		if flags.concierge.authenticatorType == "" && flags.concierge.authenticatorName == "" {
			log.Info("discovered WebhookAuthenticator", "name", auth.Name)
			flags.concierge.authenticatorType = "webhook"
			flags.concierge.authenticatorName = auth.Name
		}
	case *authenticationv1alpha1.JWTAuthenticator:
		// If the --concierge-authenticator-type/--concierge-authenticator-name flags were not set explicitly, set
		// them to point at the discovered JWTAuthenticator.
		if flags.concierge.authenticatorType == "" && flags.concierge.authenticatorName == "" {
			log.Info("discovered JWTAuthenticator", "name", auth.Name)
			flags.concierge.authenticatorType = "jwt"
			flags.concierge.authenticatorName = auth.Name
		}

		// If the --oidc-issuer flag was not set explicitly, default it to the spec.issuer field of the JWTAuthenticator.
		if flags.oidc.issuer == "" {
			log.Info("discovered OIDC issuer", "issuer", auth.Spec.Issuer)
			flags.oidc.issuer = auth.Spec.Issuer
		}

		// If the --oidc-request-audience flag was not set explicitly, default it to the spec.audience field of the JWTAuthenticator.
		if flags.oidc.requestAudience == "" {
			log.Info("discovered OIDC audience", "audience", auth.Spec.Audience)
			flags.oidc.requestAudience = auth.Spec.Audience
		}

		// If the --oidc-ca-bundle flags was not set explicitly, default it to the
		// spec.tls.certificateAuthorityData field of the JWTAuthenticator, if that field is set, or else
		// try to discover it from the spec.tls.certificateAuthorityDataSource, if that field is set.
		if len(flags.oidc.caBundle) == 0 && auth.Spec.TLS != nil {
			err := discoverOIDCCABundle(ctx, auth, flags, kubeClient, aggregatorClient, log)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func discoverOIDCCABundle(
	ctx context.Context,
	jwtAuthenticator *authenticationv1alpha1.JWTAuthenticator,
	flags *getKubeconfigParams,
	kubeClient kubernetes.Interface,
	aggregatorClient aggregatorclient.Interface,
	log plog.MinLogger,
) error {
	if jwtAuthenticator.Spec.TLS.CertificateAuthorityData != "" {
		decodedCABundleData, err := base64.StdEncoding.DecodeString(jwtAuthenticator.Spec.TLS.CertificateAuthorityData)
		if err != nil {
			return fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator %s has invalid spec.tls.certificateAuthorityData: %w", jwtAuthenticator.Name, err)
		}
		log.Info("discovered OIDC CA bundle", "roots", countCACerts(decodedCABundleData))
		flags.oidc.caBundle = decodedCABundleData
	} else if jwtAuthenticator.Spec.TLS.CertificateAuthorityDataSource != nil {
		caBundleData, err := discoverOIDCCABundleFromCertificateAuthorityDataSource(
			ctx, jwtAuthenticator, flags.concierge.apiGroupSuffix, kubeClient, aggregatorClient, log)
		if err != nil {
			return err
		}
		flags.oidc.caBundle = caBundleData
	}
	return nil
}

func discoverOIDCCABundleFromCertificateAuthorityDataSource(
	ctx context.Context,
	jwtAuthenticator *authenticationv1alpha1.JWTAuthenticator,
	apiGroupSuffix string,
	kubeClient kubernetes.Interface,
	aggregatorClient aggregatorclient.Interface,
	log plog.MinLogger,
) ([]byte, error) {
	conciergeNamespace, err := discoverConciergeNamespace(ctx, apiGroupSuffix, aggregatorClient)
	if err != nil {
		return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but encountered error discovering namespace of Concierge for JWTAuthenticator %s: %w", jwtAuthenticator.Name, err)
	}
	log.Info("discovered Concierge namespace for API group suffix", "apiGroupSuffix", apiGroupSuffix)

	var caBundleData []byte
	var keyExisted bool
	caSource := jwtAuthenticator.Spec.TLS.CertificateAuthorityDataSource

	// Note that the Kind, Name, and Key fields must all be non-empty, and Kind must be Secret or ConfigMap, due to CRD validations.
	switch caSource.Kind {
	case authenticationv1alpha1.CertificateAuthorityDataSourceKindConfigMap:
		caBundleConfigMap, err := kubeClient.CoreV1().ConfigMaps(conciergeNamespace).Get(ctx, caSource.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but encountered error getting %s %s/%s specified by JWTAuthenticator %s spec.tls.certificateAuthorityDataSource: %w",
				caSource.Kind, conciergeNamespace, caSource.Name, jwtAuthenticator.Name, err)
		}
		var caBundleDataStr string
		caBundleDataStr, keyExisted = caBundleConfigMap.Data[caSource.Key]
		caBundleData = []byte(caBundleDataStr)
	case authenticationv1alpha1.CertificateAuthorityDataSourceKindSecret:
		caBundleSecret, err := kubeClient.CoreV1().Secrets(conciergeNamespace).Get(ctx, caSource.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but encountered error getting %s %s/%s specified by JWTAuthenticator %s spec.tls.certificateAuthorityDataSource: %w",
				caSource.Kind, conciergeNamespace, caSource.Name, jwtAuthenticator.Name, err)
		}
		caBundleData, keyExisted = caBundleSecret.Data[caSource.Key]
	default:
		return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator %s spec.tls.certificateAuthorityDataSource.Kind value %q is not supported by this CLI version",
			jwtAuthenticator.Name, caSource.Kind)
	}

	if !keyExisted {
		return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but key %q specified by JWTAuthenticator %s spec.tls.certificateAuthorityDataSource.key does not exist in %s %s/%s",
			caSource.Key, jwtAuthenticator.Name, caSource.Kind, conciergeNamespace, caSource.Name)
	}

	if len(caBundleData) == 0 {
		return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but key %q specified by JWTAuthenticator %s spec.tls.certificateAuthorityDataSource.key exists but has empty value in %s %s/%s",
			caSource.Key, jwtAuthenticator.Name, caSource.Kind, conciergeNamespace, caSource.Name)
	}

	numCACerts := countCACerts(caBundleData)
	if numCACerts == 0 {
		return nil, fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but value at key %q specified by JWTAuthenticator %s spec.tls.certificateAuthorityDataSource.key does not contain any CA certificates in %s %s/%s",
			caSource.Key, jwtAuthenticator.Name, caSource.Kind, conciergeNamespace, caSource.Name)
	}

	log.Info("discovered OIDC CA bundle from JWTAuthenticator spec.tls.certificateAuthorityDataSource", "roots", numCACerts)
	return caBundleData, nil
}

func discoverConciergeNamespace(ctx context.Context, apiGroupSuffix string, aggregatorClient aggregatorclient.Interface) (string, error) {
	// Let's look for the APIService for the API group of the Concierge's TokenCredentialRequest aggregated API.
	apiGroup := "login.concierge." + apiGroupSuffix

	// List all APIServices.
	apiServiceList, err := aggregatorClient.ApiregistrationV1().APIServices().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", fmt.Errorf("error listing APIServices: %w", err)
	}

	// Find one with the expected API group name.
	for _, apiService := range apiServiceList.Items {
		if apiService.Spec.Group == apiGroup {
			if apiService.Spec.Service.Namespace != "" {
				// We are assuming that all API versions (e.g. v1alpha1) of this API group are backed by service(s)
				// in the same namespace, which is the namespace of the Concierge hosting this API suffix.
				return apiService.Spec.Service.Namespace, nil
			}
		}
	}

	// Couldn't find any APIService for the expected API group name which contained a namespace reference in its spec.
	return "", fmt.Errorf("could not find APIService with non-empty spec.service.namespace for API group %s", apiGroup)
}

func getConciergeFrontend(credentialIssuer *conciergeconfigv1alpha1.CredentialIssuer, mode conciergeModeFlag) (*conciergeconfigv1alpha1.CredentialIssuerFrontend, error) {
	for _, strategy := range credentialIssuer.Status.Strategies {
		// Skip unhealthy strategies.
		if strategy.Status != conciergeconfigv1alpha1.SuccessStrategyStatus {
			continue
		}

		// If the strategy frontend is nil, skip.
		if strategy.Frontend == nil {
			continue
		}

		//	Skip any unknown frontend types.
		switch strategy.Frontend.Type {
		case conciergeconfigv1alpha1.TokenCredentialRequestAPIFrontendType,
			conciergeconfigv1alpha1.ImpersonationProxyFrontendType:
		default:
			continue
		}
		// Skip strategies that don't match --concierge-mode.
		if !mode.MatchesFrontend(strategy.Frontend) {
			continue
		}
		return strategy.Frontend, nil
	}

	if mode == modeUnknown {
		return nil, fmt.Errorf("could not autodiscover --concierge-mode")
	}
	return nil, fmt.Errorf("could not find successful Concierge strategy matching --concierge-mode=%s", mode.String())
}

func newExecKubeconfig(cluster *clientcmdapi.Cluster, execConfig *clientcmdapi.ExecConfig, newNames *kubeconfigNames) clientcmdapi.Config {
	return clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     clientcmdapi.SchemeGroupVersion.Version,
		Clusters:       map[string]*clientcmdapi.Cluster{newNames.ClusterName: cluster},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{newNames.UserName: {Exec: execConfig}},
		Contexts:       map[string]*clientcmdapi.Context{newNames.ContextName: {Cluster: newNames.ClusterName, AuthInfo: newNames.UserName}},
		CurrentContext: newNames.ContextName,
	}
}

func lookupCredentialIssuer(clientset conciergeclientset.Interface, name string, log plog.MinLogger) (*conciergeconfigv1alpha1.CredentialIssuer, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	// If the name is specified, get that object.
	if name != "" {
		return clientset.ConfigV1alpha1().CredentialIssuers().Get(ctx, name, metav1.GetOptions{})
	}

	// Otherwise list all the available CredentialIssuers and hope there's just a single one
	results, err := clientset.ConfigV1alpha1().CredentialIssuers().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list CredentialIssuer objects for autodiscovery: %w", err)
	}
	if len(results.Items) == 0 {
		return nil, fmt.Errorf("no CredentialIssuers were found")
	}
	if len(results.Items) > 1 {
		return nil, fmt.Errorf("multiple CredentialIssuers were found, so the --concierge-credential-issuer flag must be specified")
	}

	result := &results.Items[0]
	log.Info("discovered CredentialIssuer", "name", result.Name)
	return result, nil
}

func lookupAuthenticator(clientset conciergeclientset.Interface, authType, authName string, log plog.MinLogger) (metav1.Object, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	// If one was specified, look it up or error.
	if authName != "" && authType != "" {
		switch strings.ToLower(authType) {
		case "webhook":
			return clientset.AuthenticationV1alpha1().WebhookAuthenticators().Get(ctx, authName, metav1.GetOptions{})
		case "jwt":
			return clientset.AuthenticationV1alpha1().JWTAuthenticators().Get(ctx, authName, metav1.GetOptions{})
		default:
			return nil, fmt.Errorf(`invalid authenticator type %q, supported values are "webhook" and "jwt"`, authType)
		}
	}

	// Otherwise list all the available authenticators and hope there's just a single one.

	jwtAuths, err := clientset.AuthenticationV1alpha1().JWTAuthenticators().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list JWTAuthenticator objects for autodiscovery: %w", err)
	}
	webhooks, err := clientset.AuthenticationV1alpha1().WebhookAuthenticators().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list WebhookAuthenticator objects for autodiscovery: %w", err)
	}

	results := make([]metav1.Object, 0, len(jwtAuths.Items)+len(webhooks.Items))
	for i := range jwtAuths.Items {
		results = append(results, &jwtAuths.Items[i])
	}
	for i := range webhooks.Items {
		results = append(results, &webhooks.Items[i])
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("no authenticators were found")
	}
	if len(results) > 1 {
		for _, jwtAuth := range jwtAuths.Items {
			log.Info("found JWTAuthenticator", "name", jwtAuth.Name)
		}
		for _, webhook := range webhooks.Items {
			log.Info("found WebhookAuthenticator", "name", webhook.Name)
		}
		return nil, fmt.Errorf("multiple authenticators were found, so the --concierge-authenticator-type/--concierge-authenticator-name flags must be specified")
	}
	return results[0], nil
}

func writeConfigAsYAML(out io.Writer, config clientcmdapi.Config) error {
	output, err := clientcmd.Write(config)
	if err != nil {
		return err
	}
	_, err = out.Write(output)
	if err != nil {
		return fmt.Errorf("could not write output: %w", err)
	}
	return nil
}

func validateKubeconfig(ctx context.Context, flags getKubeconfigParams, kubeconfig clientcmdapi.Config, log plog.MinLogger) error {
	if flags.skipValidate {
		return nil
	}

	kubeContext := kubeconfig.Contexts[kubeconfig.CurrentContext]
	if kubeContext == nil {
		return fmt.Errorf("invalid kubeconfig (no context)")
	}
	cluster := kubeconfig.Clusters[kubeContext.Cluster]
	if cluster == nil {
		return fmt.Errorf("invalid kubeconfig (no cluster)")
	}

	kubeconfigCA := x509.NewCertPool()
	if !kubeconfigCA.AppendCertsFromPEM(cluster.CertificateAuthorityData) {
		return fmt.Errorf("invalid kubeconfig (no certificateAuthorityData)")
	}

	httpClient := phttp.Default(kubeconfigCA)
	httpClient.Timeout = 10 * time.Second

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	pingCluster := func() error {
		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, cluster.Server, nil)
		if err != nil {
			return fmt.Errorf("could not form request to validate cluster: %w", err)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode >= 500 {
			return fmt.Errorf("unexpected status code %d", resp.StatusCode)
		}
		return nil
	}

	err := pingCluster()
	if err == nil {
		log.Info("validated connection to the cluster")
		return nil
	}

	log.Info("could not immediately connect to the cluster but it may be initializing, will retry until timeout")
	deadline, _ := ctx.Deadline()
	attempts := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			attempts++
			err := pingCluster()
			if err == nil {
				log.Info("validated connection to the cluster", "attempts", attempts)
				return nil
			}
			log.Info("could not connect to cluster, retrying...", "error", err, "attempts", attempts, "remaining", time.Until(deadline).Round(time.Second).String())
		}
	}
}

func countCACerts(pemData []byte) int {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return len(pool.Subjects()) //nolint:staticcheck // there's no other clear way to mimic this legacy behavior
}

func hasPendingStrategy(credentialIssuer *conciergeconfigv1alpha1.CredentialIssuer) bool {
	for _, strategy := range credentialIssuer.Status.Strategies {
		if strategy.Reason == conciergeconfigv1alpha1.PendingStrategyReason {
			return true
		}
	}
	return false
}

func pinnipedSupervisorDiscovery(ctx context.Context, flags *getKubeconfigParams, log plog.MinLogger) error {
	// Make a client suitable for calling the provider, which may or may not be a Pinniped Supervisor.
	oidcProviderHTTPClient, err := newDiscoveryHTTPClient(flags.oidc.caBundle)
	if err != nil {
		return err
	}

	// Call the provider's discovery endpoint, but don't parse the results yet.
	discoveredProvider, err := discoverOIDCProvider(ctx, flags.oidc.issuer, oidcProviderHTTPClient)
	if err != nil {
		return err
	}

	// Parse the discovery response to find the Supervisor IDP discovery endpoint.
	pinnipedIDPsEndpoint, err := discoverIDPsDiscoveryEndpointURL(discoveredProvider)
	if err != nil {
		return err
	}
	if pinnipedIDPsEndpoint == "" {
		// The issuer is not advertising itself as a Pinniped Supervisor which supports upstream IDP discovery.
		// Since this field is not present, then assume that the provider is not a Pinniped Supervisor. This field
		// was added to the discovery response in v0.9.0, which is so long ago that we can assume there are no such
		// old Supervisors in the wild which need to work with this CLI command anymore. Since the issuer is not a
		// Supervisor, then there is no need to do the rest of the Supervisor-specific business logic below related
		// to username/groups scopes or IDP types/names/flows.
		return nil
	}

	// Now that we know that the provider is a Supervisor, perform an additional check based on its response.
	// The username and groups scopes were added to the Supervisor in v0.20.0, and were also added to the
	// "scopes_supported" field in the discovery response in that same version. If this CLI command is talking
	// to an older Supervisor, then remove the username and groups scopes from the list of requested scopes
	// since they will certainly cause an error from the old Supervisor during authentication.
	supervisorSupportsBothUsernameAndGroupsScopes, err := discoverScopesSupportedIncludesBothUsernameAndGroups(discoveredProvider)
	if err != nil {
		return err
	}
	if !supervisorSupportsBothUsernameAndGroupsScopes {
		flags.oidc.scopes = slices.DeleteFunc(flags.oidc.scopes, func(scope string) bool {
			if scope == oidcapi.ScopeUsername || scope == oidcapi.ScopeGroups {
				log.Info("removed scope from --oidc-scopes list because it is not supported by this Supervisor", "scope", scope)
				return true // Remove username and groups scopes if there were present in the flags.
			}
			return false // Keep any other scopes in the flag list.
		})
	}

	// If any upstream IDP flags are not already set, then try to discover Supervisor upstream IDP details.
	// When all the upstream IDP flags are set by the user, then skip discovery and don't validate their input.
	// Maybe they know something that we can't know, like the name of an IDP that they are going to define in the
	// future.
	if flags.oidc.upstreamIDPType == "" || flags.oidc.upstreamIDPName == "" || flags.oidc.upstreamIDPFlow == "" {
		if err := discoverSupervisorUpstreamIDP(ctx, pinnipedIDPsEndpoint, oidcProviderHTTPClient, flags, log); err != nil {
			return err
		}
	}

	return nil
}

func discoverOIDCProvider(ctx context.Context, issuer string, httpClient *http.Client) (*coreosoidc.Provider, error) {
	discoveredProvider, err := coreosoidc.NewProvider(coreosoidc.ClientContext(ctx, httpClient), issuer)
	if err != nil {
		return nil, fmt.Errorf("while fetching OIDC discovery data from issuer: %w", err)
	}
	return discoveredProvider, nil
}

func discoverSupervisorUpstreamIDP(ctx context.Context, pinnipedIDPsEndpoint string, httpClient *http.Client, flags *getKubeconfigParams, log plog.MinLogger) error {
	discoveredUpstreamIDPs, err := discoverAllAvailableSupervisorUpstreamIDPs(ctx, pinnipedIDPsEndpoint, httpClient)
	if err != nil {
		return err
	}

	if len(discoveredUpstreamIDPs) == 0 {
		// Discovered that the Supervisor does not have any upstream IDPs defined. Continue without putting one into the
		// kubeconfig. This kubeconfig will only work if the user defines one (and only one) OIDC IDP in the Supervisor
		// later and wants to use the default client flow for OIDC (browser-based auth).
		return nil
	}

	selectedIDPName, selectedIDPType, discoveredIDPFlows, err := selectUpstreamIDPNameAndType(discoveredUpstreamIDPs, flags.oidc.upstreamIDPName, flags.oidc.upstreamIDPType)
	if err != nil {
		return err
	}

	selectedIDPFlow, err := selectUpstreamIDPFlow(discoveredIDPFlows, selectedIDPName, selectedIDPType, flags.oidc.upstreamIDPFlow, log)
	if err != nil {
		return err
	}

	flags.oidc.upstreamIDPName = selectedIDPName
	flags.oidc.upstreamIDPType = selectedIDPType.String()
	flags.oidc.upstreamIDPFlow = selectedIDPFlow.String()
	return nil
}

func newDiscoveryHTTPClient(caBundleFlag caBundleFlag) (*http.Client, error) {
	var rootCAs *x509.CertPool
	if caBundleFlag != nil {
		rootCAs = x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caBundleFlag); !ok {
			return nil, fmt.Errorf("unable to fetch OIDC discovery data from issuer: could not parse CA bundle")
		}
	}
	return phttp.Default(rootCAs), nil
}

func discoverIDPsDiscoveryEndpointURL(discoveredProvider *coreosoidc.Provider) (string, error) {
	var body idpdiscoveryv1alpha1.OIDCDiscoveryResponse
	err := discoveredProvider.Claims(&body)
	if err != nil {
		return "", fmt.Errorf("while fetching OIDC discovery data from issuer: %w", err)
	}
	return body.SupervisorDiscovery.PinnipedIDPsEndpoint, nil
}

func discoverScopesSupportedIncludesBothUsernameAndGroups(discoveredProvider *coreosoidc.Provider) (bool, error) {
	var body discoveryResponseScopesSupported
	err := discoveredProvider.Claims(&body)
	if err != nil {
		return false, fmt.Errorf("while fetching OIDC discovery data from issuer: %w", err)
	}
	return slices.Contains(body.ScopesSupported, oidcapi.ScopeUsername) && slices.Contains(body.ScopesSupported, oidcapi.ScopeGroups), nil
}

func discoverAllAvailableSupervisorUpstreamIDPs(ctx context.Context, pinnipedIDPsEndpoint string, httpClient *http.Client) ([]idpdiscoveryv1alpha1.PinnipedIDP, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, pinnipedIDPsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("while forming request to IDP discovery URL: %w", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch IDP discovery data from issuer: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unable to fetch IDP discovery data from issuer: unexpected http response status: %s", response.Status)
	}

	rawBody, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch IDP discovery data from issuer: could not read response body: %w", err)
	}

	var body idpdiscoveryv1alpha1.IDPDiscoveryResponse
	err = json.Unmarshal(rawBody, &body)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch IDP discovery data from issuer: could not parse response JSON: %w", err)
	}

	return body.PinnipedIDPs, nil
}

func selectUpstreamIDPNameAndType(pinnipedIDPs []idpdiscoveryv1alpha1.PinnipedIDP, specifiedIDPName, specifiedIDPType string) (string, idpdiscoveryv1alpha1.IDPType, []idpdiscoveryv1alpha1.IDPFlow, error) {
	pinnipedIDPsString, _ := json.Marshal(pinnipedIDPs)
	var discoveredFlows []idpdiscoveryv1alpha1.IDPFlow
	switch {
	case specifiedIDPName != "" && specifiedIDPType != "":
		// The user specified both name and type, so check to see if there exists an exact match.
		for _, idp := range pinnipedIDPs {
			if idp.Name == specifiedIDPName && idp.Type.Equals(specifiedIDPType) {
				return specifiedIDPName, idp.Type, idp.Flows, nil
			}
		}
		return "", "", nil, fmt.Errorf(
			"no Supervisor upstream identity providers with name %q of type %q were found. "+
				"Found these upstreams: %s", specifiedIDPName, specifiedIDPType, pinnipedIDPsString)
	case specifiedIDPType != "":
		// The user specified only a type, so check if there is only one of that type found.
		discoveredName := ""
		var discoveredType idpdiscoveryv1alpha1.IDPType
		for _, idp := range pinnipedIDPs {
			if idp.Type.Equals(specifiedIDPType) {
				if discoveredName != "" {
					return "", "", nil, fmt.Errorf(
						"multiple Supervisor upstream identity providers of type %q were found, "+
							"so the --upstream-identity-provider-name flag must be specified. "+
							"Found these upstreams: %s",
						specifiedIDPType, pinnipedIDPsString)
				}
				discoveredName = idp.Name
				discoveredType = idp.Type
				discoveredFlows = idp.Flows
			}
		}
		if discoveredName == "" {
			return "", "", nil, fmt.Errorf(
				"no Supervisor upstream identity providers of type %q were found. "+
					"Found these upstreams: %s", specifiedIDPType, pinnipedIDPsString)
		}
		return discoveredName, discoveredType, discoveredFlows, nil
	case specifiedIDPName != "":
		// The user specified only a name, so check if there is only one of that name found.
		var discoveredType idpdiscoveryv1alpha1.IDPType
		for _, idp := range pinnipedIDPs {
			if idp.Name == specifiedIDPName {
				if discoveredType != "" {
					return "", "", nil, fmt.Errorf(
						"multiple Supervisor upstream identity providers with name %q were found, "+
							"so the --upstream-identity-provider-type flag must be specified. Found these upstreams: %s",
						specifiedIDPName, pinnipedIDPsString)
				}
				discoveredType = idp.Type
				discoveredFlows = idp.Flows
			}
		}
		if discoveredType == "" {
			return "", "", nil, fmt.Errorf(
				"no Supervisor upstream identity providers with name %q were found. "+
					"Found these upstreams: %s", specifiedIDPName, pinnipedIDPsString)
		}
		return specifiedIDPName, discoveredType, discoveredFlows, nil
	case len(pinnipedIDPs) == 1:
		// The user did not specify any name or type, but there is only one found, so select it.
		return pinnipedIDPs[0].Name, pinnipedIDPs[0].Type, pinnipedIDPs[0].Flows, nil
	default:
		// The user did not specify any name or type, and there is more than one found.
		return "", "", nil, fmt.Errorf(
			"multiple Supervisor upstream identity providers were found, "+
				"so the --upstream-identity-provider-name/--upstream-identity-provider-type flags must be specified. "+
				"Found these upstreams: %s",
			pinnipedIDPsString)
	}
}

func selectUpstreamIDPFlow(discoveredIDPFlows []idpdiscoveryv1alpha1.IDPFlow, selectedIDPName string, selectedIDPType idpdiscoveryv1alpha1.IDPType, specifiedFlow string, log plog.MinLogger) (idpdiscoveryv1alpha1.IDPFlow, error) {
	switch {
	case len(discoveredIDPFlows) == 0:
		// No flows listed by discovery means that we are talking to an old Supervisor from before this feature existed.
		// If the user specified a flow on the CLI flag then use it without validation, otherwise skip flow selection
		// and return empty string.
		return idpdiscoveryv1alpha1.IDPFlow(specifiedFlow), nil
	case specifiedFlow != "":
		// The user specified a flow, so validate that it is available for the selected IDP.
		for _, flow := range discoveredIDPFlows {
			if flow.Equals(specifiedFlow) {
				// Found it, so use it as specified by the user.
				return flow, nil
			}
		}
		return "", fmt.Errorf(
			"no client flow %q for Supervisor upstream identity provider %q of type %q were found. "+
				"Found these flows: %v",
			specifiedFlow, selectedIDPName, selectedIDPType, discoveredIDPFlows)
	case len(discoveredIDPFlows) == 1:
		// The user did not specify a flow, but there is only one found, so select it.
		return discoveredIDPFlows[0], nil
	default:
		// The user did not specify a flow, and more than one was found.
		log.Info("multiple client flows found, selecting first value as default",
			"idpName", selectedIDPName, "idpType", selectedIDPType,
			"selectedFlow", discoveredIDPFlows[0].String(), "availableFlows", discoveredIDPFlows)
		return discoveredIDPFlows[0], nil
	}
}
