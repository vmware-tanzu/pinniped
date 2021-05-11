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
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	_ "k8s.io/client-go/plugin/pkg/client/auth" // Adds handlers for various dynamic auth plugins in client-go
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	conciergev1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	configv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/groupsuffix"
)

type kubeconfigDeps struct {
	getPathToSelf func() (string, error)
	getClientset  getConciergeClientsetFunc
	log           logr.Logger
}

func kubeconfigRealDeps() kubeconfigDeps {
	return kubeconfigDeps{
		getPathToSelf: os.Executable,
		getClientset:  getRealConciergeClientset,
		log:           stdr.New(log.New(os.Stderr, "", 0)),
	}
}

//nolint: gochecknoinits
func init() {
	getCmd.AddCommand(kubeconfigCommand(kubeconfigRealDeps()))
}

type getKubeconfigOIDCParams struct {
	issuer            string
	clientID          string
	listenPort        uint16
	scopes            []string
	skipBrowser       bool
	sessionCachePath  string
	debugSessionCache bool
	caBundle          caBundleFlag
	requestAudience   string
	upstreamIDPName   string
	upstreamIDPType   string
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
}

type supervisorOIDCDiscoveryResponse struct {
	PinnipedIDPsEndpoint string `json:"pinniped_identity_providers_endpoint"`
}

type supervisorIDPsDiscoveryResponse struct {
	PinnipedIDPs []pinnipedIDPResponse `json:"pinniped_identity_providers"`
}

type pinnipedIDPResponse struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

func kubeconfigCommand(deps kubeconfigDeps) *cobra.Command {
	var (
		cmd = &cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "kubeconfig",
			Short:        "Generate a Pinniped-based kubeconfig for a cluster",
			SilenceUsage: true,
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
	f.StringVar(&flags.oidc.clientID, "oidc-client-id", "pinniped-cli", "OpenID Connect client ID (default: autodiscover)")
	f.Uint16Var(&flags.oidc.listenPort, "oidc-listen-port", 0, "TCP port for localhost listener (authorization code flow only)")
	f.StringSliceVar(&flags.oidc.scopes, "oidc-scopes", []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID, "pinniped:request-audience"}, "OpenID Connect scopes to request during login")
	f.BoolVar(&flags.oidc.skipBrowser, "oidc-skip-browser", false, "During OpenID Connect login, skip opening the browser (just print the URL)")
	f.StringVar(&flags.oidc.sessionCachePath, "oidc-session-cache", "", "Path to OpenID Connect session cache file")
	f.Var(&flags.oidc.caBundle, "oidc-ca-bundle", "Path to TLS certificate authority bundle (PEM format, optional, can be repeated)")
	f.BoolVar(&flags.oidc.debugSessionCache, "oidc-debug-session-cache", false, "Print debug logs related to the OpenID Connect session cache")
	f.StringVar(&flags.oidc.requestAudience, "oidc-request-audience", "", "Request a token with an alternate audience using RFC8693 token exchange")
	f.StringVar(&flags.oidc.upstreamIDPName, "upstream-identity-provider-name", "", "The name of the upstream identity provider used during login with a Supervisor")
	f.StringVar(&flags.oidc.upstreamIDPType, "upstream-identity-provider-type", "", "The type of the upstream identity provider used during login with a Supervisor (e.g. 'oidc', 'ldap')")
	f.StringVar(&flags.kubeconfigPath, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to kubeconfig file")
	f.StringVar(&flags.kubeconfigContextOverride, "kubeconfig-context", "", "Kubeconfig context name (default: current active context)")
	f.BoolVar(&flags.skipValidate, "skip-validation", false, "Skip final validation of the kubeconfig (default: false)")
	f.DurationVar(&flags.timeout, "timeout", 10*time.Minute, "Timeout for autodiscovery and validation")
	f.StringVarP(&flags.outputPath, "output", "o", "", "Output file path (default: stdout)")
	f.StringVar(&flags.generatedNameSuffix, "generated-name-suffix", "-pinniped", "Suffix to append to generated cluster, context, user kubeconfig entries")
	f.StringVar(&flags.credentialCachePath, "credential-cache", "", "Path to cluster-specific credentials cache")
	mustMarkHidden(cmd, "oidc-debug-session-cache")

	mustMarkDeprecated(cmd, "concierge-namespace", "not needed anymore")
	mustMarkHidden(cmd, "concierge-namespace")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
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

//nolint:funlen
func runGetKubeconfig(ctx context.Context, out io.Writer, deps kubeconfigDeps, flags getKubeconfigParams) error {
	ctx, cancel := context.WithTimeout(ctx, flags.timeout)
	defer cancel()

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
	clientset, err := deps.getClientset(clientConfig, flags.concierge.apiGroupSuffix)
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
		credentialIssuer, err := waitForCredentialIssuer(ctx, clientset, flags, deps)
		if err != nil {
			return err
		}

		authenticator, err := lookupAuthenticator(
			clientset,
			flags.concierge.authenticatorType,
			flags.concierge.authenticatorName,
			deps.log,
		)
		if err != nil {
			return err
		}
		if err := discoverConciergeParams(credentialIssuer, &flags, cluster, deps.log); err != nil {
			return err
		}
		if err := discoverAuthenticatorParams(authenticator, &flags, deps.log); err != nil {
			return err
		}

		// Point kubectl at the concierge endpoint.
		cluster.Server = flags.concierge.endpoint
		cluster.CertificateAuthorityData = flags.concierge.caBundle
	}

	// If there is an issuer, and if both upstream flags are not already set, then try to discover Supervisor upstream IDP.
	if len(flags.oidc.issuer) > 0 && (flags.oidc.upstreamIDPType == "" || flags.oidc.upstreamIDPName == "") {
		if err := discoverSupervisorUpstreamIDP(ctx, &flags); err != nil {
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

	var err error
	execConfig.Command, err = deps.getPathToSelf()
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
		execConfig.Args = append([]string{"login", "static"}, execConfig.Args...)
		if flags.staticToken != "" {
			execConfig.Args = append(execConfig.Args, "--token="+flags.staticToken)
		}
		if flags.staticTokenEnvName != "" {
			execConfig.Args = append(execConfig.Args, "--token-env="+flags.staticTokenEnvName)
		}
		return execConfig, nil
	}

	// Otherwise continue to parse the OIDC-related flags and output a config that runs `pinniped login oidc`.
	execConfig.Args = append([]string{"login", "oidc"}, execConfig.Args...)
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
		execConfig.Args = append(execConfig.Args, "--request-audience="+flags.oidc.requestAudience)
	}
	if flags.oidc.upstreamIDPName != "" {
		execConfig.Args = append(execConfig.Args, "--upstream-identity-provider-name="+flags.oidc.upstreamIDPName)
	}
	if flags.oidc.upstreamIDPType != "" {
		execConfig.Args = append(execConfig.Args, "--upstream-identity-provider-type="+flags.oidc.upstreamIDPType)
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

func waitForCredentialIssuer(ctx context.Context, clientset conciergeclientset.Interface, flags getKubeconfigParams, deps kubeconfigDeps) (*configv1alpha1.CredentialIssuer, error) {
	credentialIssuer, err := lookupCredentialIssuer(clientset, flags.concierge.credentialIssuer, deps.log)
	if err != nil {
		return nil, err
	}

	if !flags.concierge.skipWait {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()

		deadline, _ := ctx.Deadline()
		attempts := 1

		for {
			if !hasPendingStrategy(credentialIssuer) {
				break
			}
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

func discoverConciergeParams(credentialIssuer *configv1alpha1.CredentialIssuer, flags *getKubeconfigParams, v1Cluster *clientcmdapi.Cluster, log logr.Logger) error {
	// Autodiscover the --concierge-mode.
	frontend, err := getConciergeFrontend(credentialIssuer, flags.concierge.mode)
	if err != nil {
		logStrategies(credentialIssuer, log)
		return err
	}

	// Auto-set --concierge-mode if it wasn't explicitly set.
	if flags.concierge.mode == modeUnknown {
		switch frontend.Type {
		case configv1alpha1.TokenCredentialRequestAPIFrontendType:
			log.Info("discovered Concierge operating in TokenCredentialRequest API mode")
			flags.concierge.mode = modeTokenCredentialRequestAPI
		case configv1alpha1.ImpersonationProxyFrontendType:
			log.Info("discovered Concierge operating in impersonation proxy mode")
			flags.concierge.mode = modeImpersonationProxy
		}
	}

	// Auto-set --concierge-endpoint if it wasn't explicitly set.
	if flags.concierge.endpoint == "" {
		switch frontend.Type {
		case configv1alpha1.TokenCredentialRequestAPIFrontendType:
			flags.concierge.endpoint = v1Cluster.Server
		case configv1alpha1.ImpersonationProxyFrontendType:
			flags.concierge.endpoint = frontend.ImpersonationProxyInfo.Endpoint
		}
		log.Info("discovered Concierge endpoint", "endpoint", flags.concierge.endpoint)
	}

	// Auto-set --concierge-ca-bundle if it wasn't explicitly set..
	if len(flags.concierge.caBundle) == 0 {
		switch frontend.Type {
		case configv1alpha1.TokenCredentialRequestAPIFrontendType:
			flags.concierge.caBundle = v1Cluster.CertificateAuthorityData
		case configv1alpha1.ImpersonationProxyFrontendType:
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

func logStrategies(credentialIssuer *configv1alpha1.CredentialIssuer, log logr.Logger) {
	for _, strategy := range credentialIssuer.Status.Strategies {
		log.Info("found CredentialIssuer strategy",
			"type", strategy.Type,
			"status", strategy.Status,
			"reason", strategy.Reason,
			"message", strategy.Message,
		)
	}
}

func discoverAuthenticatorParams(authenticator metav1.Object, flags *getKubeconfigParams, log logr.Logger) error {
	switch auth := authenticator.(type) {
	case *conciergev1alpha1.WebhookAuthenticator:
		// If the --concierge-authenticator-type/--concierge-authenticator-name flags were not set explicitly, set
		// them to point at the discovered WebhookAuthenticator.
		if flags.concierge.authenticatorType == "" && flags.concierge.authenticatorName == "" {
			log.Info("discovered WebhookAuthenticator", "name", auth.Name)
			flags.concierge.authenticatorType = "webhook"
			flags.concierge.authenticatorName = auth.Name
		}
	case *conciergev1alpha1.JWTAuthenticator:
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
		// spec.tls.certificateAuthorityData field of the JWTAuthenticator.
		if len(flags.oidc.caBundle) == 0 && auth.Spec.TLS != nil && auth.Spec.TLS.CertificateAuthorityData != "" {
			decoded, err := base64.StdEncoding.DecodeString(auth.Spec.TLS.CertificateAuthorityData)
			if err != nil {
				return fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator %s has invalid spec.tls.certificateAuthorityData: %w", auth.Name, err)
			}
			log.Info("discovered OIDC CA bundle", "roots", countCACerts(decoded))
			flags.oidc.caBundle = decoded
		}
	}
	return nil
}

func getConciergeFrontend(credentialIssuer *configv1alpha1.CredentialIssuer, mode conciergeModeFlag) (*configv1alpha1.CredentialIssuerFrontend, error) {
	for _, strategy := range credentialIssuer.Status.Strategies {
		// Skip unhealthy strategies.
		if strategy.Status != configv1alpha1.SuccessStrategyStatus {
			continue
		}

		// Backfill the .status.strategies[].frontend field from .status.kubeConfigInfo for backwards compatibility.
		if strategy.Type == configv1alpha1.KubeClusterSigningCertificateStrategyType && strategy.Frontend == nil && credentialIssuer.Status.KubeConfigInfo != nil {
			strategy = *strategy.DeepCopy()
			strategy.Frontend = &configv1alpha1.CredentialIssuerFrontend{
				Type: configv1alpha1.TokenCredentialRequestAPIFrontendType,
				TokenCredentialRequestAPIInfo: &configv1alpha1.TokenCredentialRequestAPIInfo{
					Server:                   credentialIssuer.Status.KubeConfigInfo.Server,
					CertificateAuthorityData: credentialIssuer.Status.KubeConfigInfo.CertificateAuthorityData,
				},
			}
		}

		// If the strategy frontend is still nil, skip.
		if strategy.Frontend == nil {
			continue
		}

		//	Skip any unknown frontend types.
		switch strategy.Frontend.Type {
		case configv1alpha1.TokenCredentialRequestAPIFrontendType, configv1alpha1.ImpersonationProxyFrontendType:
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

func lookupCredentialIssuer(clientset conciergeclientset.Interface, name string, log logr.Logger) (*configv1alpha1.CredentialIssuer, error) {
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

func lookupAuthenticator(clientset conciergeclientset.Interface, authType, authName string, log logr.Logger) (metav1.Object, error) {
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

func validateKubeconfig(ctx context.Context, flags getKubeconfigParams, kubeconfig clientcmdapi.Config, log logr.Logger) error {
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

	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    kubeconfigCA,
			},
			Proxy:               http.ProxyFromEnvironment,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		Timeout: 10 * time.Second,
	}

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
			log.Error(err, "could not connect to cluster, retrying...", "attempts", attempts, "remaining", time.Until(deadline).Round(time.Second).String())
		}
	}
}

func countCACerts(pemData []byte) int {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pemData)
	return len(pool.Subjects())
}

func hasPendingStrategy(credentialIssuer *configv1alpha1.CredentialIssuer) bool {
	for _, strategy := range credentialIssuer.Status.Strategies {
		if strategy.Reason == configv1alpha1.PendingStrategyReason {
			return true
		}
	}
	return false
}

func discoverSupervisorUpstreamIDP(ctx context.Context, flags *getKubeconfigParams) error {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		Proxy:           http.ProxyFromEnvironment,
	}
	httpClient := &http.Client{Transport: transport}
	if flags.oidc.caBundle != nil {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM(flags.oidc.caBundle)
		if !ok {
			return fmt.Errorf("unable to fetch OIDC discovery data from issuer: could not parse CA bundle")
		}
		transport.TLSClientConfig.RootCAs = rootCAs
	}

	pinnipedIDPsEndpoint, err := discoverIDPsDiscoveryEndpointURL(ctx, flags.oidc.issuer, httpClient)
	if err != nil {
		return err
	}
	if pinnipedIDPsEndpoint == "" {
		// The issuer is not advertising itself as a Pinniped Supervisor which supports upstream IDP discovery.
		return nil
	}

	upstreamIDPs, err := discoverAllAvailableSupervisorUpstreamIDPs(ctx, pinnipedIDPsEndpoint, httpClient)
	if err != nil {
		return err
	}
	if len(upstreamIDPs) == 1 {
		flags.oidc.upstreamIDPName = upstreamIDPs[0].Name
		flags.oidc.upstreamIDPType = upstreamIDPs[0].Type
	} else if len(upstreamIDPs) > 1 {
		idpName, idpType, err := selectUpstreamIDP(upstreamIDPs, flags.oidc.upstreamIDPName, flags.oidc.upstreamIDPType)
		if err != nil {
			return err
		}
		flags.oidc.upstreamIDPName = idpName
		flags.oidc.upstreamIDPType = idpType
	}
	return nil
}

func discoverIDPsDiscoveryEndpointURL(ctx context.Context, issuer string, httpClient *http.Client) (string, error) {
	issuerDiscoveryURL := issuer + "/.well-known/openid-configuration"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, issuerDiscoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("while forming request to issuer URL: %w", err)
	}

	response, err := httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("unable to fetch OIDC discovery data from issuer: %w", err)
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode == http.StatusNotFound {
		// 404 Not Found is not an error because OIDC discovery is an optional part of the OIDC spec.
		return "", nil
	}
	if response.StatusCode != http.StatusOK {
		// Other types of error responses aside from 404 are not expected.
		return "", fmt.Errorf("unable to fetch OIDC discovery data from issuer: unexpected http response status: %s", response.Status)
	}

	rawBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("unable to fetch OIDC discovery data from issuer: could not read response body: %w", err)
	}

	var body supervisorOIDCDiscoveryResponse
	err = json.Unmarshal(rawBody, &body)
	if err != nil {
		return "", fmt.Errorf("unable to fetch OIDC discovery data from issuer: could not parse response JSON: %w", err)
	}

	return body.PinnipedIDPsEndpoint, nil
}

func discoverAllAvailableSupervisorUpstreamIDPs(ctx context.Context, pinnipedIDPsEndpoint string, httpClient *http.Client) ([]pinnipedIDPResponse, error) {
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

	rawBody, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch IDP discovery data from issuer: could not read response body: %w", err)
	}

	var body supervisorIDPsDiscoveryResponse
	err = json.Unmarshal(rawBody, &body)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch IDP discovery data from issuer: could not parse response JSON: %w", err)
	}

	return body.PinnipedIDPs, nil
}

func selectUpstreamIDP(pinnipedIDPs []pinnipedIDPResponse, idpName, idpType string) (string, string, error) {
	pinnipedIDPsString, _ := json.Marshal(pinnipedIDPs)
	switch {
	case idpType != "":
		discoveredName := ""
		for _, idp := range pinnipedIDPs {
			if idp.Type == idpType {
				if discoveredName != "" {
					return "", "", fmt.Errorf(
						"multiple Supervisor upstream identity providers of type \"%s\" were found,"+
							" so the --upstream-identity-provider-name flag must be specified. "+
							"Found these upstreams: %s",
						idpType, pinnipedIDPsString)
				}
				discoveredName = idp.Name
			}
		}
		if discoveredName == "" {
			return "", "", fmt.Errorf(
				"no Supervisor upstream identity providers of type \"%s\" were found."+
					" Found these upstreams: %s", idpType, pinnipedIDPsString)
		}
		return discoveredName, idpType, nil
	case idpName != "":
		discoveredType := ""
		for _, idp := range pinnipedIDPs {
			if idp.Name == idpName {
				if discoveredType != "" {
					return "", "", fmt.Errorf(
						"multiple Supervisor upstream identity providers with name \"%s\" were found,"+
							" so the --upstream-identity-provider-type flag must be specified. Found these upstreams: %s",
						idpName, pinnipedIDPsString)
				}
				discoveredType = idp.Type
			}
		}
		if discoveredType == "" {
			return "", "", fmt.Errorf(
				"no Supervisor upstream identity providers with name \"%s\" were found."+
					" Found these upstreams: %s", idpName, pinnipedIDPsString)
		}
		return idpName, discoveredType, nil
	default:
		return "", "", fmt.Errorf(
			"multiple Supervisor upstream identity providers were found,"+
				" so the --upstream-identity-provider-name/--upstream-identity-provider-type flags must be specified."+
				" Found these upstreams: %s",
			pinnipedIDPsString)
	}
}
