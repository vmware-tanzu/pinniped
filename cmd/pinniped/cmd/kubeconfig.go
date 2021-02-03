// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	_ "k8s.io/client-go/plugin/pkg/client/auth" // Adds handlers for various dynamic auth plugins in client-go

	conciergev1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/authentication/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/1.20/client/concierge/clientset/versioned"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/kubeclient"
)

type kubeconfigDeps struct {
	getPathToSelf func() (string, error)
	getClientset  func(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, error)
}

func kubeconfigRealDeps() kubeconfigDeps {
	return kubeconfigDeps{
		getPathToSelf: os.Executable,
		getClientset: func(clientConfig clientcmd.ClientConfig, apiGroupSuffix string) (conciergeclientset.Interface, error) {
			restConfig, err := clientConfig.ClientConfig()
			if err != nil {
				return nil, err
			}
			client, err := kubeclient.New(
				kubeclient.WithConfig(restConfig),
				kubeclient.WithMiddleware(groupsuffix.New(apiGroupSuffix)),
			)
			if err != nil {
				return nil, err
			}
			return client.PinnipedConcierge, nil
		},
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
	caBundlePaths     []string
	requestAudience   string
}

type getKubeconfigConciergeParams struct {
	disabled          bool
	namespace         string
	authenticatorName string
	authenticatorType string
	apiGroupSuffix    string
}

type getKubeconfigParams struct {
	kubeconfigPath            string
	kubeconfigContextOverride string
	staticToken               string
	staticTokenEnvName        string
	oidc                      getKubeconfigOIDCParams
	concierge                 getKubeconfigConciergeParams
}

func kubeconfigCommand(deps kubeconfigDeps) *cobra.Command {
	var (
		cmd = cobra.Command{
			Args:         cobra.NoArgs,
			Use:          "kubeconfig",
			Short:        "Generate a Pinniped-based kubeconfig for a cluster",
			SilenceUsage: true,
		}
		flags getKubeconfigParams
	)

	f := cmd.Flags()
	f.StringVar(&flags.staticToken, "static-token", "", "Instead of doing an OIDC-based login, specify a static token")
	f.StringVar(&flags.staticTokenEnvName, "static-token-env", "", "Instead of doing an OIDC-based login, read a static token from the environment")

	f.BoolVar(&flags.concierge.disabled, "no-concierge", false, "Generate a configuration which does not use the concierge, but sends the credential to the cluster directly")
	f.StringVar(&flags.concierge.namespace, "concierge-namespace", "pinniped-concierge", "Namespace in which the concierge was installed")
	f.StringVar(&flags.concierge.authenticatorType, "concierge-authenticator-type", "", "Concierge authenticator type (e.g., 'webhook', 'jwt') (default: autodiscover)")
	f.StringVar(&flags.concierge.authenticatorName, "concierge-authenticator-name", "", "Concierge authenticator name (default: autodiscover)")
	f.StringVar(&flags.concierge.apiGroupSuffix, "concierge-api-group-suffix", "pinniped.dev", "Concierge API group suffix")

	f.StringVar(&flags.oidc.issuer, "oidc-issuer", "", "OpenID Connect issuer URL (default: autodiscover)")
	f.StringVar(&flags.oidc.clientID, "oidc-client-id", "pinniped-cli", "OpenID Connect client ID (default: autodiscover)")
	f.Uint16Var(&flags.oidc.listenPort, "oidc-listen-port", 0, "TCP port for localhost listener (authorization code flow only)")
	f.StringSliceVar(&flags.oidc.scopes, "oidc-scopes", []string{oidc.ScopeOfflineAccess, oidc.ScopeOpenID, "pinniped:request-audience"}, "OpenID Connect scopes to request during login")
	f.BoolVar(&flags.oidc.skipBrowser, "oidc-skip-browser", false, "During OpenID Connect login, skip opening the browser (just print the URL)")
	f.StringVar(&flags.oidc.sessionCachePath, "oidc-session-cache", "", "Path to OpenID Connect session cache file")
	f.StringSliceVar(&flags.oidc.caBundlePaths, "oidc-ca-bundle", nil, "Path to TLS certificate authority bundle (PEM format, optional, can be repeated)")
	f.BoolVar(&flags.oidc.debugSessionCache, "oidc-debug-session-cache", false, "Print debug logs related to the OpenID Connect session cache")
	f.StringVar(&flags.oidc.requestAudience, "oidc-request-audience", "", "Request a token with an alternate audience using RFC8693 token exchange")
	f.StringVar(&flags.kubeconfigPath, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to kubeconfig file")
	f.StringVar(&flags.kubeconfigContextOverride, "kubeconfig-context", "", "Kubeconfig context name (default: current active context)")

	mustMarkHidden(&cmd, "oidc-debug-session-cache")

	cmd.RunE = func(cmd *cobra.Command, args []string) error { return runGetKubeconfig(cmd.OutOrStdout(), deps, flags) }
	return &cmd
}

//nolint:funlen
func runGetKubeconfig(out io.Writer, deps kubeconfigDeps, flags getKubeconfigParams) error {
	// Validate api group suffix and immediately return an error if it is invalid.
	if err := groupsuffix.Validate(flags.concierge.apiGroupSuffix); err != nil {
		return fmt.Errorf("invalid api group suffix: %w", err)
	}

	execConfig := clientcmdapi.ExecConfig{
		APIVersion: clientauthenticationv1beta1.SchemeGroupVersion.String(),
		Args:       []string{},
		Env:        []clientcmdapi.ExecEnvVar{},
	}

	var err error
	execConfig.Command, err = deps.getPathToSelf()
	if err != nil {
		return fmt.Errorf("could not determine the Pinniped executable path: %w", err)
	}
	execConfig.ProvideClusterInfo = true

	oidcCABundle, err := loadCABundlePaths(flags.oidc.caBundlePaths)
	if err != nil {
		return fmt.Errorf("could not read --oidc-ca-bundle: %w", err)
	}

	clientConfig := newClientConfig(flags.kubeconfigPath, flags.kubeconfigContextOverride)
	currentKubeConfig, err := clientConfig.RawConfig()
	if err != nil {
		return fmt.Errorf("could not load --kubeconfig: %w", err)
	}
	cluster, err := copyCurrentClusterFromExistingKubeConfig(currentKubeConfig, flags.kubeconfigContextOverride)
	if err != nil {
		return fmt.Errorf("could not load --kubeconfig/--kubeconfig-context: %w", err)
	}
	clientset, err := deps.getClientset(clientConfig, flags.concierge.apiGroupSuffix)
	if err != nil {
		return fmt.Errorf("could not configure Kubernetes client: %w", err)
	}

	if !flags.concierge.disabled {
		authenticator, err := lookupAuthenticator(
			clientset,
			flags.concierge.namespace,
			flags.concierge.authenticatorType,
			flags.concierge.authenticatorName,
		)
		if err != nil {
			return err
		}
		if err := configureConcierge(authenticator, &flags, cluster, &oidcCABundle, &execConfig); err != nil {
			return err
		}
	}

	// If one of the --static-* flags was passed, output a config that runs `pinniped login static`.
	if flags.staticToken != "" || flags.staticTokenEnvName != "" {
		if flags.staticToken != "" && flags.staticTokenEnvName != "" {
			return fmt.Errorf("only one of --static-token and --static-token-env can be specified")
		}
		execConfig.Args = append([]string{"login", "static"}, execConfig.Args...)
		if flags.staticToken != "" {
			execConfig.Args = append(execConfig.Args, "--token="+flags.staticToken)
		}
		if flags.staticTokenEnvName != "" {
			execConfig.Args = append(execConfig.Args, "--token-env="+flags.staticTokenEnvName)
		}
		return writeConfigAsYAML(out, newExecKubeconfig(cluster, &execConfig))
	}

	// Otherwise continue to parse the OIDC-related flags and output a config that runs `pinniped login oidc`.
	execConfig.Args = append([]string{"login", "oidc"}, execConfig.Args...)
	if flags.oidc.issuer == "" {
		return fmt.Errorf("could not autodiscover --oidc-issuer, and none was provided")
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
	if oidcCABundle != "" {
		execConfig.Args = append(execConfig.Args, "--ca-bundle-data="+base64.StdEncoding.EncodeToString([]byte(oidcCABundle)))
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
	return writeConfigAsYAML(out, newExecKubeconfig(cluster, &execConfig))
}

func configureConcierge(authenticator metav1.Object, flags *getKubeconfigParams, v1Cluster *clientcmdapi.Cluster, oidcCABundle *string, execConfig *clientcmdapi.ExecConfig) error {
	switch auth := authenticator.(type) {
	case *conciergev1alpha1.WebhookAuthenticator:
		// If the --concierge-authenticator-type/--concierge-authenticator-name flags were not set explicitly, set
		// them to point at the discovered WebhookAuthenticator.
		if flags.concierge.authenticatorType == "" && flags.concierge.authenticatorName == "" {
			flags.concierge.authenticatorType = "webhook"
			flags.concierge.authenticatorName = auth.Name
		}
	case *conciergev1alpha1.JWTAuthenticator:
		// If the --concierge-authenticator-type/--concierge-authenticator-name flags were not set explicitly, set
		// them to point at the discovered JWTAuthenticator.
		if flags.concierge.authenticatorType == "" && flags.concierge.authenticatorName == "" {
			flags.concierge.authenticatorType = "jwt"
			flags.concierge.authenticatorName = auth.Name
		}

		// If the --oidc-issuer flag was not set explicitly, default it to the spec.issuer field of the JWTAuthenticator.
		if flags.oidc.issuer == "" {
			flags.oidc.issuer = auth.Spec.Issuer
		}

		// If the --oidc-request-audience flag was not set explicitly, default it to the spec.audience field of the JWTAuthenticator.
		if flags.oidc.requestAudience == "" {
			flags.oidc.requestAudience = auth.Spec.Audience
		}

		// If the --oidc-ca-bundle flags was not set explicitly, default it to the
		// spec.tls.certificateAuthorityData field of the JWTAuthenticator.
		if *oidcCABundle == "" && auth.Spec.TLS != nil && auth.Spec.TLS.CertificateAuthorityData != "" {
			decoded, err := base64.StdEncoding.DecodeString(auth.Spec.TLS.CertificateAuthorityData)
			if err != nil {
				return fmt.Errorf("tried to autodiscover --oidc-ca-bundle, but JWTAuthenticator %s/%s has invalid spec.tls.certificateAuthorityData: %w", auth.Namespace, auth.Name, err)
			}
			*oidcCABundle = string(decoded)
		}
	}

	// Append the flags to configure the Concierge credential exchange at runtime.
	execConfig.Args = append(execConfig.Args,
		"--enable-concierge",
		"--concierge-api-group-suffix="+flags.concierge.apiGroupSuffix,
		"--concierge-namespace="+flags.concierge.namespace,
		"--concierge-authenticator-name="+flags.concierge.authenticatorName,
		"--concierge-authenticator-type="+flags.concierge.authenticatorType,
		"--concierge-endpoint="+v1Cluster.Server,
		"--concierge-ca-bundle-data="+base64.StdEncoding.EncodeToString(v1Cluster.CertificateAuthorityData),
	)
	return nil
}

func loadCABundlePaths(paths []string) (string, error) {
	if len(paths) == 0 {
		return "", nil
	}
	blobs := make([][]byte, 0, len(paths))
	for _, p := range paths {
		pem, err := ioutil.ReadFile(p)
		if err != nil {
			return "", err
		}
		blobs = append(blobs, pem)
	}
	return string(bytes.Join(blobs, []byte("\n"))), nil
}

func newExecKubeconfig(cluster *clientcmdapi.Cluster, execConfig *clientcmdapi.ExecConfig) clientcmdapi.Config {
	const name = "pinniped"
	return clientcmdapi.Config{
		Kind:           "Config",
		APIVersion:     clientcmdapi.SchemeGroupVersion.Version,
		Clusters:       map[string]*clientcmdapi.Cluster{name: cluster},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{name: {Exec: execConfig}},
		Contexts:       map[string]*clientcmdapi.Context{name: {Cluster: name, AuthInfo: name}},
		CurrentContext: name,
	}
}

func lookupAuthenticator(clientset conciergeclientset.Interface, namespace, authType, authName string) (metav1.Object, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	// If one was specified, look it up or error.
	if authName != "" && authType != "" {
		switch strings.ToLower(authType) {
		case "webhook":
			return clientset.AuthenticationV1alpha1().WebhookAuthenticators(namespace).Get(ctx, authName, metav1.GetOptions{})
		case "jwt":
			return clientset.AuthenticationV1alpha1().JWTAuthenticators(namespace).Get(ctx, authName, metav1.GetOptions{})
		default:
			return nil, fmt.Errorf(`invalid authenticator type %q, supported values are "webhook" and "jwt"`, authType)
		}
	}

	// Otherwise list all the available authenticators and hope there's just a single one.

	jwtAuths, err := clientset.AuthenticationV1alpha1().JWTAuthenticators(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list JWTAuthenticator objects for autodiscovery: %w", err)
	}
	webhooks, err := clientset.AuthenticationV1alpha1().WebhookAuthenticators(namespace).List(ctx, metav1.ListOptions{})
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
		return nil, fmt.Errorf("no authenticators were found in namespace %q (try setting --concierge-namespace)", namespace)
	}
	if len(results) > 1 {
		return nil, fmt.Errorf("multiple authenticators were found in namespace %q, so the --concierge-authenticator-type/--concierge-authenticator-name flags must be specified", namespace)
	}
	return results[0], nil
}

func newClientConfig(kubeconfigPathOverride string, currentContextName string) clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPathOverride
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{
		CurrentContext: currentContextName,
	})
	return clientConfig
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

func copyCurrentClusterFromExistingKubeConfig(currentKubeConfig clientcmdapi.Config, currentContextNameOverride string) (*clientcmdapi.Cluster, error) {
	contextName := currentKubeConfig.CurrentContext
	if currentContextNameOverride != "" {
		contextName = currentContextNameOverride
	}
	context := currentKubeConfig.Contexts[contextName]
	if context == nil {
		return nil, fmt.Errorf("no such context %q", contextName)
	}
	return currentKubeConfig.Clusters[context.Cluster], nil
}
