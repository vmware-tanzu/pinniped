// Copyright 2020 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ghodss/yaml"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	v1 "k8s.io/client-go/tools/clientcmd/api/v1"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/here"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(newGetKubeConfigCommand().Command())
}

type getKubeConfigFlags struct {
	token             string
	kubeconfig        string
	contextOverride   string
	namespace         string
	authenticatorName string
	authenticatorType string
}

type getKubeConfigCommand struct {
	flags getKubeConfigFlags
	// 	Test mocking points
	getPathToSelf     func() (string, error)
	kubeClientCreator func(restConfig *rest.Config) (pinnipedclientset.Interface, error)
}

func newGetKubeConfigCommand() *getKubeConfigCommand {
	return &getKubeConfigCommand{
		flags: getKubeConfigFlags{
			namespace: "pinniped",
		},
		getPathToSelf: os.Executable,
		kubeClientCreator: func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
			return pinnipedclientset.NewForConfig(restConfig)
		},
	}
}

func (c *getKubeConfigCommand) Command() *cobra.Command {
	cmd := &cobra.Command{
		RunE:  c.run,
		Args:  cobra.NoArgs, // do not accept positional arguments for this command
		Use:   "get-kubeconfig",
		Short: "Print a kubeconfig for authenticating into a cluster via Pinniped",
		Long: here.Doc(`
			Print a kubeconfig for authenticating into a cluster via Pinniped.

			Requires admin-like access to the cluster using the current
			kubeconfig context in order to access Pinniped's metadata.
			The current kubeconfig is found similar to how kubectl finds it:
			using the value of the --kubeconfig option, or if that is not
			specified then from the value of the KUBECONFIG environment
			variable, or if that is not specified then it defaults to
			.kube/config in your home directory.

			Prints a kubeconfig which is suitable to access the cluster using
			Pinniped as the authentication mechanism. This kubeconfig output
			can be saved to a file and used with future kubectl commands, e.g.:
				pinniped get-kubeconfig --token $MY_TOKEN > $HOME/mycluster-kubeconfig
				kubectl --kubeconfig $HOME/mycluster-kubeconfig get pods
		`),
	}
	cmd.Flags().StringVar(&c.flags.token, "token", "", "Credential to include in the resulting kubeconfig output (Required)")
	cmd.Flags().StringVar(&c.flags.kubeconfig, "kubeconfig", c.flags.kubeconfig, "Path to the kubeconfig file")
	cmd.Flags().StringVar(&c.flags.contextOverride, "kubeconfig-context", c.flags.contextOverride, "Kubeconfig context override")
	cmd.Flags().StringVar(&c.flags.namespace, "pinniped-namespace", c.flags.namespace, "Namespace in which Pinniped was installed")
	cmd.Flags().StringVar(&c.flags.authenticatorType, "authenticator-type", c.flags.authenticatorType, "Authenticator type (e.g., 'webhook')")
	cmd.Flags().StringVar(&c.flags.authenticatorName, "authenticator-name", c.flags.authenticatorType, "Authenticator name")
	mustMarkRequired(cmd, "token")
	return cmd
}

func (c *getKubeConfigCommand) run(cmd *cobra.Command, args []string) error {
	fullPathToSelf, err := c.getPathToSelf()
	if err != nil {
		return fmt.Errorf("could not find path to self: %w", err)
	}

	clientConfig := newClientConfig(c.flags.kubeconfig, c.flags.contextOverride)

	currentKubeConfig, err := clientConfig.RawConfig()
	if err != nil {
		return err
	}

	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return err
	}
	clientset, err := c.kubeClientCreator(restConfig)
	if err != nil {
		return err
	}

	authenticatorType, authenticatorName := c.flags.authenticatorType, c.flags.authenticatorName
	if authenticatorType == "" || authenticatorName == "" {
		authenticatorType, authenticatorName, err = getDefaultAuthenticator(clientset, c.flags.namespace)
		if err != nil {
			return err
		}
	}

	credentialIssuerConfig, err := fetchPinnipedCredentialIssuerConfig(clientset, c.flags.namespace)
	if err != nil {
		return err
	}

	if credentialIssuerConfig.Status.KubeConfigInfo == nil {
		return constable.Error(`CredentialIssuerConfig "pinniped-config" was missing KubeConfigInfo`)
	}

	v1Cluster, err := copyCurrentClusterFromExistingKubeConfig(currentKubeConfig, c.flags.contextOverride)
	if err != nil {
		return err
	}

	err = issueWarningForNonMatchingServerOrCA(v1Cluster, credentialIssuerConfig, cmd.ErrOrStderr())
	if err != nil {
		return err
	}

	config := newPinnipedKubeconfig(v1Cluster, fullPathToSelf, c.flags.token, c.flags.namespace, authenticatorType, authenticatorName)

	err = writeConfigAsYAML(cmd.OutOrStdout(), config)
	if err != nil {
		return err
	}

	return nil
}

func issueWarningForNonMatchingServerOrCA(v1Cluster v1.Cluster, credentialIssuerConfig *configv1alpha1.CredentialIssuerConfig, warningsWriter io.Writer) error {
	credentialIssuerConfigCA, err := base64.StdEncoding.DecodeString(credentialIssuerConfig.Status.KubeConfigInfo.CertificateAuthorityData)
	if err != nil {
		return err
	}
	if v1Cluster.Server != credentialIssuerConfig.Status.KubeConfigInfo.Server ||
		!bytes.Equal(v1Cluster.CertificateAuthorityData, credentialIssuerConfigCA) {
		_, err := warningsWriter.Write([]byte("WARNING: Server and certificate authority did not match between local kubeconfig and Pinniped's CredentialIssuerConfig on the cluster. Using local kubeconfig values.\n"))
		if err != nil {
			return fmt.Errorf("output write error: %w", err)
		}
	}
	return nil
}

type noAuthenticatorError struct{ Namespace string }

func (e noAuthenticatorError) Error() string {
	return fmt.Sprintf(`no authenticators were found in namespace %q`, e.Namespace)
}

type indeterminateAuthenticatorError struct{ Namespace string }

func (e indeterminateAuthenticatorError) Error() string {
	return fmt.Sprintf(
		`multiple authenticators were found in namespace %q, so --authenticator-name/--authenticator-type must be specified`,
		e.Namespace,
	)
}

func getDefaultAuthenticator(clientset pinnipedclientset.Interface, namespace string) (string, string, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	webhooks, err := clientset.AuthenticationV1alpha1().WebhookAuthenticators(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", "", err
	}

	type ref struct{ authenticatorType, authenticatorName string }
	authenticators := make([]ref, 0, len(webhooks.Items))
	for _, webhook := range webhooks.Items {
		authenticators = append(authenticators, ref{authenticatorType: "webhook", authenticatorName: webhook.Name})
	}

	if len(authenticators) == 0 {
		return "", "", noAuthenticatorError{namespace}
	}
	if len(authenticators) > 1 {
		return "", "", indeterminateAuthenticatorError{namespace}
	}
	return authenticators[0].authenticatorType, authenticators[0].authenticatorName, nil
}

func fetchPinnipedCredentialIssuerConfig(clientset pinnipedclientset.Interface, pinnipedInstallationNamespace string) (*configv1alpha1.CredentialIssuerConfig, error) {
	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	credentialIssuerConfigs, err := clientset.ConfigV1alpha1().CredentialIssuerConfigs(pinnipedInstallationNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	if len(credentialIssuerConfigs.Items) == 0 {
		return nil, constable.Error(fmt.Sprintf(
			`No CredentialIssuerConfig was found in namespace "%s". Is Pinniped installed on this cluster in namespace "%s"?`,
			pinnipedInstallationNamespace,
			pinnipedInstallationNamespace,
		))
	}

	if len(credentialIssuerConfigs.Items) > 1 {
		return nil, constable.Error(fmt.Sprintf(
			`More than one CredentialIssuerConfig was found in namespace "%s"`,
			pinnipedInstallationNamespace,
		))
	}

	return &credentialIssuerConfigs.Items[0], nil
}

func newClientConfig(kubeconfigPathOverride string, currentContextName string) clientcmd.ClientConfig {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPathOverride
	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, &clientcmd.ConfigOverrides{
		CurrentContext: currentContextName,
	})
	return clientConfig
}

func writeConfigAsYAML(outputWriter io.Writer, config v1.Config) error {
	output, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("YAML serialization error: %w", err)
	}

	_, err = outputWriter.Write(output)
	if err != nil {
		return fmt.Errorf("output write error: %w", err)
	}

	return nil
}

func copyCurrentClusterFromExistingKubeConfig(currentKubeConfig clientcmdapi.Config, currentContextNameOverride string) (v1.Cluster, error) {
	v1Cluster := v1.Cluster{}

	contextName := currentKubeConfig.CurrentContext
	if currentContextNameOverride != "" {
		contextName = currentContextNameOverride
	}

	err := v1.Convert_api_Cluster_To_v1_Cluster(
		currentKubeConfig.Clusters[currentKubeConfig.Contexts[contextName].Cluster],
		&v1Cluster,
		nil,
	)
	if err != nil {
		return v1.Cluster{}, err
	}

	return v1Cluster, nil
}

func newPinnipedKubeconfig(v1Cluster v1.Cluster, fullPathToSelf string, token string, namespace string, authenticatorType string, authenticatorName string) v1.Config {
	clusterName := "pinniped-cluster"
	userName := "pinniped-user"

	return v1.Config{
		Kind:        "Config",
		APIVersion:  v1.SchemeGroupVersion.Version,
		Preferences: v1.Preferences{},
		Clusters: []v1.NamedCluster{
			{
				Name:    clusterName,
				Cluster: v1Cluster,
			},
		},
		Contexts: []v1.NamedContext{
			{
				Name: clusterName,
				Context: v1.Context{
					Cluster:  clusterName,
					AuthInfo: userName,
				},
			},
		},
		AuthInfos: []v1.NamedAuthInfo{
			{
				Name: userName,
				AuthInfo: v1.AuthInfo{
					Exec: &v1.ExecConfig{
						Command: fullPathToSelf,
						Args:    []string{"exchange-credential"},
						Env: []v1.ExecEnvVar{
							{
								Name:  "PINNIPED_K8S_API_ENDPOINT",
								Value: v1Cluster.Server,
							},
							{
								Name:  "PINNIPED_CA_BUNDLE",
								Value: string(v1Cluster.CertificateAuthorityData)},
							{
								Name:  "PINNIPED_NAMESPACE",
								Value: namespace,
							},
							{
								Name:  "PINNIPED_TOKEN",
								Value: token,
							},
							{
								Name:  "PINNIPED_AUTHENTICATOR_TYPE",
								Value: authenticatorType,
							},
							{
								Name:  "PINNIPED_AUTHENTICATOR_NAME",
								Value: authenticatorName,
							},
						},
						APIVersion: clientauthenticationv1beta1.SchemeGroupVersion.String(),
						InstallHint: "The Pinniped CLI is required to authenticate to the current cluster.\n" +
							"For more information, please visit https://pinniped.dev",
					},
				},
			},
		},
		CurrentContext: clusterName,
	}
}
