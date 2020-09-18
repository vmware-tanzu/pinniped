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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientauthenticationv1beta1 "k8s.io/client-go/pkg/apis/clientauthentication/v1beta1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	v1 "k8s.io/client-go/tools/clientcmd/api/v1"

	configv1alpha1 "go.pinniped.dev/generated/1.19/apis/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/1.19/client/clientset/versioned"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/here"
)

const (
	getKubeConfigCmdTokenFlagName             = "token"
	getKubeConfigCmdKubeconfigFlagName        = "kubeconfig"
	getKubeConfigCmdKubeconfigContextFlagName = "kubeconfig-context"
	getKubeConfigCmdPinnipedNamespaceFlagName = "pinniped-namespace"
)

//nolint: gochecknoinits
func init() {
	rootCmd.AddCommand(newGetKubeConfigCmd(os.Args, os.Stdout, os.Stderr).cmd)
}

type getKubeConfigCommand struct {
	// runFunc is called by the cobra.Command.Run hook. It is included here for
	// testability.
	runFunc func(
		stdout, stderr io.Writer,
		token, kubeconfigPathOverride, currentContextOverride, pinnipedInstallationNamespace string,
	)

	// cmd is the cobra.Command for this CLI command. It is included here for
	// testability.
	cmd *cobra.Command
}

func newGetKubeConfigCmd(args []string, stdout, stderr io.Writer) *getKubeConfigCommand {
	c := &getKubeConfigCommand{
		runFunc: runGetKubeConfig,
	}

	c.cmd = &cobra.Command{
		Run: func(cmd *cobra.Command, _ []string) {
			token := cmd.Flag(getKubeConfigCmdTokenFlagName).Value.String()
			kubeconfigPathOverride := cmd.Flag(getKubeConfigCmdKubeconfigFlagName).Value.String()
			currentContextOverride := cmd.Flag(getKubeConfigCmdKubeconfigContextFlagName).Value.String()
			pinnipedInstallationNamespace := cmd.Flag(getKubeConfigCmdPinnipedNamespaceFlagName).Value.String()
			c.runFunc(
				stdout,
				stderr,
				token,
				kubeconfigPathOverride,
				currentContextOverride,
				pinnipedInstallationNamespace,
			)
		},
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

	c.cmd.SetArgs(args)
	c.cmd.SetOut(stdout)
	c.cmd.SetErr(stderr)

	c.cmd.Flags().StringP(
		getKubeConfigCmdTokenFlagName,
		"",
		"",
		"Credential to include in the resulting kubeconfig output (Required)",
	)
	err := c.cmd.MarkFlagRequired(getKubeConfigCmdTokenFlagName)
	if err != nil {
		panic(err)
	}

	c.cmd.Flags().StringP(
		getKubeConfigCmdKubeconfigFlagName,
		"",
		"",
		"Path to the kubeconfig file",
	)

	c.cmd.Flags().StringP(
		getKubeConfigCmdKubeconfigContextFlagName,
		"",
		"",
		"Kubeconfig context override",
	)

	c.cmd.Flags().StringP(
		getKubeConfigCmdPinnipedNamespaceFlagName,
		"",
		"pinniped",
		"Namespace in which Pinniped was installed",
	)

	return c
}

func runGetKubeConfig(
	stdout, stderr io.Writer,
	token, kubeconfigPathOverride, currentContextOverride, pinnipedInstallationNamespace string,
) {
	err := getKubeConfig(
		stdout,
		stderr,
		token,
		kubeconfigPathOverride,
		currentContextOverride,
		pinnipedInstallationNamespace,
		func(restConfig *rest.Config) (pinnipedclientset.Interface, error) {
			return pinnipedclientset.NewForConfig(restConfig)
		},
	)

	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
		os.Exit(1)
	}
}

func getKubeConfig(
	outputWriter io.Writer,
	warningsWriter io.Writer,
	token string,
	kubeconfigPathOverride string,
	currentContextNameOverride string,
	pinnipedInstallationNamespace string,
	kubeClientCreator func(restConfig *rest.Config) (pinnipedclientset.Interface, error),
) error {
	if token == "" {
		return constable.Error("--" + getKubeConfigCmdTokenFlagName + " flag value cannot be empty")
	}

	fullPathToSelf, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not find path to self: %w", err)
	}

	clientConfig := newClientConfig(kubeconfigPathOverride, currentContextNameOverride)

	currentKubeConfig, err := clientConfig.RawConfig()
	if err != nil {
		return err
	}

	credentialIssuerConfig, err := fetchPinnipedCredentialIssuerConfig(clientConfig, kubeClientCreator, pinnipedInstallationNamespace)
	if err != nil {
		return err
	}

	if credentialIssuerConfig.Status.KubeConfigInfo == nil {
		return constable.Error(`CredentialIssuerConfig "pinniped-config" was missing KubeConfigInfo`)
	}

	v1Cluster, err := copyCurrentClusterFromExistingKubeConfig(currentKubeConfig, currentContextNameOverride)
	if err != nil {
		return err
	}

	err = issueWarningForNonMatchingServerOrCA(v1Cluster, credentialIssuerConfig, warningsWriter)
	if err != nil {
		return err
	}

	config := newPinnipedKubeconfig(v1Cluster, fullPathToSelf, token, pinnipedInstallationNamespace)

	err = writeConfigAsYAML(outputWriter, config)
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

func fetchPinnipedCredentialIssuerConfig(clientConfig clientcmd.ClientConfig, kubeClientCreator func(restConfig *rest.Config) (pinnipedclientset.Interface, error), pinnipedInstallationNamespace string) (*configv1alpha1.CredentialIssuerConfig, error) {
	restConfig, err := clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	clientset, err := kubeClientCreator(restConfig)
	if err != nil {
		return nil, err
	}

	ctx, cancelFunc := context.WithTimeout(context.Background(), time.Second*20)
	defer cancelFunc()

	credentialIssuerConfig, err := clientset.ConfigV1alpha1().CredentialIssuerConfigs(pinnipedInstallationNamespace).Get(ctx, issuerconfig.ConfigName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, constable.Error(fmt.Sprintf(
				`CredentialIssuerConfig "%s" was not found in namespace "%s". Is Pinniped installed on this cluster in namespace "%s"?`,
				issuerconfig.ConfigName,
				pinnipedInstallationNamespace,
				pinnipedInstallationNamespace,
			))
		}
		return nil, err
	}

	return credentialIssuerConfig, nil
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

func newPinnipedKubeconfig(v1Cluster v1.Cluster, fullPathToSelf string, token string, namespace string) v1.Config {
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
