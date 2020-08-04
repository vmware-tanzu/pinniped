/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package server is the command line entry point for placeholder-name-server.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	genericapiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	aggregationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	"github.com/suzerain-io/controller-go"
	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	placeholderclientset "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/clientset/versioned"
	placeholderinformers "github.com/suzerain-io/placeholder-name-client-go/pkg/generated/informers/externalversions"
	"github.com/suzerain-io/placeholder-name/internal/apiserver"
	"github.com/suzerain-io/placeholder-name/internal/autoregistration"
	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	"github.com/suzerain-io/placeholder-name/internal/controller/logindiscovery"
	"github.com/suzerain-io/placeholder-name/internal/downward"
	"github.com/suzerain-io/placeholder-name/pkg/config"
)

const (
	singletonWorker       = 1
	defaultResyncInterval = 3 * time.Minute
)

// App is an object that represents the placeholder-name-server application.
type App struct {
	cmd *cobra.Command

	// CLI flags
	configPath                 string
	downwardAPIPath            string
	clusterSigningCertFilePath string
	clusterSigningKeyFilePath  string

	recommendedOptions *genericoptions.RecommendedOptions
}

// This is ignored for now because we turn off etcd storage below, but this is
// the right prefix in case we turn it back on.
const defaultEtcdPathPrefix = "/registry/" + placeholderv1alpha1.GroupName

// New constructs a new App with command line args, stdout and stderr.
func New(ctx context.Context, args []string, stdout, stderr io.Writer) *App {
	a := &App{
		recommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(placeholderv1alpha1.SchemeGroupVersion),
			// TODO we should check to see if all the other default settings are acceptable for us
		),
	}
	a.recommendedOptions.Etcd = nil // turn off etcd storage because we don't need it yet

	cmd := &cobra.Command{
		Use: `placeholder-name-server`,
		Long: `placeholder-name-server provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load the Kubernetes client configuration (kubeconfig),
			kubeConfig, err := restclient.InClusterConfig()
			if err != nil {
				return fmt.Errorf("could not load in-cluster configuration: %w", err)
			}

			// explicitly use protobuf when talking to built-in kube APIs
			protoKubeConfig := createProtoKubeConfig(kubeConfig)

			// Connect to the core Kubernetes API.
			k8sClient, err := kubernetes.NewForConfig(protoKubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			// Connect to the Kubernetes aggregation API.
			aggregationClient, err := aggregationv1client.NewForConfig(protoKubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			// Connect to the placeholder API.
			// I think we can't use protobuf encoding here because we are using CRDs
			// (for which protobuf encoding is not supported).
			placeholderClient, err := placeholderclientset.NewForConfig(kubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize placeholder client: %w", err)
			}

			return a.run(ctx, k8sClient, aggregationClient, placeholderClient)
		},
		Args: cobra.NoArgs,
	}

	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)

	cmd.Flags().StringVarP(
		&a.configPath,
		"config",
		"c",
		"placeholder-name.yaml",
		"path to configuration file",
	)

	cmd.Flags().StringVar(
		&a.downwardAPIPath,
		"downward-api-path",
		"/etc/podinfo",
		"path to Downward API volume mount",
	)

	cmd.Flags().StringVar(
		&a.clusterSigningCertFilePath,
		"cluster-signing-cert-file",
		"",
		"path to cluster signing certificate",
	)

	cmd.Flags().StringVar(
		&a.clusterSigningKeyFilePath,
		"cluster-signing-key-file",
		"",
		"path to cluster signing private key",
	)

	a.cmd = cmd

	return a
}

func (a *App) Run() error {
	return a.cmd.Execute()
}

func (a *App) run(
	ctx context.Context,
	k8sClient kubernetes.Interface,
	aggregationClient aggregationv1client.Interface,
	placeholderClient placeholderclientset.Interface,
) error {
	cfg, err := config.FromPath(a.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	// Load the Kubernetes cluster signing CA.
	clientCA, err := certauthority.Load(a.clusterSigningCertFilePath, a.clusterSigningKeyFilePath)
	if err != nil {
		return fmt.Errorf("could not load cluster signing CA: %w", err)
	}

	webhookTokenAuthenticator, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could not create webhook client: %w", err)
	}

	podinfo, err := downward.Load(a.downwardAPIPath)
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}
	serverInstallationNamespace := podinfo.Namespace

	// TODO use the postStart hook to generate certs?

	aggregatedAPIServerCA, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}

	const serviceName = "placeholder-name-api"

	cert, err := aggregatedAPIServerCA.Issue(
		pkix.Name{CommonName: serviceName + "." + serverInstallationNamespace + ".svc"},
		[]string{},
		24*365*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	if err := autoregistration.UpdateAPIService(ctx, aggregationClient, aggregatedAPIServerCA.Bundle()); err != nil {
		return fmt.Errorf("could not register API service: %w", err)
	}

	cmrf := wireControllerManagerRunFunc(
		serverInstallationNamespace,
		cfg.DiscoveryConfig.URL,
		k8sClient,
		placeholderClient,
	)
	apiServerConfig, err := a.configServer(
		cert,
		webhookTokenAuthenticator,
		clientCA,
		cmrf,
	)
	if err != nil {
		return err
	}

	server, err := apiServerConfig.Complete().New()
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	return server.GenericAPIServer.PrepareRun().Run(ctx.Done())
}

func (a *App) configServer(
	cert *tls.Certificate,
	webhookTokenAuthenticator *webhook.WebhookTokenAuthenticator,
	ca *certauthority.CA,
	startControllersPostStartHook func(context.Context),
) (*apiserver.Config, error) {
	provider, err := createStaticCertKeyProvider(cert)
	if err != nil {
		return nil, fmt.Errorf("could not create static cert key provider: %w", err)
	}
	a.recommendedOptions.SecureServing.ServerCert.GeneratedCert = provider

	serverConfig := genericapiserver.NewRecommendedConfig(apiserver.Codecs)
	if err := a.recommendedOptions.ApplyTo(serverConfig); err != nil {
		return nil, err
	}

	apiServerConfig := &apiserver.Config{
		GenericConfig: serverConfig,
		ExtraConfig: apiserver.ExtraConfig{
			Webhook:                       webhookTokenAuthenticator,
			Issuer:                        ca,
			StartControllersPostStartHook: startControllersPostStartHook,
		},
	}
	return apiServerConfig, nil
}

// createProtoKubeConfig returns a copy of the input config with the ContentConfig set to use protobuf.
// do not use this config to communicate with any CRD based APIs.
func createProtoKubeConfig(kubeConfig *restclient.Config) *restclient.Config {
	protoKubeConfig := restclient.CopyConfig(kubeConfig)
	const protoThenJSON = runtime.ContentTypeProtobuf + "," + runtime.ContentTypeJSON
	protoKubeConfig.AcceptContentTypes = protoThenJSON
	protoKubeConfig.ContentType = runtime.ContentTypeProtobuf
	return protoKubeConfig
}

func createStaticCertKeyProvider(cert *tls.Certificate) (dynamiccertificates.CertKeyContentProvider, error) {
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("error marshalling private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:    "PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDER,
	})

	certChainPEM := make([]byte, 0)
	for _, certFromChain := range cert.Certificate {
		certPEMBytes := pem.EncodeToMemory(&pem.Block{
			Type:    "CERTIFICATE",
			Headers: nil,
			Bytes:   certFromChain,
		})
		certChainPEM = append(certChainPEM, certPEMBytes...)
	}

	return dynamiccertificates.NewStaticCertKeyContent("some-name???", certChainPEM, privateKeyPEM)
}

func wireControllerManagerRunFunc(
	serverInstallationNamespace string,
	discoveryURLOverride *string,
	k8s kubernetes.Interface,
	placeholder placeholderclientset.Interface,
) func(ctx context.Context) {
	k8sInformers := k8sinformers.NewSharedInformerFactoryWithOptions(
		k8s,
		defaultResyncInterval,
		k8sinformers.WithNamespace(
			logindiscovery.ClusterInfoNamespace,
		),
	)
	placeholderInformers := placeholderinformers.NewSharedInformerFactoryWithOptions(
		placeholder,
		defaultResyncInterval,
		placeholderinformers.WithNamespace(serverInstallationNamespace),
	)
	cm := controller.
		NewManager().
		WithController(
			logindiscovery.NewPublisherController(
				serverInstallationNamespace,
				discoveryURLOverride,
				placeholder,
				k8sInformers.Core().V1().ConfigMaps(),
				placeholderInformers.Crds().V1alpha1().LoginDiscoveryConfigs(),
				controller.WithInformer,
			),
			singletonWorker,
		)
	return func(ctx context.Context) {
		k8sInformers.Start(ctx.Done())
		placeholderInformers.Start(ctx.Done())
		go cm.Start(ctx)
	}
}
