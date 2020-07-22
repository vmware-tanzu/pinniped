/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package app is the command line entry point for placeholder-name.
package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"time"

	"k8s.io/apiserver/pkg/server/dynamiccertificates"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	"github.com/suzerain-io/placeholder-name/internal/autoregistration"
	"github.com/suzerain-io/placeholder-name/internal/certauthority"
	"github.com/suzerain-io/placeholder-name/internal/downward"

	"k8s.io/apimachinery/pkg/runtime"

	"github.com/spf13/cobra"
	genericapiserver "k8s.io/apiserver/pkg/server"
	genericoptions "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	"k8s.io/client-go/kubernetes"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	restclient "k8s.io/client-go/rest"
	aggregationv1client "k8s.io/kube-aggregator/pkg/client/clientset_generated/clientset"

	placeholderv1alpha1 "github.com/suzerain-io/placeholder-name-api/pkg/apis/placeholder/v1alpha1"
	"github.com/suzerain-io/placeholder-name/pkg/apiserver"
	"github.com/suzerain-io/placeholder-name/pkg/config"
)

// App is an object that represents the placeholder-name application.
type App struct {
	cmd *cobra.Command

	// CLI flags
	configPath      string
	downwardAPIPath string

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
		Use: `placeholder-name`,
		Long: `placeholder-name provides a generic API for mapping an external
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
			k8s, err := kubernetes.NewForConfig(protoKubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			// Connect to the Kubernetes aggregation API.
			aggregation, err := aggregationv1client.NewForConfig(protoKubeConfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			return a.run(ctx, k8s.CoreV1(), aggregation)
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

	a.cmd = cmd

	return a
}

func (a *App) Run() error {
	return a.cmd.Execute()
}

func (a *App) run(
	ctx context.Context,
	k8s corev1client.CoreV1Interface,
	aggregation aggregationv1client.Interface,
) error {
	cfg, err := config.FromPath(a.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	webhookTokenAuthenticator, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could create webhook client: %w", err)
	}

	podinfo, err := downward.Load(a.downwardAPIPath)
	if err != nil {
		return fmt.Errorf("could not read pod metadata: %w", err)
	}

	// TODO use the postStart hook to generate certs?

	ca, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	if err != nil {
		return fmt.Errorf("could not initialize CA: %w", err)
	}
	caBundle, err := ca.Bundle()
	if err != nil {
		return fmt.Errorf("could not read CA bundle: %w", err)
	}
	log.Printf("initialized CA bundle:\n%s", string(caBundle))

	const serviceName = "placeholder-name-api"

	cert, err := ca.Issue(
		pkix.Name{CommonName: serviceName + "." + podinfo.Namespace + ".svc"},
		[]string{},
		24*365*time.Hour,
	)
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	// Dynamically register our v1alpha1 API service.
	service := corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: serviceName},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       443,
					TargetPort: intstr.IntOrString{IntVal: 443},
				},
			},
			Selector: podinfo.Labels,
			Type:     corev1.ServiceTypeClusterIP,
		},
	}
	apiService := apiregistrationv1.APIService{
		ObjectMeta: metav1.ObjectMeta{
			Name: placeholderv1alpha1.SchemeGroupVersion.Version + "." + placeholderv1alpha1.GroupName,
		},
		Spec: apiregistrationv1.APIServiceSpec{
			Group:                placeholderv1alpha1.GroupName,
			Version:              placeholderv1alpha1.SchemeGroupVersion.Version,
			CABundle:             caBundle,
			GroupPriorityMinimum: 2500, // TODO what is the right value? https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#apiservicespec-v1beta1-apiregistration-k8s-io
			VersionPriority:      10,   // TODO what is the right value? https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.18/#apiservicespec-v1beta1-apiregistration-k8s-io
		},
	}
	if err := autoregistration.Setup(ctx, autoregistration.SetupOptions{
		CoreV1:             k8s,
		AggregationV1:      aggregation,
		Namespace:          podinfo.Namespace,
		ServiceTemplate:    service,
		APIServiceTemplate: apiService,
	}); err != nil {
		return fmt.Errorf("could not register API service: %w", err)
	}

	apiServerConfig, err := a.ConfigServer(cert, webhookTokenAuthenticator)
	if err != nil {
		return err
	}

	server, err := apiServerConfig.Complete().New()
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	return server.GenericAPIServer.PrepareRun().Run(ctx.Done())
}

func (a *App) ConfigServer(cert *tls.Certificate, webhookTokenAuthenticator *webhook.WebhookTokenAuthenticator) (*apiserver.Config, error) {
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
			Webhook: webhookTokenAuthenticator,
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
