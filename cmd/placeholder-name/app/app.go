/*
Copyright 2020 VMware, Inc.
SPDX-License-Identifier: Apache-2.0
*/

// Package app is the command line entry point for placeholder-name.
package app

import (
	"context"
	"fmt"
	"io"
	"net"

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

// This is ignored for now because we turn off etcd storage below, but this is the right prefix in case we turn it back on
const defaultEtcdPathPrefix = "/registry/" + placeholderv1alpha1.GroupName

// New constructs a new App with command line args, stdout and stderr.
func New(ctx context.Context, args []string, stdout, stderr io.Writer) *App {
	a := &App{
		recommendedOptions: genericoptions.NewRecommendedOptions(
			defaultEtcdPathPrefix,
			apiserver.Codecs.LegacyCodec(placeholderv1alpha1.SchemeGroupVersion),
		),
	}
	a.recommendedOptions.Etcd = nil // turn off etcd storage

	cmd := &cobra.Command{
		Use: `placeholder-name`,
		Long: `placeholder-name provides a generic API for mapping an external
credential from somewhere to an internal credential to be used for
authenticating to the Kubernetes API.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Load the Kubernetes client configuration (kubeconfig),
			kubeconfig, err := restclient.InClusterConfig()
			if err != nil {
				return fmt.Errorf("could not load in-cluster configuration: %w", err)
			}

			// Connect to the core Kubernetes API.
			k8s, err := kubernetes.NewForConfig(kubeconfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			// Connect to the Kubernetes aggregation API.
			aggregation, err := aggregationv1client.NewForConfig(kubeconfig)
			if err != nil {
				return fmt.Errorf("could not initialize Kubernetes client: %w", err)
			}

			return a.run(ctx, a.configPath, k8s.CoreV1(), aggregation)
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

func (a *App) run(ctx context.Context, configPath string,
	k8s corev1client.CoreV1Interface, aggregation aggregationv1client.Interface) error {

	cfg, err := config.FromPath(a.configPath)
	if err != nil {
		return fmt.Errorf("could not load config: %w", err)
	}

	webhookTokenAuthenticator, err := config.NewWebhook(cfg.WebhookConfig)
	if err != nil {
		return fmt.Errorf("could create webhook client: %w", err)
	}

	// TODO use this stuff again
	//podinfo, err := downward.Load(a.downwardAPIPath)
	//if err != nil {
	//	return fmt.Errorf("could not read pod metadata: %w", err)
	//}
	//
	//ca, err := certauthority.New(pkix.Name{CommonName: "Placeholder CA"})
	//if err != nil {
	//	return fmt.Errorf("could not initialize CA: %w", err)
	//}
	//caBundle, err := ca.Bundle()
	//if err != nil {
	//	return fmt.Errorf("could not read CA bundle: %w", err)
	//}
	//log.Printf("initialized CA bundle:\n%s", string(caBundle))
	//
	//cert, err := ca.Issue(
	//	pkix.Name{CommonName: "Placeholder Server"},
	//	[]string{"placeholder-serve"},
	//	24*365*time.Hour,
	//)
	//if err != nil {
	//	return fmt.Errorf("could not issue serving certificate: %w", err)
	//}
	//
	//// Dynamically register our v1alpha1 API service.
	//service := corev1.Service{
	//	ObjectMeta: metav1.ObjectMeta{Name: "placeholder-name-api"},
	//	Spec: corev1.ServiceSpec{
	//		Ports: []corev1.ServicePort{
	//			{
	//				Protocol:   corev1.ProtocolTCP,
	//				Port:       443,
	//				TargetPort: intstr.IntOrString{IntVal: 443},
	//			},
	//		},
	//		Selector: podinfo.Labels,
	//		Type:     corev1.ServiceTypeClusterIP,
	//	},
	//}
	//apiService := apiregistrationv1.APIService{
	//	ObjectMeta: metav1.ObjectMeta{
	//		Name: "v1alpha1." + placeholder.GroupName,
	//	},
	//	Spec: apiregistrationv1.APIServiceSpec{
	//		Group:                 placeholder.GroupName,
	//		Version:               "v1alpha1",
	//		CABundle:              caBundle,
	//		GroupPriorityMinimum:  2500,
	//		VersionPriority:       10,
	//	},
	//}
	//if err := autoregistration.Setup(ctx, autoregistration.SetupOptions{
	//	CoreV1:             k8s,
	//	AggregationV1:      aggregation,
	//	Namespace:          podinfo.Namespace,
	//	ServiceTemplate:    service,
	//	APIServiceTemplate: apiService,
	//}); err != nil {
	//	return fmt.Errorf("could not register API service: %w", err)
	//}

	apiServerConfig, err := a.ConfigServer(webhookTokenAuthenticator)
	if err != nil {
		return err
	}

	server, err := apiServerConfig.Complete().New()
	if err != nil {
		return fmt.Errorf("could not issue serving certificate: %w", err)
	}

	return server.GenericAPIServer.PrepareRun().Run(ctx.Done())
}

func (a *App) ConfigServer(webhookTokenAuthenticator *webhook.WebhookTokenAuthenticator) (*apiserver.Config, error) {
	// TODO Use certs created elsewhere instead of creating them here. Also dynamically determine namespace of service in the hostname.
	if err := a.recommendedOptions.SecureServing.MaybeDefaultWithSelfSignedCerts("placeholder-name.placeholder.svc", nil, []net.IP{net.ParseIP("127.0.0.1")}); err != nil {
		return nil, fmt.Errorf("error creating self-signed certificates: %w", err)
	}

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
