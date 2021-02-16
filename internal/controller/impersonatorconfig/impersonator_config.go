// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/clusterhost"
	"go.pinniped.dev/internal/concierge/impersonator"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/plog"
)

const (
	impersonationProxyPort = ":8444"
)

type impersonatorConfigController struct {
	namespace                        string
	configMapResourceName            string
	k8sClient                        kubernetes.Interface
	configMapsInformer               corev1informers.ConfigMapInformer
	generatedLoadBalancerServiceName string
	labels                           map[string]string
	startTLSListenerFunc             StartTLSListenerFunc
	httpHandlerFactory               func() (http.Handler, error)

	server               *http.Server
	loadBalancer         *v1.Service
	hasControlPlaneNodes *bool
}

type StartTLSListenerFunc func(network, listenAddress string, config *tls.Config) (net.Listener, error)

func NewImpersonatorConfigController(
	namespace string,
	configMapResourceName string,
	k8sClient kubernetes.Interface,
	configMapsInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	withInitialEvent pinnipedcontroller.WithInitialEventOptionFunc,
	generatedLoadBalancerServiceName string,
	labels map[string]string,
	startTLSListenerFunc StartTLSListenerFunc,
	httpHandlerFactory func() (http.Handler, error),
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "impersonator-config-controller",
			Syncer: &impersonatorConfigController{
				namespace:                        namespace,
				configMapResourceName:            configMapResourceName,
				k8sClient:                        k8sClient,
				configMapsInformer:               configMapsInformer,
				generatedLoadBalancerServiceName: generatedLoadBalancerServiceName,
				labels:                           labels,
				startTLSListenerFunc:             startTLSListenerFunc,
				httpHandlerFactory:               httpHandlerFactory,
			},
		},
		withInformer(
			configMapsInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(configMapResourceName, namespace),
			controllerlib.InformerOption{},
		),
		// Be sure to run once even if the ConfigMap that the informer is watching doesn't exist.
		withInitialEvent(controllerlib.Key{
			Namespace: namespace,
			Name:      configMapResourceName,
		}),
	)
}

func (c *impersonatorConfigController) Sync(ctx controllerlib.Context) error {
	plog.Info("impersonatorConfigController Sync")

	configMap, err := c.configMapsInformer.Lister().ConfigMaps(c.namespace).Get(c.configMapResourceName)
	notFound := k8serrors.IsNotFound(err)
	if err != nil && !notFound {
		return fmt.Errorf("failed to get %s/%s configmap: %w", c.namespace, c.configMapResourceName, err)
	}

	var config *impersonator.Config
	if notFound {
		plog.Info("Did not find impersonation proxy config: using default config values",
			"configmap", c.configMapResourceName,
			"namespace", c.namespace,
		)
		config = impersonator.NewConfig() // use default configuration options
	} else {
		config, err = impersonator.ConfigFromConfigMap(configMap)
		if err != nil {
			return fmt.Errorf("invalid impersonator configuration: %v", err)
		}
		plog.Info("Read impersonation proxy config",
			"configmap", c.configMapResourceName,
			"namespace", c.namespace,
		)
	}

	// Make a live API call to avoid the cost of having an informer watch all node changes on the cluster,
	// since there could be lots and we don't especially care about node changes.
	// Once we have concluded that there is or is not a visible control plane, then cache that decision
	// to avoid listing nodes very often.
	if c.hasControlPlaneNodes == nil {
		hasControlPlaneNodes, err := clusterhost.New(c.k8sClient).HasControlPlaneNodes(ctx.Context)
		if err != nil {
			return err
		}
		c.hasControlPlaneNodes = &hasControlPlaneNodes
		plog.Debug("Queried for control plane nodes", "foundControlPlaneNodes", hasControlPlaneNodes)
	}

	if (config.Mode == impersonator.ModeAuto && !*c.hasControlPlaneNodes) || config.Mode == impersonator.ModeEnabled {
		if err = c.startImpersonator(); err != nil {
			return err
		}
	} else {
		if err = c.stopImpersonator(); err != nil {
			return err
		}
	}

	// start the load balancer only if:
	// - the impersonator is running
	// - the cluster is cloud hosted
	// - there is no endpoint specified in the config
	if c.server != nil && !*c.hasControlPlaneNodes && config.Endpoint == "" {
		if err = c.startLoadBalancer(ctx.Context); err != nil {
			return err
		}
	} else {
		if err = c.stopLoadBalancer(ctx.Context); err != nil {
			return err
		}
	}

	return nil
}

func (c *impersonatorConfigController) stopImpersonator() error {
	if c.server != nil {
		plog.Info("Stopping impersonation proxy", "port", impersonationProxyPort)
		err := c.server.Close()
		c.server = nil
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *impersonatorConfigController) startImpersonator() error {
	if c.server != nil {
		return nil
	}

	impersonationCA, err := certauthority.New(pkix.Name{CommonName: "test CA"}, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("could not create impersonation CA: %w", err)
	}
	impersonationCert, err := impersonationCA.Issue(pkix.Name{}, []string{"impersonation-proxy"}, nil, 24*time.Hour)
	if err != nil {
		return fmt.Errorf("could not create impersonation cert: %w", err)
	}

	handler, err := c.httpHandlerFactory()
	if err != nil {
		return err
	}

	listener, err := c.startTLSListenerFunc("tcp", impersonationProxyPort, &tls.Config{
		MinVersion: tls.VersionTLS12, // Allow v1.2 because clients like the default `curl` on MacOS don't support 1.3 yet.
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return impersonationCert, nil
		},
	})
	if err != nil {
		return err
	}

	c.server = &http.Server{Handler: handler}

	go func() {
		plog.Info("Starting impersonation proxy", "port", impersonationProxyPort)
		err = c.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			plog.Info("The impersonation proxy server has shut down")
		} else {
			plog.Error("Unexpected shutdown of the impersonation proxy server", err)
		}
	}()
	return nil
}

func (c *impersonatorConfigController) stopLoadBalancer(ctx context.Context) error {
	if c.loadBalancer != nil {
		err := c.k8sClient.CoreV1().Services(c.namespace).Delete(ctx, c.generatedLoadBalancerServiceName, metav1.DeleteOptions{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *impersonatorConfigController) startLoadBalancer(ctx context.Context) error {
	if c.loadBalancer != nil {
		return nil
	}

	appNameLabel := c.labels["app"] // TODO what if this doesn't exist
	loadBalancer := v1.Service{
		Spec: v1.ServiceSpec{
			Type: "LoadBalancer",
			Ports: []v1.ServicePort{
				{
					TargetPort: intstr.FromInt(8444),
					Port:       443,
					Protocol:   v1.ProtocolTCP,
				},
			},
			Selector: map[string]string{"app": appNameLabel},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.generatedLoadBalancerServiceName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
	}
	createdLoadBalancer, err := c.k8sClient.CoreV1().Services(c.namespace).Create(ctx, &loadBalancer, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create load balancer: %w", err)
	}
	c.loadBalancer = createdLoadBalancer
	return nil
}
