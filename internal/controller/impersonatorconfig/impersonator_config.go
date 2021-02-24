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
	"sync"
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
	servicesInformer                 corev1informers.ServiceInformer
	secretsInformer                  corev1informers.SecretInformer
	generatedLoadBalancerServiceName string
	tlsSecretName                    string
	labels                           map[string]string
	startTLSListenerFunc             StartTLSListenerFunc
	httpHandlerFactory               func() (http.Handler, error)

	server               *http.Server
	hasControlPlaneNodes *bool
	tlsCert              *tls.Certificate
	tlsCertMutex         sync.RWMutex
}

type StartTLSListenerFunc func(network, listenAddress string, config *tls.Config) (net.Listener, error)

func NewImpersonatorConfigController(
	namespace string,
	configMapResourceName string,
	k8sClient kubernetes.Interface,
	configMapsInformer corev1informers.ConfigMapInformer,
	servicesInformer corev1informers.ServiceInformer,
	secretsInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	withInitialEvent pinnipedcontroller.WithInitialEventOptionFunc,
	generatedLoadBalancerServiceName string,
	tlsSecretName string,
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
				servicesInformer:                 servicesInformer,
				secretsInformer:                  secretsInformer,
				generatedLoadBalancerServiceName: generatedLoadBalancerServiceName,
				tlsSecretName:                    tlsSecretName,
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
		withInformer(
			servicesInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(generatedLoadBalancerServiceName, namespace),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretsInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(tlsSecretName, namespace),
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
	plog.Debug("Starting impersonatorConfigController Sync")

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

	if c.shouldHaveImpersonator(config) {
		if err = c.ensureImpersonatorIsStarted(); err != nil {
			return err
		}
	} else {
		if err = c.ensureImpersonatorIsStopped(); err != nil {
			return err
		}
	}

	if c.shouldHaveLoadBalancer(config) {
		if err = c.ensureLoadBalancerIsStarted(ctx.Context); err != nil {
			return err
		}
	} else {
		if err = c.ensureLoadBalancerIsStopped(ctx.Context); err != nil {
			return err
		}
	}

	if c.shouldHaveTLSSecret(config) {
		if err = c.ensureTLSSecretIsCreated(ctx.Context, config); err != nil {
			// return err // TODO
		}
	} else {
		if err = c.ensureTLSSecretIsRemoved(ctx.Context); err != nil {
			return err
		}
	}

	plog.Debug("Successfully finished impersonatorConfigController Sync")

	return nil
}

func (c *impersonatorConfigController) shouldHaveTLSSecret(config *impersonator.Config) bool {
	return c.shouldHaveImpersonator(config)
}

func (c *impersonatorConfigController) shouldHaveImpersonator(config *impersonator.Config) bool {
	return (config.Mode == impersonator.ModeAuto && !*c.hasControlPlaneNodes) || config.Mode == impersonator.ModeEnabled
}

func (c *impersonatorConfigController) shouldHaveLoadBalancer(config *impersonator.Config) bool {
	return c.shouldHaveImpersonator(config) && config.Endpoint == ""
}

func (c *impersonatorConfigController) ensureImpersonatorIsStopped() error {
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

func (c *impersonatorConfigController) ensureImpersonatorIsStarted() error {
	if c.server != nil {
		return nil
	}

	handler, err := c.httpHandlerFactory()
	if err != nil {
		return err
	}

	listener, err := c.startTLSListenerFunc("tcp", impersonationProxyPort, &tls.Config{
		MinVersion: tls.VersionTLS12, // Allow v1.2 because clients like the default `curl` on MacOS don't support 1.3 yet.
		GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.getTLSCert(), nil
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

func (c *impersonatorConfigController) isLoadBalancerRunning() (bool, error) {
	_, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c *impersonatorConfigController) tlsSecretExists() (bool, *v1.Secret, error) {
	secret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.tlsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, secret, nil
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStopped(ctx context.Context) error {
	running, err := c.isLoadBalancerRunning()
	if err != nil {
		return err
	}
	if !running {
		return nil
	}

	plog.Info("Deleting load balancer for impersonation proxy",
		"service", c.generatedLoadBalancerServiceName,
		"namespace", c.namespace)
	err = c.k8sClient.CoreV1().Services(c.namespace).Delete(ctx, c.generatedLoadBalancerServiceName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStarted(ctx context.Context) error {
	running, err := c.isLoadBalancerRunning()
	if err != nil {
		return err
	}
	if running {
		return nil
	}
	appNameLabel := c.labels["app"]
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
	plog.Info("creating load balancer for impersonation proxy",
		"service", c.generatedLoadBalancerServiceName,
		"namespace", c.namespace)
	_, err = c.k8sClient.CoreV1().Services(c.namespace).Create(ctx, &loadBalancer, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("could not create load balancer: %w", err)
	}
	return nil
}

func (c *impersonatorConfigController) ensureTLSSecretIsCreated(ctx context.Context, config *impersonator.Config) error {
	tlsSecretExists, tlsSecret, err := c.tlsSecretExists()
	if err != nil {
		return err
	}
	if tlsSecretExists {
		certPEM := tlsSecret.Data[v1.TLSCertKey]
		keyPEM := tlsSecret.Data[v1.TLSPrivateKeyKey]
		tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
		// TODO handle err, like when the Secret did not contain the fields that we expected
		c.setTLSCert(&tlsCert)
		return nil
	}
	impersonationCA, err := certauthority.New(pkix.Name{CommonName: "test CA"}, 24*time.Hour) // TODO change the length of this
	if err != nil {
		return fmt.Errorf("could not create impersonation CA: %w", err)
	}
	var ips []net.IP
	if config.Endpoint == "" { // TODO are there other cases where we need to do this?
		lb, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
		notFound := k8serrors.IsNotFound(err)
		if notFound {
			return nil
		}
		if err != nil {
			return err
		}
		ingresses := lb.Status.LoadBalancer.Ingress
		if len(ingresses) == 0 {
			return nil
		}
		ip := ingresses[0].IP // TODO multiple ips
		ips = []net.IP{net.ParseIP(ip)}
		// check with informer to get the ip address of the load balancer if its available
		// if not, return
	} else {
		ips = []net.IP{net.ParseIP(config.Endpoint)}
	}
	impersonationCert, err := impersonationCA.Issue(pkix.Name{}, nil, ips, 24*time.Hour) // TODO change the length of this
	if err != nil {
		return fmt.Errorf("could not create impersonation cert: %w", err)
	}

	c.setTLSCert(impersonationCert)

	certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
	// TODO error handling?

	// TODO handle error on create
	c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, &v1.Secret{
		Type: v1.SecretTypeTLS,
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.tlsSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			"ca.crt":            impersonationCA.Bundle(),
			v1.TLSPrivateKeyKey: keyPEM,
			v1.TLSCertKey:       certPEM,
		},
	}, metav1.CreateOptions{})
	return nil
}

func (c *impersonatorConfigController) ensureTLSSecretIsRemoved(ctx context.Context) error {
	tlsSecretExists, _, err := c.tlsSecretExists()
	if err != nil {
		return err
	}
	if !tlsSecretExists {
		return nil
	}
	plog.Info("Deleting TLS certificates for impersonation proxy",
		"service", c.tlsSecretName,
		"namespace", c.namespace)
	err = c.k8sClient.CoreV1().Secrets(c.namespace).Delete(ctx, c.tlsSecretName, metav1.DeleteOptions{})
	if err != nil {
		return err
	}

	return nil
}

func (c *impersonatorConfigController) setTLSCert(cert *tls.Certificate) {
	c.tlsCertMutex.Lock()
	defer c.tlsCertMutex.Unlock()
	c.tlsCert = cert
}

func (c *impersonatorConfigController) getTLSCert() *tls.Certificate {
	c.tlsCertMutex.RLock()
	defer c.tlsCertMutex.RUnlock()
	return c.tlsCert
}
