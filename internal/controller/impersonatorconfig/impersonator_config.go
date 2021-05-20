// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/clock"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"

	"go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	pinnipedclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	conciergeconfiginformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/config/v1alpha1"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/clusterhost"
	"go.pinniped.dev/internal/concierge/impersonator"
	"go.pinniped.dev/internal/constable"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/apicerts"
	"go.pinniped.dev/internal/controller/issuerconfig"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/dynamiccert"
	"go.pinniped.dev/internal/plog"
)

const (
	impersonationProxyPort       = 8444
	defaultHTTPSPort             = 443
	approximatelyOneHundredYears = 100 * 365 * 24 * time.Hour
	caCommonName                 = "Pinniped Impersonation Proxy CA"
	caCrtKey                     = "ca.crt"
	caKeyKey                     = "ca.key"
	appLabelKey                  = "app"
)

type impersonatorConfigController struct {
	namespace                        string
	credentialIssuerResourceName     string
	generatedLoadBalancerServiceName string
	generatedClusterIPServiceName    string
	tlsSecretName                    string
	caSecretName                     string
	impersonationSignerSecretName    string

	k8sClient         kubernetes.Interface
	pinnipedAPIClient pinnipedclientset.Interface

	credIssuerInformer conciergeconfiginformers.CredentialIssuerInformer
	servicesInformer   corev1informers.ServiceInformer
	secretsInformer    corev1informers.SecretInformer

	labels                           map[string]string
	clock                            clock.Clock
	impersonationSigningCertProvider dynamiccert.Provider
	impersonatorFunc                 impersonator.FactoryFunc

	hasControlPlaneNodes              *bool
	serverStopCh                      chan struct{}
	errorCh                           chan error
	tlsServingCertDynamicCertProvider dynamiccert.Private
}

func NewImpersonatorConfigController(
	namespace string,
	credentialIssuerResourceName string,
	k8sClient kubernetes.Interface,
	pinnipedAPIClient pinnipedclientset.Interface,
	credentialIssuerInformer conciergeconfiginformers.CredentialIssuerInformer,
	servicesInformer corev1informers.ServiceInformer,
	secretsInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	withInitialEvent pinnipedcontroller.WithInitialEventOptionFunc,
	generatedLoadBalancerServiceName string,
	generatedClusterIPServiceName string,
	tlsSecretName string,
	caSecretName string,
	labels map[string]string,
	clock clock.Clock,
	impersonatorFunc impersonator.FactoryFunc,
	impersonationSignerSecretName string,
	impersonationSigningCertProvider dynamiccert.Provider,
) controllerlib.Controller {
	secretNames := sets.NewString(tlsSecretName, caSecretName, impersonationSignerSecretName)
	return controllerlib.New(
		controllerlib.Config{
			Name: "impersonator-config-controller",
			Syncer: &impersonatorConfigController{
				namespace:                         namespace,
				credentialIssuerResourceName:      credentialIssuerResourceName,
				generatedLoadBalancerServiceName:  generatedLoadBalancerServiceName,
				generatedClusterIPServiceName:     generatedClusterIPServiceName,
				tlsSecretName:                     tlsSecretName,
				caSecretName:                      caSecretName,
				impersonationSignerSecretName:     impersonationSignerSecretName,
				k8sClient:                         k8sClient,
				pinnipedAPIClient:                 pinnipedAPIClient,
				credIssuerInformer:                credentialIssuerInformer,
				servicesInformer:                  servicesInformer,
				secretsInformer:                   secretsInformer,
				labels:                            labels,
				clock:                             clock,
				impersonationSigningCertProvider:  impersonationSigningCertProvider,
				impersonatorFunc:                  impersonatorFunc,
				tlsServingCertDynamicCertProvider: dynamiccert.NewServingCert("impersonation-proxy-serving-cert"),
			},
		},
		withInformer(credentialIssuerInformer,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return obj.GetName() == credentialIssuerResourceName
			}),
			controllerlib.InformerOption{},
		),
		withInformer(
			servicesInformer,
			pinnipedcontroller.NameAndNamespaceExactMatchFilterFactory(generatedLoadBalancerServiceName, namespace),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretsInformer,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				return obj.GetNamespace() == namespace && secretNames.Has(obj.GetName())
			}, nil),
			controllerlib.InformerOption{},
		),
		// Be sure to run once even if the CredentialIssuer that the informer is watching doesn't exist so we can implement
		// the default configuration behavior.
		withInitialEvent(controllerlib.Key{Name: credentialIssuerResourceName}),
		// TODO fix these controller options to make this a singleton queue
	)
}

func (c *impersonatorConfigController) Sync(syncCtx controllerlib.Context) error {
	plog.Debug("Starting impersonatorConfigController Sync")

	strategy, err := c.doSync(syncCtx)

	if err != nil {
		strategy = &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.ErrorDuringSetupStrategyReason,
			Message:        err.Error(),
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
		// The impersonator is not ready, so clear the signer CA from the dynamic provider.
		c.clearSignerCA()
	}

	updateStrategyErr := c.updateStrategy(syncCtx.Context, strategy)
	if updateStrategyErr != nil {
		plog.Error("error while updating the CredentialIssuer status", err)
		if err == nil {
			err = updateStrategyErr
		}
	}

	if err == nil {
		plog.Debug("Successfully finished impersonatorConfigController Sync")
	}
	return err
}

type certNameInfo struct {
	// ready will be true when the certificate name information is known.
	// ready will be false when it is pending because we are waiting for a load balancer to get assigned an ip/hostname.
	// When false, the other fields in this struct should not be considered meaningful and may be zero values.
	ready bool

	// The IP address or hostname which was selected to be used as the name in the cert.
	// Either selectedIP or selectedHostname will be set, but not both.
	selectedIP       net.IP
	selectedHostname string

	// The name of the endpoint to which a client should connect to talk to the impersonator.
	// This may be a hostname or an IP, and may include a port number.
	clientEndpoint string
}

func (c *impersonatorConfigController) doSync(syncCtx controllerlib.Context) (*v1alpha1.CredentialIssuerStrategy, error) {
	ctx := syncCtx.Context

	config, err := c.loadImpersonationProxyConfiguration()
	if err != nil {
		return nil, err
	}

	// Make a live API call to avoid the cost of having an informer watch all node changes on the cluster,
	// since there could be lots and we don't especially care about node changes.
	// Once we have concluded that there is or is not a visible control plane, then cache that decision
	// to avoid listing nodes very often.
	if c.hasControlPlaneNodes == nil {
		hasControlPlaneNodes, err := clusterhost.New(c.k8sClient).HasControlPlaneNodes(ctx)
		if err != nil {
			return nil, err
		}
		c.hasControlPlaneNodes = &hasControlPlaneNodes
		plog.Debug("Queried for control plane nodes", "foundControlPlaneNodes", hasControlPlaneNodes)
	}

	if c.shouldHaveImpersonator(config) {
		if err = c.ensureImpersonatorIsStarted(syncCtx); err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureImpersonatorIsStopped(true); err != nil {
			return nil, err // TODO write unit test that errors during stopping the server are returned by sync
		}
	}

	if c.shouldHaveLoadBalancer(config) {
		if err = c.ensureLoadBalancerIsStarted(ctx, config); err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureLoadBalancerIsStopped(ctx); err != nil {
			return nil, err
		}
	}

	if c.shouldHaveClusterIPService(config) {
		if err = c.ensureClusterIPServiceIsStarted(ctx, config); err != nil {
			return nil, err
		}
	} // else { // TODO test stopping the cluster ip service
	//	if err = c.ensureClusterIPServiceIsStopped(ctx); err != nil {
	//		return nil, err
	//	}
	//}

	nameInfo, err := c.findDesiredTLSCertificateName(config)
	if err != nil {
		// Unexpected error while determining the name that should go into the certs, so clear any existing certs.
		c.tlsServingCertDynamicCertProvider.UnsetCertKeyContent()
		return nil, err
	}

	var impersonationCA *certauthority.CA
	if c.shouldHaveTLSSecret(config) {
		if impersonationCA, err = c.ensureCASecretIsCreated(ctx); err != nil {
			return nil, err
		}
		if err = c.ensureTLSSecret(ctx, nameInfo, impersonationCA); err != nil {
			return nil, err
		}
	} else if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
		return nil, err
	}

	credentialIssuerStrategyResult := c.doSyncResult(nameInfo, config, impersonationCA)

	if err = c.loadSignerCA(credentialIssuerStrategyResult.Status); err != nil {
		return nil, err
	}

	return credentialIssuerStrategyResult, nil
}

func (c *impersonatorConfigController) loadImpersonationProxyConfiguration() (*v1alpha1.ImpersonationProxySpec, error) {
	credIssuer, err := c.credIssuerInformer.Lister().Get(c.credentialIssuerResourceName)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s CredentialIssuer: %w", c.credentialIssuerResourceName, err)
	}

	// Make a copy of the spec since we got this object from informer cache.
	spec := credIssuer.Spec.DeepCopy().ImpersonationProxy
	if spec == nil {
		return nil, fmt.Errorf("could not load CredentialIssuer: spec.impersonationProxy is nil")
	}

	// Default service type to LoadBalancer (this is normally already done via CRD defaulting).
	if spec.Service.Type == "" {
		spec.Service.Type = v1alpha1.ImpersonationProxyServiceTypeLoadBalancer
	}

	if err := validateCredentialIssuerSpec(spec); err != nil {
		return nil, fmt.Errorf("could not load CredentialIssuer spec.impersonationProxy: %w", err)
	}
	plog.Info("Read impersonation proxy config",
		"credentialIssuer", c.credentialIssuerResourceName,
	)
	return spec, nil
}

func (c *impersonatorConfigController) shouldHaveImpersonator(config *v1alpha1.ImpersonationProxySpec) bool {
	return c.enabledByAutoMode(config) || config.Mode == v1alpha1.ImpersonationProxyModeEnabled
}

func (c *impersonatorConfigController) enabledByAutoMode(config *v1alpha1.ImpersonationProxySpec) bool {
	return config.Mode == v1alpha1.ImpersonationProxyModeAuto && !*c.hasControlPlaneNodes
}

func (c *impersonatorConfigController) disabledByAutoMode(config *v1alpha1.ImpersonationProxySpec) bool {
	return config.Mode == v1alpha1.ImpersonationProxyModeAuto && *c.hasControlPlaneNodes
}

func (c *impersonatorConfigController) disabledExplicitly(config *v1alpha1.ImpersonationProxySpec) bool {
	return config.Mode == v1alpha1.ImpersonationProxyModeDisabled
}

func (c *impersonatorConfigController) shouldHaveLoadBalancer(config *v1alpha1.ImpersonationProxySpec) bool {
	return c.shouldHaveImpersonator(config) && config.Service.Type == v1alpha1.ImpersonationProxyServiceTypeLoadBalancer
}

func (c *impersonatorConfigController) shouldHaveClusterIPService(config *v1alpha1.ImpersonationProxySpec) bool {
	return c.shouldHaveImpersonator(config) && config.Service.Type == v1alpha1.ImpersonationProxyServiceTypeClusterIP
}

func (c *impersonatorConfigController) shouldHaveTLSSecret(config *v1alpha1.ImpersonationProxySpec) bool {
	return c.shouldHaveImpersonator(config)
}

func (c *impersonatorConfigController) updateStrategy(ctx context.Context, strategy *v1alpha1.CredentialIssuerStrategy) error {
	// TODO use informer client rather than api client for reading
	return issuerconfig.UpdateStrategy(ctx, c.credentialIssuerResourceName, c.labels, c.pinnipedAPIClient, *strategy)
}

func (c *impersonatorConfigController) loadBalancerExists() (bool, error) {
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

func (c *impersonatorConfigController) loadBalancerNeedsUpdate(config *v1alpha1.ImpersonationProxySpec) (bool, error) {
	lb, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
	if err != nil {
		return false, err
	}
	// TODO this will break if anything other than pinniped is adding annotations
	if !reflect.DeepEqual(lb.Annotations, config.Service.Annotations) {
		return true, nil
	}
	if lb.Spec.LoadBalancerIP != config.Service.LoadBalancerIP {
		return true, nil
	}
	return false, nil
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

func (c *impersonatorConfigController) ensureImpersonatorIsStarted(syncCtx controllerlib.Context) error {
	if c.serverStopCh != nil {
		// The server was already started, but it could have died in the background, so make a non-blocking
		// check to see if it has sent any errors on the errorCh.
		select {
		case runningErr := <-c.errorCh:
			if runningErr == nil {
				// The server sent a nil error, meaning that it shutdown without reporting any particular
				// error for some reason. We would still like to report this as an error for logging purposes.
				runningErr = constable.Error("unexpected shutdown of proxy server")
			}
			// The server has stopped, so finish shutting it down.
			// If that fails too, return both errors for logging purposes.
			// By returning an error, the sync function will be called again
			// and we'll have a chance to restart the server.
			close(c.errorCh) // We don't want ensureImpersonatorIsStopped to block on reading this channel.
			stoppingErr := c.ensureImpersonatorIsStopped(false)
			return errors.NewAggregate([]error{runningErr, stoppingErr})
		default:
			// Seems like it is still running, so nothing to do.
			return nil
		}
	}

	plog.Info("Starting impersonation proxy", "port", impersonationProxyPort)
	startImpersonatorFunc, err := c.impersonatorFunc(
		impersonationProxyPort,
		c.tlsServingCertDynamicCertProvider,
		c.impersonationSigningCertProvider,
	)
	if err != nil {
		return err
	}

	c.serverStopCh = make(chan struct{})
	// use a buffered channel so that startImpersonatorFunc can send
	// on it without coordinating with the main controller go routine
	c.errorCh = make(chan error, 1)

	// startImpersonatorFunc will block until the server shuts down (or fails to start), so run it in the background.
	go func() {
		defer utilruntime.HandleCrash()

		// The server has stopped, so enqueue ourselves for another sync,
		// so we can try to start the server again as quickly as possible.
		defer syncCtx.Queue.AddRateLimited(syncCtx.Key)

		// Forward any errors returned by startImpersonatorFunc on the errorCh.
		c.errorCh <- startImpersonatorFunc(c.serverStopCh)
	}()

	return nil
}

func (c *impersonatorConfigController) ensureImpersonatorIsStopped(shouldCloseErrChan bool) error {
	if c.serverStopCh == nil {
		return nil
	}

	plog.Info("Stopping impersonation proxy", "port", impersonationProxyPort)
	close(c.serverStopCh)
	stopErr := <-c.errorCh

	if shouldCloseErrChan {
		close(c.errorCh)
	}

	c.serverStopCh = nil
	c.errorCh = nil

	return stopErr
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStarted(ctx context.Context, config *v1alpha1.ImpersonationProxySpec) error {
	appNameLabel := c.labels[appLabelKey]
	loadBalancer := v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeLoadBalancer,
			Ports: []v1.ServicePort{
				{
					TargetPort: intstr.FromInt(impersonationProxyPort),
					Port:       defaultHTTPSPort,
					Protocol:   v1.ProtocolTCP,
				},
			},
			LoadBalancerIP: config.Service.LoadBalancerIP,
			Selector:       map[string]string{appLabelKey: appNameLabel},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        c.generatedLoadBalancerServiceName,
			Namespace:   c.namespace,
			Labels:      c.labels,
			Annotations: config.Service.Annotations,
		},
	}
	running, err := c.loadBalancerExists()
	if err != nil {
		return err
	}
	if running {
		needsUpdate, err := c.loadBalancerNeedsUpdate(config)
		if err != nil {
			return err
		}
		if needsUpdate {
			plog.Info("updating load balancer for impersonation proxy",
				"service", c.generatedLoadBalancerServiceName,
				"namespace", c.namespace)
			_, err = c.k8sClient.CoreV1().Services(c.namespace).Update(ctx, &loadBalancer, metav1.UpdateOptions{})
			return err
		}
		return nil
	}
	plog.Info("creating load balancer for impersonation proxy",
		"service", c.generatedLoadBalancerServiceName,
		"namespace", c.namespace)
	_, err = c.k8sClient.CoreV1().Services(c.namespace).Create(ctx, &loadBalancer, metav1.CreateOptions{})
	return err
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStopped(ctx context.Context) error {
	running, err := c.loadBalancerExists()
	if err != nil {
		return err
	}
	if !running {
		return nil
	}

	plog.Info("Deleting load balancer for impersonation proxy",
		"service", c.generatedLoadBalancerServiceName,
		"namespace", c.namespace)
	return c.k8sClient.CoreV1().Services(c.namespace).Delete(ctx, c.generatedLoadBalancerServiceName, metav1.DeleteOptions{})
}

func (c *impersonatorConfigController) ensureClusterIPServiceIsStarted(ctx context.Context, config *v1alpha1.ImpersonationProxySpec) error {
	appNameLabel := c.labels[appLabelKey]
	clusterIP := v1.Service{
		Spec: v1.ServiceSpec{
			Type: v1.ServiceTypeClusterIP,
			Ports: []v1.ServicePort{
				{
					TargetPort: intstr.FromInt(impersonationProxyPort),
					Port:       defaultHTTPSPort,
					Protocol:   v1.ProtocolTCP,
				},
			},
			Selector: map[string]string{appLabelKey: appNameLabel},
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:        c.generatedClusterIPServiceName,
			Namespace:   c.namespace,
			Labels:      c.labels,
			Annotations: config.Service.Annotations,
		},
	}
	//running, err := c.ClusterIPExists() // TODO test that clusterip is only created once
	//if err != nil {
	//	return err
	//}
	//if running {
	//	needsUpdate, err := c.ClusterIPNeedsUpdate(config) // TODO test updating annotations on clusterip
	//	if err != nil {
	//		return err
	//	}
	//	if needsUpdate {
	//		plog.Info("updating load balancer for impersonation proxy",
	//			"service", c.generatedLoadBalancerServiceName,
	//			"namespace", c.namespace)
	//		_, err = c.k8sClient.CoreV1().Services(c.namespace).Update(ctx, &loadBalancer, metav1.UpdateOptions{})
	//		return err
	//	}
	//	return nil
	//}
	plog.Info("creating cluster ip for impersonation proxy",
		"service", c.generatedClusterIPServiceName,
		"namespace", c.namespace)
	_, err := c.k8sClient.CoreV1().Services(c.namespace).Create(ctx, &clusterIP, metav1.CreateOptions{})
	return err
}

func (c *impersonatorConfigController) ensureTLSSecret(ctx context.Context, nameInfo *certNameInfo, ca *certauthority.CA) error {
	secretFromInformer, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.tlsSecretName)
	notFound := k8serrors.IsNotFound(err)
	if !notFound && err != nil {
		return err
	}

	if !notFound {
		secretWasDeleted, err := c.deleteTLSSecretWhenCertificateDoesNotMatchDesiredState(ctx, nameInfo, ca, secretFromInformer)
		if err != nil {
			return err
		}
		// If it was deleted by the above call, then set it to nil. This allows us to avoid waiting
		// for the informer cache to update before deciding to proceed to create the new Secret below.
		if secretWasDeleted {
			secretFromInformer = nil
		}
	}

	return c.ensureTLSSecretIsCreatedAndLoaded(ctx, nameInfo, secretFromInformer, ca)
}

func (c *impersonatorConfigController) deleteTLSSecretWhenCertificateDoesNotMatchDesiredState(ctx context.Context, nameInfo *certNameInfo, ca *certauthority.CA, secret *v1.Secret) (bool, error) {
	certPEM := secret.Data[v1.TLSCertKey]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		plog.Warning("Found missing or not PEM-encoded data in TLS Secret",
			"invalidCertPEM", string(certPEM),
			"secret", c.tlsSecretName,
			"namespace", c.namespace)
		deleteErr := c.ensureTLSSecretIsRemoved(ctx)
		if deleteErr != nil {
			return false, fmt.Errorf("found missing or not PEM-encoded data in TLS Secret, but got error while deleting it: %w", deleteErr)
		}
		return true, nil
	}

	actualCertFromSecret, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		plog.Error("Found invalid PEM data in TLS Secret", err,
			"invalidCertPEM", string(certPEM),
			"secret", c.tlsSecretName,
			"namespace", c.namespace)
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, fmt.Errorf("PEM data represented an invalid cert, but got error while deleting it: %w", err)
		}
		return true, nil
	}

	keyPEM := secret.Data[v1.TLSPrivateKeyKey]
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		plog.Error("Found invalid private key PEM data in TLS Secret", err,
			"secret", c.tlsSecretName,
			"namespace", c.namespace)
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, fmt.Errorf("cert had an invalid private key, but got error while deleting it: %w", err)
		}
		return true, nil
	}

	opts := x509.VerifyOptions{Roots: ca.Pool()}
	if _, err = actualCertFromSecret.Verify(opts); err != nil {
		// The TLS cert was not signed by the current CA. Since they are mismatched, delete the TLS cert
		// so we can recreate it using the current CA.
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	if !nameInfo.ready {
		// We currently have a secret but we are waiting for a load balancer to be assigned an ingress, so
		// our current secret must be old/unwanted.
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	actualIPs := actualCertFromSecret.IPAddresses
	actualHostnames := actualCertFromSecret.DNSNames
	plog.Info("Checking TLS certificate names",
		"desiredIP", nameInfo.selectedIP,
		"desiredHostname", nameInfo.selectedHostname,
		"actualIPs", actualIPs,
		"actualHostnames", actualHostnames,
		"secret", c.tlsSecretName,
		"namespace", c.namespace)

	if certHostnameAndIPMatchDesiredState(nameInfo.selectedIP, actualIPs, nameInfo.selectedHostname, actualHostnames) {
		// The cert already matches the desired state, so there is no need to delete/recreate it.
		return false, nil
	}

	if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func certHostnameAndIPMatchDesiredState(desiredIP net.IP, actualIPs []net.IP, desiredHostname string, actualHostnames []string) bool {
	if desiredIP != nil && len(actualIPs) == 1 && desiredIP.Equal(actualIPs[0]) && len(actualHostnames) == 0 {
		return true
	}
	if desiredHostname != "" && len(actualHostnames) == 1 && desiredHostname == actualHostnames[0] && len(actualIPs) == 0 {
		return true
	}
	return false
}

func (c *impersonatorConfigController) ensureTLSSecretIsCreatedAndLoaded(ctx context.Context, nameInfo *certNameInfo, secret *v1.Secret, ca *certauthority.CA) error {
	if secret != nil {
		err := c.loadTLSCertFromSecret(secret)
		if err != nil {
			return err
		}
		return nil
	}

	if !nameInfo.ready {
		return nil
	}

	newTLSSecret, err := c.createNewTLSSecret(ctx, ca, nameInfo.selectedIP, nameInfo.selectedHostname)
	if err != nil {
		return err
	}

	err = c.loadTLSCertFromSecret(newTLSSecret)
	if err != nil {
		return err
	}

	return nil
}

func (c *impersonatorConfigController) ensureCASecretIsCreated(ctx context.Context) (*certauthority.CA, error) {
	caSecret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.caSecretName)
	if err != nil && !k8serrors.IsNotFound(err) {
		return nil, err
	}

	var impersonationCA *certauthority.CA
	if k8serrors.IsNotFound(err) {
		impersonationCA, err = c.createCASecret(ctx)
	} else {
		crtBytes := caSecret.Data[caCrtKey]
		keyBytes := caSecret.Data[caKeyKey]
		impersonationCA, err = certauthority.Load(string(crtBytes), string(keyBytes))
	}
	if err != nil {
		return nil, err
	}

	return impersonationCA, nil
}

func (c *impersonatorConfigController) createCASecret(ctx context.Context) (*certauthority.CA, error) {
	impersonationCA, err := certauthority.New(caCommonName, approximatelyOneHundredYears)
	if err != nil {
		return nil, fmt.Errorf("could not create impersonation CA: %w", err)
	}

	caPrivateKeyPEM, err := impersonationCA.PrivateKeyToPEM()
	if err != nil {
		return nil, err
	}

	secret := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.caSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			caCrtKey: impersonationCA.Bundle(),
			caKeyKey: caPrivateKeyPEM,
		},
		Type: v1.SecretTypeOpaque,
	}

	plog.Info("Creating CA certificates for impersonation proxy",
		"secret", c.caSecretName,
		"namespace", c.namespace)
	if _, err = c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, &secret, metav1.CreateOptions{}); err != nil {
		return nil, err
	}

	return impersonationCA, nil
}

func (c *impersonatorConfigController) findDesiredTLSCertificateName(config *v1alpha1.ImpersonationProxySpec) (*certNameInfo, error) {
	// possible valid options:
	// - you have a loadbalancer and are autoconfiguring the endpoint -> get cert info based on load balancer ip/hostnome
	// - you have a loadbalancer AND an external endpoint -> either should work since they should be the same
	// - external endpoint no loadbalancer or other service -> use the endpoint config
	// - external endpoint and ClusterIP -> use external endpoint?
	// - clusterip and no external endpoint
	if config.ExternalEndpoint != "" {
		return c.findTLSCertificateNameFromEndpointConfig(config), nil
	} // else if config.Service.Type == v1alpha1.ImpersonationProxyServiceTypeClusterIP {
	//	// c.findTLSCertificateNameFromClusterIPService()
	//	// TODO implement this
	//}
	return c.findTLSCertificateNameFromLoadBalancer()
}

func (c *impersonatorConfigController) findTLSCertificateNameFromEndpointConfig(config *v1alpha1.ImpersonationProxySpec) *certNameInfo {
	endpointMaybeWithPort := config.ExternalEndpoint
	endpointWithoutPort := strings.Split(endpointMaybeWithPort, ":")[0]
	parsedAsIP := net.ParseIP(endpointWithoutPort)
	if parsedAsIP != nil {
		return &certNameInfo{ready: true, selectedIP: parsedAsIP, clientEndpoint: endpointMaybeWithPort}
	}
	return &certNameInfo{ready: true, selectedHostname: endpointWithoutPort, clientEndpoint: endpointMaybeWithPort}
}

func (c *impersonatorConfigController) findTLSCertificateNameFromLoadBalancer() (*certNameInfo, error) {
	lb, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		// We aren't ready and will try again later in this case.
		return &certNameInfo{ready: false}, nil
	}
	if err != nil {
		return nil, err
	}
	ingresses := lb.Status.LoadBalancer.Ingress
	if len(ingresses) == 0 || (ingresses[0].Hostname == "" && ingresses[0].IP == "") {
		plog.Info("load balancer for impersonation proxy does not have an ingress yet, so skipping tls cert generation while we wait",
			"service", c.generatedLoadBalancerServiceName,
			"namespace", c.namespace)
		return &certNameInfo{ready: false}, nil
	}
	for _, ingress := range ingresses {
		hostname := ingress.Hostname
		if hostname != "" {
			return &certNameInfo{ready: true, selectedHostname: hostname, clientEndpoint: hostname}, nil
		}
	}
	for _, ingress := range ingresses {
		ip := ingress.IP
		parsedIP := net.ParseIP(ip)
		if parsedIP != nil {
			return &certNameInfo{ready: true, selectedIP: parsedIP, clientEndpoint: ip}, nil
		}
	}

	return nil, fmt.Errorf("could not find valid IP addresses or hostnames from load balancer %s/%s", c.namespace, lb.Name)
}

func (c *impersonatorConfigController) createNewTLSSecret(ctx context.Context, ca *certauthority.CA, ip net.IP, hostname string) (*v1.Secret, error) {
	var hostnames []string
	var ips []net.IP
	if hostname != "" {
		hostnames = []string{hostname}
	}
	if ip != nil {
		ips = []net.IP{ip}
	}

	impersonationCert, err := ca.IssueServerCert(hostnames, ips, approximatelyOneHundredYears)
	if err != nil {
		return nil, fmt.Errorf("could not create impersonation cert: %w", err)
	}

	certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
	if err != nil {
		return nil, err
	}

	newTLSSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.tlsSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			v1.TLSPrivateKeyKey: keyPEM,
			v1.TLSCertKey:       certPEM,
		},
		Type: v1.SecretTypeTLS,
	}

	plog.Info("Creating TLS certificates for impersonation proxy",
		"ips", ips,
		"hostnames", hostnames,
		"secret", c.tlsSecretName,
		"namespace", c.namespace)
	return c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, newTLSSecret, metav1.CreateOptions{})
}

func (c *impersonatorConfigController) loadTLSCertFromSecret(tlsSecret *v1.Secret) error {
	certPEM := tlsSecret.Data[v1.TLSCertKey]
	keyPEM := tlsSecret.Data[v1.TLSPrivateKeyKey]

	if err := c.tlsServingCertDynamicCertProvider.SetCertKeyContent(certPEM, keyPEM); err != nil {
		c.tlsServingCertDynamicCertProvider.UnsetCertKeyContent()
		return fmt.Errorf("could not parse TLS cert PEM data from Secret: %w", err)
	}

	plog.Info("Loading TLS certificates for impersonation proxy",
		"certPEM", string(certPEM),
		"secret", c.tlsSecretName,
		"namespace", c.namespace)

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
		"secret", c.tlsSecretName,
		"namespace", c.namespace)
	err = c.k8sClient.CoreV1().Secrets(c.namespace).Delete(ctx, c.tlsSecretName, metav1.DeleteOptions{})
	notFound := k8serrors.IsNotFound(err)
	if notFound {
		// its okay if we tried to delete and we got a not found error. This probably means
		// another instance of the concierge got here first so there's nothing to delete.
		return nil
	}
	if err != nil {
		return err
	}

	c.tlsServingCertDynamicCertProvider.UnsetCertKeyContent()

	return nil
}

func (c *impersonatorConfigController) loadSignerCA(status v1alpha1.StrategyStatus) error {
	// Clear it when the impersonator is not completely ready.
	if status != v1alpha1.SuccessStrategyStatus {
		c.clearSignerCA()
		return nil
	}

	signingCertSecret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.impersonationSignerSecretName)
	if err != nil {
		return fmt.Errorf("could not load the impersonator's credential signing secret: %w", err)
	}

	certPEM := signingCertSecret.Data[apicerts.CACertificateSecretKey]
	keyPEM := signingCertSecret.Data[apicerts.CACertificatePrivateKeySecretKey]

	if err := c.impersonationSigningCertProvider.SetCertKeyContent(certPEM, keyPEM); err != nil {
		return fmt.Errorf("could not load the impersonator's credential signing secret: %w", err)
	}

	plog.Info("Loading credential signing certificate for impersonation proxy",
		"certPEM", string(certPEM),
		"fromSecret", c.impersonationSignerSecretName,
		"namespace", c.namespace)

	return nil
}

func (c *impersonatorConfigController) clearSignerCA() {
	plog.Info("Clearing credential signing certificate for impersonation proxy")
	c.impersonationSigningCertProvider.UnsetCertKeyContent()
}

func (c *impersonatorConfigController) doSyncResult(nameInfo *certNameInfo, config *v1alpha1.ImpersonationProxySpec, ca *certauthority.CA) *v1alpha1.CredentialIssuerStrategy {
	switch {
	case c.disabledExplicitly(config):
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.DisabledStrategyReason,
			Message:        "impersonation proxy was explicitly disabled by configuration",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	case c.disabledByAutoMode(config):
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.DisabledStrategyReason,
			Message:        "automatically determined that impersonation proxy should be disabled",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	case !nameInfo.ready:
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.ErrorStrategyStatus,
			Reason:         v1alpha1.PendingStrategyReason,
			Message:        "waiting for load balancer Service to be assigned IP or hostname",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	default:
		return &v1alpha1.CredentialIssuerStrategy{
			Type:           v1alpha1.ImpersonationProxyStrategyType,
			Status:         v1alpha1.SuccessStrategyStatus,
			Reason:         v1alpha1.ListeningStrategyReason,
			Message:        "impersonation proxy is ready to accept client connections",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
			Frontend: &v1alpha1.CredentialIssuerFrontend{
				Type: v1alpha1.ImpersonationProxyFrontendType,
				ImpersonationProxyInfo: &v1alpha1.ImpersonationProxyInfo{
					Endpoint:                 "https://" + nameInfo.clientEndpoint,
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(ca.Bundle()),
				},
			},
		}
	}
}

func validateCredentialIssuerSpec(spec *v1alpha1.ImpersonationProxySpec) error {
	// Validate that the mode is one of our known values.
	switch spec.Mode {
	case v1alpha1.ImpersonationProxyModeDisabled:
	case v1alpha1.ImpersonationProxyModeAuto:
	case v1alpha1.ImpersonationProxyModeEnabled:
	default:
		return fmt.Errorf("invalid proxy mode %q (expected auto, disabled, or enabled)", spec.Mode)
	}

	// If disabled, ignore all other fields and consider the configuration valid.
	if spec.Mode == v1alpha1.ImpersonationProxyModeDisabled {
		return nil
	}

	// Validate that the service type is one of our known values.
	switch spec.Service.Type {
	case v1alpha1.ImpersonationProxyServiceTypeNone:
	case v1alpha1.ImpersonationProxyServiceTypeLoadBalancer:
	case v1alpha1.ImpersonationProxyServiceTypeClusterIP:
	default:
		return fmt.Errorf("invalid service type %q (expected None, LoadBalancer, or ClusterIP)", spec.Service.Type)
	}

	// If specified, validate that the LoadBalancerIP is a valid IPv4 or IPv6 address.
	if ip := spec.Service.LoadBalancerIP; ip != "" && len(validation.IsValidIP(ip)) > 0 {
		return fmt.Errorf("invalid LoadBalancerIP %q", spec.Service.LoadBalancerIP)
	}

	// If service is type "None", a non-empty external endpoint must be specified.
	if spec.ExternalEndpoint == "" && spec.Service.Type == v1alpha1.ImpersonationProxyServiceTypeNone {
		return fmt.Errorf("externalEndpoint must be set when service.type is None")
	}

	if err := validateExternalEndpoint(spec.ExternalEndpoint); err != nil {
		return fmt.Errorf("invalid ExternalEndpoint %q: %w", spec.ExternalEndpoint, err)
	}

	return nil
}

func validateExternalEndpoint(endpoint string) error {
	// Empty string is valid (no external endpoint, default to service name)
	if endpoint == "" {
		return nil
	}

	// Try parsing it both with and without an implicit port 443 at the end.
	host, port, err := net.SplitHostPort(endpoint)

	// If we got an error parsing the raw input, try adding an implicit port 443.
	if err != nil {
		host, port, err = net.SplitHostPort(net.JoinHostPort(endpoint, "443"))
	}

	// If there's still an error, fail now.
	if err != nil {
		return err
	}

	portInt, _ := strconv.Atoi(port)
	if len(validation.IsValidPortNum(portInt)) > 0 {
		return fmt.Errorf("invalid port %q", port)
	}

	// Check if the host part is a valid IP address.
	if len(validation.IsValidIP(host)) == 0 {
		return nil
	}

	// Check if the host part is a valid hostname according to RFC 1123.
	if len(validation.IsDNS1123Subdomain(host)) == 0 {
		return nil
	}

	return fmt.Errorf("host %q is not a valid hostname or IP address", host)
}
