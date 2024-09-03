// Copyright 2021-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package impersonatorconfig

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/intstr"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/config/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
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
	"go.pinniped.dev/internal/endpointaddr"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/tokenclient"
)

const (
	defaultHTTPSPort             = 443
	approximatelyOneHundredYears = 100 * 365 * 24 * time.Hour
	caCommonName                 = "Pinniped Impersonation Proxy Serving CA"
	caCrtKey                     = "ca.crt"
	caKeyKey                     = "ca.key"
	appLabelKey                  = "app"
	annotationKeysKey            = "credentialissuer.pinniped.dev/annotation-keys"
)

type impersonatorConfigController struct {
	namespace                        string
	credentialIssuerResourceName     string
	impersonationProxyPort           int
	generatedLoadBalancerServiceName string
	generatedClusterIPServiceName    string
	tlsSecretName                    string
	caSecretName                     string
	impersonationSignerSecretName    string

	k8sClient         kubernetes.Interface
	pinnipedAPIClient conciergeclientset.Interface

	credIssuerInformer conciergeconfiginformers.CredentialIssuerInformer
	servicesInformer   corev1informers.ServiceInformer
	secretsInformer    corev1informers.SecretInformer

	labels                           map[string]string
	clock                            clock.Clock
	impersonationSigningCertProvider dynamiccert.Provider
	impersonatorFunc                 impersonator.FactoryFunc

	hasControlPlaneNodes              *bool
	serverCancelFunc                  context.CancelFunc
	errorCh                           chan error
	tlsServingCertDynamicCertProvider dynamiccert.Private
	log                               plog.Logger

	impersonationProxyTokenCache tokenclient.ExpiringSingletonTokenCacheGet
}

func NewImpersonatorConfigController(
	namespace string,
	credentialIssuerResourceName string,
	k8sClient kubernetes.Interface,
	pinnipedAPIClient conciergeclientset.Interface,
	credentialIssuerInformer conciergeconfiginformers.CredentialIssuerInformer,
	servicesInformer corev1informers.ServiceInformer,
	secretsInformer corev1informers.SecretInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	impersonationProxyPort int,
	generatedLoadBalancerServiceName string,
	generatedClusterIPServiceName string,
	tlsSecretName string,
	caSecretName string,
	labels map[string]string,
	clock clock.Clock,
	impersonatorFunc impersonator.FactoryFunc,
	impersonationSignerSecretName string,
	impersonationSigningCertProvider dynamiccert.Provider,
	log plog.Logger,
	impersonationProxyTokenCache tokenclient.ExpiringSingletonTokenCacheGet,
) controllerlib.Controller {
	secretNames := sets.NewString(tlsSecretName, caSecretName, impersonationSignerSecretName)
	log = log.WithName("impersonator-config-controller")
	return controllerlib.New(
		controllerlib.Config{
			Name: "impersonator-config-controller",
			Syncer: &impersonatorConfigController{
				namespace:                         namespace,
				credentialIssuerResourceName:      credentialIssuerResourceName,
				impersonationProxyPort:            impersonationProxyPort,
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
				log:                               log,
				impersonationProxyTokenCache:      impersonationProxyTokenCache,
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
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				if obj.GetNamespace() != namespace {
					return false
				}
				switch obj.GetName() {
				case generatedLoadBalancerServiceName, generatedClusterIPServiceName:
					return true
				default:
					return false
				}
			}),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretsInformer,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				secret, ok := obj.(*corev1.Secret)
				if !ok {
					return false
				}

				if secret.GetNamespace() != namespace {
					return false
				}

				return secretNames.Has(secret.GetName()) || secret.Type == corev1.SecretTypeTLS
			}),
			controllerlib.InformerOption{},
		),
	)
}

func (c *impersonatorConfigController) Sync(syncCtx controllerlib.Context) error {
	c.log.Debug("starting impersonatorConfigController Sync")

	// Load the CredentialIssuer that we'll update with status.
	credIssuer, err := c.credIssuerInformer.Lister().Get(c.credentialIssuerResourceName)
	if err != nil {
		return fmt.Errorf("could not get CredentialIssuer to update: %w", err)
	}

	strategy, err := c.doSync(syncCtx, credIssuer)
	if err != nil {
		strategy = &conciergeconfigv1alpha1.CredentialIssuerStrategy{
			Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
			Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
			Reason:         strategyReasonForError(err),
			Message:        err.Error(),
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	}

	err = utilerrors.NewAggregate([]error{err, issuerconfig.Update(
		syncCtx.Context,
		c.pinnipedAPIClient,
		credIssuer,
		*strategy,
	)})

	if err == nil {
		c.log.Debug("successfully finished impersonatorConfigController Sync")
	}
	return err
}

// strategyReasonForError returns the proper v1alpha1.StrategyReason for a sync error. Some errors are occasionally
// expected because there are multiple pods running, in these cases we should  report a Pending reason and we'll
// recover on a following sync.
func strategyReasonForError(err error) conciergeconfigv1alpha1.StrategyReason {
	switch {
	case apierrors.IsConflict(err), apierrors.IsAlreadyExists(err):
		return conciergeconfigv1alpha1.PendingStrategyReason
	default:
		return conciergeconfigv1alpha1.ErrorDuringSetupStrategyReason
	}
}

type certNameInfo struct {
	// ready will be true when the certificate name information is known.
	// ready will be false when it is pending because we are waiting for a load balancer to get assigned an ip/hostname.
	// When false, the other fields in this struct should not be considered meaningful and may be zero values.
	ready bool

	// The IP address or hostname which was selected to be used as the name in the cert.
	// Either selectedIP or selectedHostname will be set, but not both.
	selectedIPs      []net.IP
	selectedHostname string

	// The name of the endpoint to which a client should connect to talk to the impersonator.
	// This may be a hostname or an IP, and may include a port number.
	clientEndpoint string
}

func (c *impersonatorConfigController) doSync(syncCtx controllerlib.Context, credIssuer *conciergeconfigv1alpha1.CredentialIssuer) (*conciergeconfigv1alpha1.CredentialIssuerStrategy, error) {
	ctx := syncCtx.Context

	impersonationSpec, err := c.loadImpersonationProxyConfiguration(credIssuer)
	if err != nil {
		return nil, err
	}

	// Make a live API call to avoid the cost of having an informer watch all node changes on the cluster,
	// since there could be lots, and we don't especially care about node changes.
	// Once we have concluded that there is or is not a visible control plane, then cache that decision
	// to avoid listing nodes very often.
	if c.hasControlPlaneNodes == nil {
		hasControlPlaneNodes, err := clusterhost.New(c.k8sClient).HasControlPlaneNodes(ctx)
		if err != nil {
			return nil, err
		}
		c.hasControlPlaneNodes = &hasControlPlaneNodes
		c.log.Debug("queried for control plane nodes", "foundControlPlaneNodes", hasControlPlaneNodes)
	}

	if c.shouldHaveImpersonator(impersonationSpec) {
		if err = c.ensureImpersonatorIsStarted(syncCtx); err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureImpersonatorIsStopped(true); err != nil {
			return nil, err
		}
	}

	if c.shouldHaveLoadBalancer(impersonationSpec) {
		if err = c.ensureLoadBalancerIsStarted(ctx, impersonationSpec); err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureLoadBalancerIsStopped(ctx); err != nil {
			return nil, err
		}
	}

	if c.shouldHaveClusterIPService(impersonationSpec) {
		if err = c.ensureClusterIPServiceIsStarted(ctx, impersonationSpec); err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureClusterIPServiceIsStopped(ctx); err != nil {
			return nil, err
		}
	}

	nameInfo, err := c.findDesiredTLSCertificateName(impersonationSpec)
	if err != nil {
		return nil, err
	}

	var impersonationCABundle []byte
	if c.shouldHaveImpersonator(impersonationSpec) { //nolint:nestif // This is complex but readable
		if impersonationSpec.TLS != nil {
			impersonationCABundle, err = c.evaluateExternallyProvidedTLSSecret(ctx, impersonationSpec.TLS)
		} else {
			impersonationCABundle, err = c.ensureCAAndTLSSecrets(ctx, nameInfo)
		}

		if err != nil {
			return nil, err
		}
	} else {
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return nil, err
		}
		c.clearTLSSecret()
	}

	credentialIssuerStrategyResult := c.doSyncResult(nameInfo, impersonationSpec, impersonationCABundle)

	if c.shouldHaveImpersonator(impersonationSpec) {
		if err = c.loadSignerCA(); err != nil {
			return nil, err
		}
	} else {
		c.clearSignerCA()
	}

	return credentialIssuerStrategyResult, nil
}

func (c *impersonatorConfigController) ensureCAAndTLSSecrets(
	ctx context.Context,
	nameInfo *certNameInfo,
) ([]byte, error) {
	var (
		impersonationCA *certauthority.CA
		err             error
	)
	if impersonationCA, err = c.ensureCASecretIsCreated(ctx); err != nil {
		return nil, err
	}
	if err = c.ensureTLSSecret(ctx, nameInfo, impersonationCA); err != nil {
		return nil, err
	}

	if impersonationCA != nil {
		return impersonationCA.Bundle(), nil
	}

	return nil, nil
}

func (c *impersonatorConfigController) evaluateExternallyProvidedTLSSecret(
	ctx context.Context,
	tlsSpec *conciergeconfigv1alpha1.ImpersonationProxyTLSSpec,
) ([]byte, error) {
	if tlsSpec.SecretName == "" {
		return nil, fmt.Errorf("must provide impersonationSpec.TLS.secretName if impersonationSpec.TLS is provided")
	}

	c.log.Info("configuring the impersonation proxy to use an externally provided TLS secret",
		"secretName", tlsSpec.SecretName)

	// Ensure that any TLS secret generated by this controller is removed
	err := c.ensureTLSSecretIsRemoved(ctx)
	if err != nil {
		return nil, fmt.Errorf("unable to remove generated TLS secret with name %s: %w", c.tlsSecretName, err)
	}

	// The CA Bundle may come from either the TLS secret or the CertificateAuthorityData.
	// Check CertificateAuthorityData last so that it will take priority.

	var caBundle []byte
	caBundle, err = c.readExternalTLSSecret(tlsSpec.SecretName)
	if err != nil {
		return nil, fmt.Errorf("could not load the externally provided TLS secret for the impersonation proxy: %w", err)
	}

	if tlsSpec.CertificateAuthorityData != "" {
		caBundle, err = base64.StdEncoding.DecodeString(tlsSpec.CertificateAuthorityData)
		if err != nil {
			return nil, fmt.Errorf("could not decode impersonationSpec.TLS.certificateAuthorityData: %w", err)
		}

		block, _ := pem.Decode(caBundle)
		if block == nil {
			return nil, fmt.Errorf("could not decode impersonationSpec.TLS.certificateAuthorityData: data is not a certificate")
		}

		c.log.Info("the impersonation proxy will advertise its CA Bundle from impersonationSpec.TLS.CertificateAuthorityData",
			"CertificateAuthorityData", caBundle)
	}

	return caBundle, nil
}

func (c *impersonatorConfigController) loadImpersonationProxyConfiguration(credIssuer *conciergeconfigv1alpha1.CredentialIssuer) (*conciergeconfigv1alpha1.ImpersonationProxySpec, error) {
	// Make a copy of the spec since we got this object from informer cache.
	spec := credIssuer.Spec.DeepCopy().ImpersonationProxy
	if spec == nil {
		return nil, fmt.Errorf("could not load CredentialIssuer: spec.impersonationProxy is nil")
	}

	// Default service type to LoadBalancer (this is normally already done via CRD defaulting).
	if spec.Service.Type == "" {
		spec.Service.Type = conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer
	}

	if err := validateCredentialIssuerSpec(spec); err != nil {
		return nil, fmt.Errorf("could not load CredentialIssuer spec.impersonationProxy: %w", err)
	}
	c.log.Debug("read impersonation proxy config", "credentialIssuer", c.credentialIssuerResourceName)
	return spec, nil
}

func (c *impersonatorConfigController) shouldHaveImpersonator(config *conciergeconfigv1alpha1.ImpersonationProxySpec) bool {
	return c.enabledByAutoMode(config) || config.Mode == conciergeconfigv1alpha1.ImpersonationProxyModeEnabled
}

func (c *impersonatorConfigController) enabledByAutoMode(config *conciergeconfigv1alpha1.ImpersonationProxySpec) bool {
	return config.Mode == conciergeconfigv1alpha1.ImpersonationProxyModeAuto && !*c.hasControlPlaneNodes
}

func (c *impersonatorConfigController) disabledByAutoMode(config *conciergeconfigv1alpha1.ImpersonationProxySpec) bool {
	return config.Mode == conciergeconfigv1alpha1.ImpersonationProxyModeAuto && *c.hasControlPlaneNodes
}

func (c *impersonatorConfigController) disabledExplicitly(config *conciergeconfigv1alpha1.ImpersonationProxySpec) bool {
	return config.Mode == conciergeconfigv1alpha1.ImpersonationProxyModeDisabled
}

func (c *impersonatorConfigController) shouldHaveLoadBalancer(config *conciergeconfigv1alpha1.ImpersonationProxySpec) bool {
	return c.shouldHaveImpersonator(config) && config.Service.Type == conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer
}

func (c *impersonatorConfigController) shouldHaveClusterIPService(config *conciergeconfigv1alpha1.ImpersonationProxySpec) bool {
	return c.shouldHaveImpersonator(config) && config.Service.Type == conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP
}

func (c *impersonatorConfigController) serviceExists(serviceName string) (bool, *corev1.Service, error) {
	service, err := c.servicesInformer.Lister().Services(c.namespace).Get(serviceName)
	notFound := apierrors.IsNotFound(err)
	if notFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, service, nil
}

func (c *impersonatorConfigController) tlsSecretExists() (bool, *corev1.Secret, error) {
	secret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.tlsSecretName)
	notFound := apierrors.IsNotFound(err)
	if notFound {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, secret, nil
}

func (c *impersonatorConfigController) ensureImpersonatorIsStarted(syncCtx controllerlib.Context) error {
	if c.serverCancelFunc != nil {
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
			return utilerrors.NewAggregate([]error{runningErr, stoppingErr})
		default:
			// Seems like it is still running, so nothing to do.
			return nil
		}
	}

	c.log.Info("starting impersonation proxy", "port", c.impersonationProxyPort)
	startImpersonatorFunc, err := c.impersonatorFunc(
		c.impersonationProxyPort,
		c.tlsServingCertDynamicCertProvider,
		c.impersonationSigningCertProvider,
		c.impersonationProxyTokenCache,
	)
	if err != nil {
		return err
	}

	var serverCtx context.Context
	serverCtx, c.serverCancelFunc = context.WithCancel(context.Background())
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
		c.errorCh <- startImpersonatorFunc(serverCtx)
	}()

	return nil
}

func (c *impersonatorConfigController) ensureImpersonatorIsStopped(shouldCloseErrChan bool) error {
	if c.serverCancelFunc == nil {
		return nil
	}

	c.log.Info("stopping impersonation proxy", "port", c.impersonationProxyPort)
	c.serverCancelFunc()
	stopErr := <-c.errorCh

	if shouldCloseErrChan {
		close(c.errorCh)
	}

	c.serverCancelFunc = nil
	c.errorCh = nil

	return stopErr
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStarted(ctx context.Context, config *conciergeconfigv1alpha1.ImpersonationProxySpec) error {
	appNameLabel := c.labels[appLabelKey]
	loadBalancer := corev1.Service{
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeLoadBalancer,
			Ports: []corev1.ServicePort{
				{
					TargetPort: intstr.FromInt(c.impersonationProxyPort),
					Port:       defaultHTTPSPort,
					Protocol:   corev1.ProtocolTCP,
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
	return c.createOrUpdateService(ctx, &loadBalancer)
}

func (c *impersonatorConfigController) ensureLoadBalancerIsStopped(ctx context.Context) error {
	running, service, err := c.serviceExists(c.generatedLoadBalancerServiceName)
	if err != nil {
		return err
	}
	if !running {
		return nil
	}

	c.log.Info("deleting load balancer for impersonation proxy",
		"service", klog.KRef(c.namespace, c.generatedLoadBalancerServiceName),
	)
	err = c.k8sClient.CoreV1().Services(c.namespace).Delete(ctx, c.generatedLoadBalancerServiceName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &service.UID,
			ResourceVersion: &service.ResourceVersion,
		},
	})
	return utilerrors.FilterOut(err, apierrors.IsNotFound)
}

func (c *impersonatorConfigController) ensureClusterIPServiceIsStarted(ctx context.Context, config *conciergeconfigv1alpha1.ImpersonationProxySpec) error {
	appNameLabel := c.labels[appLabelKey]
	clusterIP := corev1.Service{
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceTypeClusterIP,
			Ports: []corev1.ServicePort{
				{
					TargetPort: intstr.FromInt(c.impersonationProxyPort),
					Port:       defaultHTTPSPort,
					Protocol:   corev1.ProtocolTCP,
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
	return c.createOrUpdateService(ctx, &clusterIP)
}

func (c *impersonatorConfigController) ensureClusterIPServiceIsStopped(ctx context.Context) error {
	running, service, err := c.serviceExists(c.generatedClusterIPServiceName)
	if err != nil {
		return err
	}
	if !running {
		return nil
	}

	c.log.Info("deleting cluster ip for impersonation proxy",
		"service", klog.KRef(c.namespace, c.generatedClusterIPServiceName),
	)
	err = c.k8sClient.CoreV1().Services(c.namespace).Delete(ctx, c.generatedClusterIPServiceName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &service.UID,
			ResourceVersion: &service.ResourceVersion,
		},
	})
	return utilerrors.FilterOut(err, apierrors.IsNotFound)
}

func (c *impersonatorConfigController) createOrUpdateService(ctx context.Context, desiredService *corev1.Service) error {
	log := c.log.WithValues("serviceType", desiredService.Spec.Type, "service", klog.KObj(desiredService))

	// Prepare to remember which annotation keys were added from the CredentialIssuer spec, both for
	// creates and for updates, in case someone removes a key from the spec in the future. We would like
	// to be able to detect that the missing key means that we should remove the key. This is needed to
	// differentiate it from a key that was added by another actor, which we should not remove.
	// But don't bother recording the requested annotations if there were no annotations requested.
	desiredAnnotationKeys := make([]string, 0, len(desiredService.Annotations))
	for k := range desiredService.Annotations {
		desiredAnnotationKeys = append(desiredAnnotationKeys, k)
	}
	if len(desiredAnnotationKeys) > 0 {
		// Sort them since they come out of the map in no particular order.
		sort.Strings(desiredAnnotationKeys)
		keysJSONArray, err := json.Marshal(desiredAnnotationKeys)
		if err != nil {
			return err // This shouldn't really happen. We should always be able to marshal an array of strings.
		}
		// Save the desired annotations to a bookkeeping annotation.
		desiredService.Annotations[annotationKeysKey] = string(keysJSONArray)
	}

	// Get the Service from the informer, and create it if it does not already exist.
	existingService, err := c.servicesInformer.Lister().Services(c.namespace).Get(desiredService.Name)
	if apierrors.IsNotFound(err) {
		log.Info("creating service for impersonation proxy")
		_, err := c.k8sClient.CoreV1().Services(c.namespace).Create(ctx, desiredService, metav1.CreateOptions{})
		return err
	}
	if err != nil {
		return err
	}

	// The Service already exists, so update only the specific fields that are meaningfully part of our desired state.
	updatedService := existingService.DeepCopy()
	updatedService.ObjectMeta.Labels = desiredService.ObjectMeta.Labels
	updatedService.Spec.LoadBalancerIP = desiredService.Spec.LoadBalancerIP
	updatedService.Spec.Type = desiredService.Spec.Type
	updatedService.Spec.Selector = desiredService.Spec.Selector

	// Do not simply overwrite the existing annotations with the desired annotations. Instead, merge-overwrite.
	// Another actor in the system, like a human user or a non-Pinniped controller, might have updated the
	// existing Service's annotations. If they did, then we do not want to overwrite those keys expect for
	// the specific keys that are from the CredentialIssuer's spec, because if we overwrite keys belonging
	// to another controller then we could end up infinitely flapping back and forth with the other controller,
	// both updating that annotation on the Service.
	if updatedService.Annotations == nil {
		updatedService.Annotations = map[string]string{}
	}
	for k, v := range desiredService.Annotations {
		updatedService.Annotations[k] = v
	}

	// Check if the the existing Service contains a record of previous annotations that were added by this controller.
	// Note that in an upgrade, older versions of Pinniped might have created the Service without this bookkeeping annotation.
	oldDesiredAnnotationKeysJSON, foundOldDesiredAnnotationKeysJSON := existingService.Annotations[annotationKeysKey]
	oldDesiredAnnotationKeys := []string{}
	if foundOldDesiredAnnotationKeysJSON {
		_ = json.Unmarshal([]byte(oldDesiredAnnotationKeysJSON), &oldDesiredAnnotationKeys)
		// In the unlikely event that we cannot parse the value of our bookkeeping annotation, just act like it
		// wasn't present and update it to the new value that it should have based on the current desired state.
	}

	// Check if any annotations which were previously in the CredentialIssuer spec are now gone from the spec,
	// which means that those now-missing annotations should get deleted.
	for _, oldKey := range oldDesiredAnnotationKeys {
		if _, existsInDesired := desiredService.Annotations[oldKey]; !existsInDesired {
			delete(updatedService.Annotations, oldKey)
		}
	}

	// If no annotations were requested, then remove the special bookkeeping annotation which might be
	// leftover from a previous update. During the next update, non-existence will be taken to mean
	// that no annotations were previously requested by the CredentialIssuer spec.
	if len(desiredAnnotationKeys) == 0 {
		delete(updatedService.Annotations, annotationKeysKey)
	}

	// If our updates didn't change anything, we're done.
	if equality.Semantic.DeepEqual(existingService, updatedService) {
		return nil
	}

	// Otherwise apply the updates.
	c.log.Info("updating service for impersonation proxy")
	_, err = c.k8sClient.CoreV1().Services(c.namespace).Update(ctx, updatedService, metav1.UpdateOptions{})
	return err
}

func (c *impersonatorConfigController) readExternalTLSSecret(externalTLSSecretName string) (impersonationCABundle []byte, err error) {
	secretFromInformer, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(externalTLSSecretName)
	if err != nil {
		c.log.Info("could not find externally provided TLS secret for the impersonation proxy",
			"secretName", externalTLSSecretName)
		return nil, err
	}

	c.log.Info("found externally provided TLS secret for the impersonation proxy",
		"secretName", externalTLSSecretName)

	err = c.loadTLSCertFromSecret(secretFromInformer)
	if err != nil {
		plog.Error("error loading cert from externally provided TLS secret for the impersonation proxy", err)
		return nil, err
	}

	if caCertPEM, ok := secretFromInformer.Data[caCrtKey]; ok && len(caCertPEM) > 0 {
		plog.Info(fmt.Sprintf("found a %s field in the externally provided TLS secret for the impersonation proxy", caCrtKey),
			"secretName", externalTLSSecretName,
			"caCertPEM", caCertPEM)

		block, _ := pem.Decode(caCertPEM)
		if block == nil {
			plog.Warning("error loading cert from externally provided TLS secret for the impersonation proxy: data is not a certificate")
			return nil, fmt.Errorf("unable to read provided ca.crt: data is not a certificate")
		}

		return caCertPEM, nil
	}

	return nil, nil
}

func (c *impersonatorConfigController) ensureTLSSecret(ctx context.Context, nameInfo *certNameInfo, ca *certauthority.CA) error {
	secretFromInformer, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.tlsSecretName)
	notFound := apierrors.IsNotFound(err)
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

func (c *impersonatorConfigController) deleteTLSSecretWhenCertificateDoesNotMatchDesiredState(ctx context.Context, nameInfo *certNameInfo, ca *certauthority.CA, secret *corev1.Secret) (bool, error) {
	certPEM := secret.Data[corev1.TLSCertKey]
	block, _ := pem.Decode(certPEM)
	if block == nil {
		c.log.Info("found missing or not PEM-encoded data in TLS Secret",
			"invalidCertPEM", string(certPEM),
			"secret", klog.KObj(secret),
		)
		deleteErr := c.ensureTLSSecretIsRemoved(ctx)
		if deleteErr != nil {
			return false, fmt.Errorf("found missing or not PEM-encoded data in TLS Secret, but got error while deleting it: %w", deleteErr)
		}
		return true, nil
	}

	actualCertFromSecret, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.log.Error("found missing or not PEM-encoded data in TLS Secret",
			err,
			"invalidCertPEM", string(certPEM),
			"secret", klog.KObj(secret),
		)
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, fmt.Errorf("PEM data represented an invalid cert, but got error while deleting it: %w", err)
		}
		return true, nil
	}

	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	_, err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		c.log.Error("found invalid private key PEM data in TLS Secret",
			err,
			"invalidCertPEM", string(certPEM),
			"secret", klog.KObj(secret),
		)
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
		// We currently have a secret, but we are waiting for a load balancer to be assigned an ingress, so
		// our current secret must be old/unwanted.
		if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
			return false, err
		}
		return true, nil
	}

	actualIPs := actualCertFromSecret.IPAddresses
	actualHostnames := actualCertFromSecret.DNSNames
	c.log.Info("checking TLS certificate names",
		"desiredIPs", nameInfo.selectedIPs,
		"desiredHostname", nameInfo.selectedHostname,
		"actualIPs", actualIPs,
		"actualHostnames", actualHostnames,
		"secret", klog.KObj(secret),
	)

	if certHostnameAndIPMatchDesiredState(nameInfo.selectedIPs, actualIPs, nameInfo.selectedHostname, actualHostnames) {
		// The cert already matches the desired state, so there is no need to delete/recreate it.
		return false, nil
	}

	if err = c.ensureTLSSecretIsRemoved(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func certHostnameAndIPMatchDesiredState(desiredIPs []net.IP, actualIPs []net.IP, desiredHostname string, actualHostnames []string) bool {
	if len(desiredIPs) > 0 && len(actualIPs) > 0 && len(actualIPs) == len(desiredIPs) && len(actualHostnames) == 0 {
		for i := range desiredIPs {
			if !actualIPs[i].Equal(desiredIPs[i]) {
				return false
			}
		}
		return true
	}
	if desiredHostname != "" && len(actualHostnames) == 1 && desiredHostname == actualHostnames[0] && len(actualIPs) == 0 {
		return true
	}
	return false
}

func (c *impersonatorConfigController) ensureTLSSecretIsCreatedAndLoaded(ctx context.Context, nameInfo *certNameInfo, secret *corev1.Secret, ca *certauthority.CA) error {
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

	newTLSSecret, err := c.createNewTLSSecret(ctx, ca, nameInfo.selectedIPs, nameInfo.selectedHostname)
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
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, err
	}

	var impersonationCA *certauthority.CA
	if apierrors.IsNotFound(err) {
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

	secret := corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.caSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			caCrtKey: impersonationCA.Bundle(),
			caKeyKey: caPrivateKeyPEM,
		},
		Type: corev1.SecretTypeOpaque,
	}

	c.log.Info("creating CA certificates for impersonation proxy",
		"secret", klog.KObj(&secret),
	)
	if _, err = c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, &secret, metav1.CreateOptions{}); err != nil {
		return nil, err
	}

	return impersonationCA, nil
}

func (c *impersonatorConfigController) findDesiredTLSCertificateName(config *conciergeconfigv1alpha1.ImpersonationProxySpec) (*certNameInfo, error) {
	if config.ExternalEndpoint != "" {
		return c.findTLSCertificateNameFromEndpointConfig(config), nil
	} else if config.Service.Type == conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP {
		return c.findTLSCertificateNameFromClusterIPService()
	}
	return c.findTLSCertificateNameFromLoadBalancer()
}

func (c *impersonatorConfigController) findTLSCertificateNameFromEndpointConfig(config *conciergeconfigv1alpha1.ImpersonationProxySpec) *certNameInfo {
	addr, _ := endpointaddr.Parse(config.ExternalEndpoint, 443)
	endpoint := strings.TrimSuffix(addr.Endpoint(), ":443")

	if ip := net.ParseIP(addr.Host); ip != nil {
		return &certNameInfo{ready: true, selectedIPs: []net.IP{ip}, clientEndpoint: endpoint}
	}
	return &certNameInfo{ready: true, selectedHostname: addr.Host, clientEndpoint: endpoint}
}

func (c *impersonatorConfigController) findTLSCertificateNameFromLoadBalancer() (*certNameInfo, error) {
	lb, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedLoadBalancerServiceName)
	notFound := apierrors.IsNotFound(err)
	if notFound {
		// We aren't ready and will try again later in this case.
		return &certNameInfo{ready: false}, nil
	}
	if err != nil {
		return nil, err
	}
	ingresses := lb.Status.LoadBalancer.Ingress
	if len(ingresses) == 0 || (ingresses[0].Hostname == "" && ingresses[0].IP == "") {
		c.log.Info("load balancer for impersonation proxy does not have an ingress yet, so skipping tls cert generation while we wait",
			"service", klog.KObj(lb),
		)
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
			return &certNameInfo{ready: true, selectedIPs: []net.IP{parsedIP}, clientEndpoint: ip}, nil
		}
	}

	return nil, fmt.Errorf("could not find valid IP addresses or hostnames from load balancer %s/%s", c.namespace, lb.Name)
}

func (c *impersonatorConfigController) findTLSCertificateNameFromClusterIPService() (*certNameInfo, error) {
	clusterIP, err := c.servicesInformer.Lister().Services(c.namespace).Get(c.generatedClusterIPServiceName)
	notFound := apierrors.IsNotFound(err)
	if notFound {
		// We aren't ready and will try again later in this case.
		return &certNameInfo{ready: false}, nil
	}
	if err != nil {
		return nil, err
	}
	ip := clusterIP.Spec.ClusterIP
	ips := clusterIP.Spec.ClusterIPs
	if ip != "" {
		// clusterIP will always exist when clusterIPs does, but not vice versa
		var parsedIPs []net.IP
		if len(ips) > 0 {
			for _, ipFromIPs := range ips {
				parsedIPs = append(parsedIPs, net.ParseIP(ipFromIPs))
			}
		} else {
			parsedIPs = []net.IP{net.ParseIP(ip)}
		}
		return &certNameInfo{ready: true, selectedIPs: parsedIPs, clientEndpoint: ip}, nil
	}
	return &certNameInfo{ready: false}, nil
}

func (c *impersonatorConfigController) createNewTLSSecret(ctx context.Context, ca *certauthority.CA, ips []net.IP, hostname string) (*corev1.Secret, error) {
	var hostnames []string
	if hostname != "" {
		hostnames = []string{hostname}
	}

	impersonationCert, err := ca.IssueServerCert(hostnames, ips, approximatelyOneHundredYears)
	if err != nil {
		return nil, fmt.Errorf("could not create impersonation cert: %w", err)
	}

	certPEM, keyPEM, err := certauthority.ToPEM(impersonationCert)
	if err != nil {
		return nil, err
	}

	newTLSSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      c.tlsSecretName,
			Namespace: c.namespace,
			Labels:    c.labels,
		},
		Data: map[string][]byte{
			corev1.TLSPrivateKeyKey: keyPEM,
			corev1.TLSCertKey:       certPEM,
		},
		Type: corev1.SecretTypeTLS,
	}

	c.log.Info("creating TLS certificates for impersonation proxy",
		"ips", ips,
		"hostnames", hostnames,
		"secret", klog.KObj(newTLSSecret),
	)
	return c.k8sClient.CoreV1().Secrets(c.namespace).Create(ctx, newTLSSecret, metav1.CreateOptions{})
}

func (c *impersonatorConfigController) loadTLSCertFromSecret(tlsSecret *corev1.Secret) error {
	certPEM := tlsSecret.Data[corev1.TLSCertKey]
	keyPEM := tlsSecret.Data[corev1.TLSPrivateKeyKey]

	if err := c.tlsServingCertDynamicCertProvider.SetCertKeyContent(certPEM, keyPEM); err != nil {
		return fmt.Errorf("could not parse TLS cert PEM data from Secret: %w", err)
	}

	c.log.Info("loading TLS certificates for impersonation proxy",
		"certPEM", string(certPEM),
		"secret", klog.KObj(tlsSecret),
	)

	return nil
}

func (c *impersonatorConfigController) ensureTLSSecretIsRemoved(ctx context.Context) error {
	tlsSecretExists, secret, err := c.tlsSecretExists()
	if err != nil {
		return err
	}
	if !tlsSecretExists {
		return nil
	}
	c.log.Info("deleting TLS serving certificate for impersonation proxy",
		"secret", klog.KRef(c.namespace, c.tlsSecretName),
	)
	err = c.k8sClient.CoreV1().Secrets(c.namespace).Delete(ctx, c.tlsSecretName, metav1.DeleteOptions{
		Preconditions: &metav1.Preconditions{
			UID:             &secret.UID,
			ResourceVersion: &secret.ResourceVersion,
		},
	})
	// it is okay if we tried to delete and we got a not found error. This probably means
	// another instance of the concierge got here first so there's nothing to delete.
	return utilerrors.FilterOut(err, apierrors.IsNotFound)
}

func (c *impersonatorConfigController) clearTLSSecret() {
	c.log.Debug("clearing TLS serving certificate for impersonation proxy")
	c.tlsServingCertDynamicCertProvider.UnsetCertKeyContent()
}

func (c *impersonatorConfigController) loadSignerCA() error {
	signingCertSecret, err := c.secretsInformer.Lister().Secrets(c.namespace).Get(c.impersonationSignerSecretName)
	if err != nil {
		return fmt.Errorf("could not load the impersonator's credential signing secret: %w", err)
	}

	certPEM := signingCertSecret.Data[apicerts.CACertificateSecretKey]
	keyPEM := signingCertSecret.Data[apicerts.CACertificatePrivateKeySecretKey]

	if err := c.impersonationSigningCertProvider.SetCertKeyContent(certPEM, keyPEM); err != nil {
		return fmt.Errorf("could not set the impersonator's credential signing secret: %w", err)
	}

	c.log.Info("loading credential signing certificate for impersonation proxy",
		"certPEM", string(certPEM),
		"secret", klog.KObj(signingCertSecret),
	)

	return nil
}

func (c *impersonatorConfigController) clearSignerCA() {
	c.log.Debug("clearing credential signing certificate for impersonation proxy")
	c.impersonationSigningCertProvider.UnsetCertKeyContent()
}

func (c *impersonatorConfigController) doSyncResult(nameInfo *certNameInfo, config *conciergeconfigv1alpha1.ImpersonationProxySpec, caBundle []byte) *conciergeconfigv1alpha1.CredentialIssuerStrategy {
	switch {
	case c.disabledExplicitly(config):
		return &conciergeconfigv1alpha1.CredentialIssuerStrategy{
			Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
			Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
			Reason:         conciergeconfigv1alpha1.DisabledStrategyReason,
			Message:        "impersonation proxy was explicitly disabled by configuration",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	case c.disabledByAutoMode(config):
		return &conciergeconfigv1alpha1.CredentialIssuerStrategy{
			Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
			Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
			Reason:         conciergeconfigv1alpha1.DisabledStrategyReason,
			Message:        "automatically determined that impersonation proxy should be disabled",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	case !nameInfo.ready:
		return &conciergeconfigv1alpha1.CredentialIssuerStrategy{
			Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
			Status:         conciergeconfigv1alpha1.ErrorStrategyStatus,
			Reason:         conciergeconfigv1alpha1.PendingStrategyReason,
			Message:        "waiting for load balancer Service to be assigned IP or hostname",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
		}
	default:
		return &conciergeconfigv1alpha1.CredentialIssuerStrategy{
			Type:           conciergeconfigv1alpha1.ImpersonationProxyStrategyType,
			Status:         conciergeconfigv1alpha1.SuccessStrategyStatus,
			Reason:         conciergeconfigv1alpha1.ListeningStrategyReason,
			Message:        "impersonation proxy is ready to accept client connections",
			LastUpdateTime: metav1.NewTime(c.clock.Now()),
			Frontend: &conciergeconfigv1alpha1.CredentialIssuerFrontend{
				Type: conciergeconfigv1alpha1.ImpersonationProxyFrontendType,
				ImpersonationProxyInfo: &conciergeconfigv1alpha1.ImpersonationProxyInfo{
					Endpoint:                 "https://" + nameInfo.clientEndpoint,
					CertificateAuthorityData: base64.StdEncoding.EncodeToString(caBundle),
				},
			},
		}
	}
}

func validateCredentialIssuerSpec(spec *conciergeconfigv1alpha1.ImpersonationProxySpec) error {
	// Validate that the mode is one of our known values.
	switch spec.Mode {
	case conciergeconfigv1alpha1.ImpersonationProxyModeDisabled:
	case conciergeconfigv1alpha1.ImpersonationProxyModeAuto:
	case conciergeconfigv1alpha1.ImpersonationProxyModeEnabled:
	default:
		return fmt.Errorf("invalid proxy mode %q (expected auto, disabled, or enabled)", spec.Mode)
	}

	// If disabled, ignore all other fields and consider the configuration valid.
	if spec.Mode == conciergeconfigv1alpha1.ImpersonationProxyModeDisabled {
		return nil
	}

	// Validate that the service type is one of our known values.
	switch spec.Service.Type {
	case conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone:
	case conciergeconfigv1alpha1.ImpersonationProxyServiceTypeLoadBalancer:
	case conciergeconfigv1alpha1.ImpersonationProxyServiceTypeClusterIP:
	default:
		return fmt.Errorf("invalid service type %q (expected None, LoadBalancer, or ClusterIP)", spec.Service.Type)
	}

	// If specified, validate that the LoadBalancerIP is a valid IPv4 or IPv6 address.
	if ip := spec.Service.LoadBalancerIP; ip != "" && len(validation.IsValidIP(field.NewPath("spec", "service", "loadBalancerIP"), ip)) > 0 {
		return fmt.Errorf("invalid LoadBalancerIP %q", spec.Service.LoadBalancerIP)
	}

	// If service is type "None", a non-empty external endpoint must be specified.
	if spec.ExternalEndpoint == "" && spec.Service.Type == conciergeconfigv1alpha1.ImpersonationProxyServiceTypeNone {
		return fmt.Errorf("externalEndpoint must be set when service.type is None")
	}

	if spec.ExternalEndpoint != "" {
		if _, err := endpointaddr.Parse(spec.ExternalEndpoint, 443); err != nil {
			return fmt.Errorf("invalid ExternalEndpoint %q: %w", spec.ExternalEndpoint, err)
		}
	}

	return nil
}
