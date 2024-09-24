// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package webhookcachefiller implements a controller for filling an authncache.Cache with each added/updated WebhookAuthenticator.
package webhookcachefiller

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"time"

	k8sauthv1beta1 "k8s.io/api/authentication/v1beta1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	k8snetutil "k8s.io/apimachinery/pkg/util/net"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/webhook"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	authinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/endpointaddr"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

const (
	controllerName = "webhookcachefiller-controller"

	typeReady                  = "Ready"
	typeWebhookConnectionValid = "WebhookConnectionValid"
	typeEndpointURLValid       = "EndpointURLValid"
	typeAuthenticatorValid     = "AuthenticatorValid"

	reasonUnableToCreateClient       = "UnableToCreateClient"
	reasonUnableToInstantiateWebhook = "UnableToInstantiateWebhook"
	reasonInvalidEndpointURL         = "InvalidEndpointURL"
	reasonInvalidEndpointURLScheme   = "InvalidEndpointURLScheme"
)

type cachedWebhookAuthenticator struct {
	authenticator.Token
	endpoint     string
	caBundleHash tlsconfigutil.CABundleHash
}

func (*cachedWebhookAuthenticator) Close() {
	// no-op, because no cleanup is needed on webhook authenticators
}

// New instantiates a new controllerlib.Controller which will populate the provided authncache.Cache.
func New(
	namespace string,
	cache *authncache.Cache,
	client conciergeclientset.Interface,
	webhookInformer authinformers.WebhookAuthenticatorInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	clock clock.Clock,
	log plog.Logger,
	dialer ptls.Dialer,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: controllerName,
			Syncer: &webhookCacheFillerController{
				namespace:         namespace,
				cache:             cache,
				client:            client,
				webhookInformer:   webhookInformer,
				secretInformer:    secretInformer,
				configMapInformer: configMapInformer,
				clock:             clock,
				log:               log.WithName(controllerName),
				dialer:            dialer,
			},
		},
		withInformer(
			webhookInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypesFilter(
				[]corev1.SecretType{
					corev1.SecretTypeOpaque,
					corev1.SecretTypeTLS,
				},
				pinnipedcontroller.SingletonQueue(),
			),
			controllerlib.InformerOption{},
		),
		withInformer(
			configMapInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

type webhookCacheFillerController struct {
	namespace         string
	cache             *authncache.Cache
	webhookInformer   authinformers.WebhookAuthenticatorInformer
	secretInformer    corev1informers.SecretInformer
	configMapInformer corev1informers.ConfigMapInformer
	client            conciergeclientset.Interface
	clock             clock.Clock
	log               plog.Logger
	dialer            ptls.Dialer
}

// Sync implements controllerlib.Syncer.
func (c *webhookCacheFillerController) Sync(ctx controllerlib.Context) error {
	webhookAuthenticators, err := c.webhookInformer.Lister().List(labels.Everything())
	if err != nil {
		return err
	}

	if len(webhookAuthenticators) == 0 {
		c.log.Info("No WebhookAuthenticators found")
		return nil
	}

	// Sort them by name so that order is predictable and therefore output is consistent for tests and logs.
	slices.SortStableFunc(webhookAuthenticators, func(a, b *authenticationv1alpha1.WebhookAuthenticator) int {
		return strings.Compare(a.Name, b.Name)
	})

	var errs []error
	for _, webhookAuthenticator := range webhookAuthenticators {
		err = c.syncIndividualWebhookAuthenticator(ctx.Context, webhookAuthenticator)
		if err != nil {
			errs = append(errs, fmt.Errorf("error for WebhookAuthenticator %s: %w", webhookAuthenticator.Name, err))
		}
	}
	return utilerrors.NewAggregate(errs)
}

func (c *webhookCacheFillerController) syncIndividualWebhookAuthenticator(ctx context.Context, webhookAuthenticator *authenticationv1alpha1.WebhookAuthenticator) error {
	cacheKey := authncache.Key{
		APIGroup: authenticationv1alpha1.GroupName,
		Kind:     "WebhookAuthenticator",
		Name:     webhookAuthenticator.Name,
	}

	logger := c.log.WithValues(
		"webhookAuthenticator", webhookAuthenticator.Name,
		"endpoint", webhookAuthenticator.Spec.Endpoint)

	var errs []error
	conditions := make([]*metav1.Condition, 0)
	var newWebhookAuthenticatorForCache *cachedWebhookAuthenticator

	caBundle, conditions, tlsBundleOk := c.validateTLSBundle(webhookAuthenticator.Spec.TLS, conditions)

	endpointHostPort, conditions, endpointOk := c.validateEndpoint(webhookAuthenticator.Spec.Endpoint, conditions)
	okSoFar := tlsBundleOk && endpointOk

	// Only revalidate and update the cache if the cached authenticator is different from the desired authenticator.
	// There is no need to repeat connection probe validations for a URL and CA bundle combination that was already
	// successfully validated. We are making a design decision to avoid repeating the validation which dials the server,
	// even though the server's TLS configuration could have changed, because it is also possible that the network
	// could be flaky. We are choosing to prefer to keep the authenticator cached (available for end-user auth attempts)
	// during times of network flakes rather than trying to show the most up-to-date status possible. These validations
	// are for administrator convenience at the time of a configuration change, to catch typos and blatant
	// misconfigurations, rather than to constantly monitor for external issues.
	foundAuthenticatorInCache, previouslyValidatedWithSameEndpointAndBundle := c.havePreviouslyValidated(
		cacheKey, webhookAuthenticator.Spec.Endpoint, tlsBundleOk, caBundle.Hash(), logger)
	if previouslyValidatedWithSameEndpointAndBundle {
		// Because the authenticator was previously cached, that implies that the following conditions were
		// previously validated. These are the expensive validations to repeat, so skip them this time.
		// However, the status may be lagging behind due to the informer cache being slow to catch up
		// after previous status updates, so always calculate the new status conditions again and check
		// if they need to be updated.
		logger.Info("cached webhook authenticator and desired webhook authenticator are the same: already cached, so skipping validations")
		conditions = append(conditions,
			successfulWebhookConnectionValidCondition(),
			successfulAuthenticatorValidCondition(),
		)
	} else {
		// Run all remaining validations.
		a, moreConditions, moreErrs := c.doExpensiveValidations(ctx, webhookAuthenticator, endpointHostPort, caBundle, okSoFar, logger)
		newWebhookAuthenticatorForCache = a
		conditions = append(conditions, moreConditions...)
		errs = append(errs, moreErrs...)
	}

	authenticatorValid := !conditionsutil.HadErrorCondition(conditions)

	// If we calculated a failed status condition, then remove it from the cache even before we try to write
	// the status, because writing the status can fail for various reasons.
	if !authenticatorValid {
		// The authenticator was determined to be invalid. Remove it from the cache, in case it was previously
		// validated and cached. Do not allow an old, previously validated spec of the authenticator to continue
		// being used for authentication.
		c.cache.Delete(cacheKey)
		logger.Info("invalid webhook authenticator",
			"removedFromCache", foundAuthenticatorInCache)
	}

	// Always try to update the status, even when we found it in the authenticator cache.
	updateErr := c.updateStatus(ctx, webhookAuthenticator, conditions, logger)
	errs = append(errs, updateErr)

	// Only add/update this authenticator to the cache when we have a new one and the status update succeeded.
	if newWebhookAuthenticatorForCache != nil && authenticatorValid && updateErr == nil {
		c.cache.Store(cacheKey, newWebhookAuthenticatorForCache)
		logger.Info("added or updated webhook authenticator in cache",
			"isOverwrite", foundAuthenticatorInCache)
	}

	// Sync loop errors:
	// - Should not be configuration errors. Config errors a user must correct belong on the .Status
	//   object. The controller simply must wait for a user to correct before running again.
	// - Other errors, such as networking errors, etc. are the types of errors that should return here
	//   and signal the controller to retry the sync loop. These may be corrected by machines.
	return utilerrors.NewAggregate(errs)
}

func (c *webhookCacheFillerController) doExpensiveValidations(
	ctx context.Context,
	webhookAuthenticator *authenticationv1alpha1.WebhookAuthenticator,
	endpointHostPort *endpointaddr.HostPort,
	caBundle *tlsconfigutil.CABundle,
	okSoFar bool,
	logger plog.Logger,
) (*cachedWebhookAuthenticator, []*metav1.Condition, []error) {
	var newWebhookAuthenticatorForCache *cachedWebhookAuthenticator
	var conditions []*metav1.Condition
	var errs []error

	conditions, tlsNegotiateErr := c.validateConnection(ctx, caBundle.CertPool(), endpointHostPort, conditions, okSoFar, logger)
	errs = append(errs, tlsNegotiateErr)
	okSoFar = okSoFar && tlsNegotiateErr == nil

	newAuthenticator, conditions, err := newWebhookAuthenticator(
		// Note that we use the whole URL when constructing the webhook client,
		// not just the host and port that we validated above. We need the path, etc.
		webhookAuthenticator.Spec.Endpoint,
		caBundle.PEMBytes(),
		conditions,
		okSoFar,
	)
	errs = append(errs, err)

	if newAuthenticator != nil {
		newWebhookAuthenticatorForCache = &cachedWebhookAuthenticator{
			Token:        newAuthenticator,
			endpoint:     webhookAuthenticator.Spec.Endpoint,
			caBundleHash: caBundle.Hash(),
		}
	}
	return newWebhookAuthenticatorForCache, conditions, errs
}

func (c *webhookCacheFillerController) havePreviouslyValidated(
	cacheKey authncache.Key,
	endpoint string,
	tlsBundleOk bool,
	caBundleHash tlsconfigutil.CABundleHash,
	logger plog.Logger,
) (bool, bool) {
	var authenticatorFromCache *cachedWebhookAuthenticator
	valueFromCache := c.cache.Get(cacheKey)
	if valueFromCache == nil {
		return false, false
	}
	authenticatorFromCache = c.cacheValueAsWebhookAuthenticator(valueFromCache, logger)
	if authenticatorFromCache == nil {
		return false, false
	}
	if authenticatorFromCache.endpoint == endpoint &&
		tlsBundleOk && // if there was any error while validating the latest CA bundle, then do not consider it previously validated
		authenticatorFromCache.caBundleHash.Equal(caBundleHash) {
		return true, true
	}
	return true, false // found the authenticator, but it had not been previously validated with these same settings
}

func (c *webhookCacheFillerController) cacheValueAsWebhookAuthenticator(value authncache.Value, log plog.Logger) *cachedWebhookAuthenticator {
	webhookAuthenticator, ok := value.(*cachedWebhookAuthenticator)
	if !ok {
		actualType := "<nil>"
		if t := reflect.TypeOf(value); t != nil {
			actualType = t.String()
		}
		log.Info("wrong webhook authenticator type in cache",
			"actualType", actualType)
		return nil
	}
	return webhookAuthenticator
}

func (c *webhookCacheFillerController) validateTLSBundle(tlsSpec *authenticationv1alpha1.TLSSpec, conditions []*metav1.Condition) (*tlsconfigutil.CABundle, []*metav1.Condition, bool) {
	condition, caBundle := tlsconfigutil.ValidateTLSConfig(
		tlsconfigutil.TLSSpecForConcierge(tlsSpec),
		"spec.tls",
		c.namespace,
		c.secretInformer,
		c.configMapInformer)

	conditions = append(conditions, condition)
	return caBundle, conditions, condition.Status == metav1.ConditionTrue
}

func successfulAuthenticatorValidCondition() *metav1.Condition {
	return &metav1.Condition{
		Type:    typeAuthenticatorValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: "authenticator initialized",
	}
}

// newWebhookAuthenticator creates a webhook from the provided API server url and caBundle
// used to validate TLS connections.
func newWebhookAuthenticator(
	endpointURL string,
	pemBytes []byte,
	conditions []*metav1.Condition,
	prereqOk bool,
) (*webhook.WebhookTokenAuthenticator, []*metav1.Condition, error) {
	if !prereqOk {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeAuthenticatorValid,
			Status:  metav1.ConditionUnknown,
			Reason:  conditionsutil.ReasonUnableToValidate,
			Message: conditionsutil.MessageUnableToValidate,
		})
		return nil, conditions, nil
	}

	// We use v1beta1 instead of v1 since v1beta1 is more prevalent in our desired
	// integration points.
	version := k8sauthv1beta1.SchemeGroupVersion.Version

	// At the current time, we don't provide any audiences because we simply don't
	// have any requirements to do so. This can be changed in the future as
	// requirements change.
	var implicitAuds authenticator.Audiences

	// We set this to nil because we would only need this to support some of the
	// custom proxy stuff used by the API server.
	var customDial k8snetutil.DialFunc

	restConfig := &rest.Config{
		Host:            endpointURL,
		TLSClientConfig: rest.TLSClientConfig{CAData: pemBytes},

		// The remainder of these settings are copied from webhookutil.LoadKubeconfig in k8s.io/apiserver/pkg/util/webhook.
		Dial:    customDial,
		Timeout: 30 * time.Second,
		QPS:     -1,
	}

	client, err := kubeclient.New(kubeclient.WithConfig(restConfig), kubeclient.WithTLSConfigFunc(ptls.Default))
	if err != nil {
		errText := "unable to create client for this webhook"
		msg := fmt.Sprintf("%s: %s", errText, err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeAuthenticatorValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonUnableToCreateClient,
			Message: msg,
		})
		return nil, conditions, fmt.Errorf("%s: %w", errText, err)
	}

	webhookAuthenticator, err := webhook.New(client.JSONConfig, version, implicitAuds, *webhook.DefaultRetryBackoff())
	if err != nil {
		// no unit test for this failure.
		errText := "unable to instantiate webhook"
		msg := fmt.Sprintf("%s: %s", errText, err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeAuthenticatorValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonUnableToInstantiateWebhook,
			Message: msg,
		})
		return nil, conditions, fmt.Errorf("%s: %w", errText, err)
	}

	conditions = append(conditions, successfulAuthenticatorValidCondition())

	return webhookAuthenticator, conditions, nil
}

func successfulWebhookConnectionValidCondition() *metav1.Condition {
	return &metav1.Condition{
		Type:    typeWebhookConnectionValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: "successfully dialed webhook server",
	}
}

func (c *webhookCacheFillerController) validateConnection(
	ctx context.Context,
	certPool *x509.CertPool,
	endpointHostPort *endpointaddr.HostPort,
	conditions []*metav1.Condition,
	prereqOk bool,
	logger plog.Logger,
) ([]*metav1.Condition, error) {
	if !prereqOk {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeWebhookConnectionValid,
			Status:  metav1.ConditionUnknown,
			Reason:  conditionsutil.ReasonUnableToValidate,
			Message: conditionsutil.MessageUnableToValidate,
		})
		return conditions, nil
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dialCancel()
	err := c.dialer.IsReachableAndTLSValidationSucceeds(dialCtx, endpointHostPort.Endpoint(), certPool, logger)

	if err != nil {
		errText := "cannot dial server"
		msg := fmt.Sprintf("%s: %s", errText, err)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeWebhookConnectionValid,
			Status:  metav1.ConditionFalse,
			Reason:  conditionsutil.ReasonUnableToDialServer,
			Message: msg,
		})
		return conditions, fmt.Errorf("%s: %w", errText, err)
	}

	conditions = append(conditions, successfulWebhookConnectionValidCondition())
	return conditions, nil
}

func (c *webhookCacheFillerController) validateEndpoint(endpoint string, conditions []*metav1.Condition) (*endpointaddr.HostPort, []*metav1.Condition, bool) {
	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		msg := fmt.Sprintf("%s: %s", "spec.endpoint URL cannot be parsed", err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeEndpointURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidEndpointURL,
			Message: msg,
		})
		return nil, conditions, false
	}

	// handles empty string and other issues as well.
	if endpointURL.Scheme != "https" {
		msg := fmt.Sprintf("spec.endpoint URL %s has invalid scheme, require 'https'", endpoint)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeEndpointURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidEndpointURLScheme,
			Message: msg,
		})
		return nil, conditions, false
	}

	endpointHostPort, err := endpointaddr.ParseFromURL(endpointURL, 443)
	if err != nil {
		msg := fmt.Sprintf("%s: %s", "spec.endpoint URL is not valid", err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeEndpointURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidEndpointURL,
			Message: msg,
		})
		return nil, conditions, false
	}

	conditions = append(conditions, &metav1.Condition{
		Type:    typeEndpointURLValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: "spec.endpoint is a valid URL",
	})
	return &endpointHostPort, conditions, true
}

func (c *webhookCacheFillerController) updateStatus(
	ctx context.Context,
	original *authenticationv1alpha1.WebhookAuthenticator,
	conditions []*metav1.Condition,
	logger plog.Logger,
) error {
	updated := original.DeepCopy()

	if conditionsutil.HadErrorCondition(conditions) {
		updated.Status.Phase = authenticationv1alpha1.WebhookAuthenticatorPhaseError
		conditions = append(conditions, &metav1.Condition{
			Type:    typeReady,
			Status:  metav1.ConditionFalse,
			Reason:  conditionsutil.ReasonNotReady,
			Message: "the WebhookAuthenticator is not ready: see other conditions for details",
		})
	} else {
		updated.Status.Phase = authenticationv1alpha1.WebhookAuthenticatorPhaseReady
		conditions = append(conditions, &metav1.Condition{
			Type:    typeReady,
			Status:  metav1.ConditionTrue,
			Reason:  conditionsutil.ReasonSuccess,
			Message: "the WebhookAuthenticator is ready",
		})
	}

	_ = conditionsutil.MergeConditions(
		conditions,
		&updated.Status.Conditions,
		original.Generation,
		metav1.NewTime(c.clock.Now()),
		logger,
	)

	if equality.Semantic.DeepEqual(original, updated) {
		logger.Debug("choosing to not update the webhookauthenticator status since there is no update to make",
			"phase", updated.Status.Phase)
		return nil
	}
	_, err := c.client.AuthenticationV1alpha1().WebhookAuthenticators().UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err == nil {
		logger.Debug("webhookauthenticator status successfully updated",
			"phase", updated.Status.Phase)
	}
	return err
}
