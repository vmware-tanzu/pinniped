// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package jwtcachefiller implements a controller for filling an authncache.Cache with each
// added/updated JWTAuthenticator.
package jwtcachefiller

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	authenticationv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	authinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	pinnipedauthenticator "go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
)

const (
	controllerName = "jwtcachefiller-controller"

	typeReady                 = "Ready"
	typeTLSConfigurationValid = "TLSConfigurationValid"
	typeIssuerURLValid        = "IssuerURLValid"
	typeDiscoveryValid        = "DiscoveryURLValid"
	typeJWKSURLValid          = "JWKSURLValid"
	typeJWKSFetchValid        = "JWKSFetchValid"
	typeAuthenticatorValid    = "AuthenticatorValid"

	reasonSuccess                                   = "Success"
	reasonNotReady                                  = "NotReady"
	reasonUnableToValidate                          = "UnableToValidate"
	reasonInvalidIssuerURL                          = "InvalidIssuerURL"
	reasonInvalidIssuerURLScheme                    = "InvalidIssuerURLScheme"
	reasonInvalidIssuerURLFragment                  = "InvalidIssuerURLContainsFragment"
	reasonInvalidIssuerURLQueryParams               = "InvalidIssuerURLContainsQueryParams"
	reasonInvalidIssuerURLContainsWellKnownEndpoint = "InvalidIssuerURLContainsWellKnownEndpoint"
	reasonInvalidProviderJWKSURL                    = "InvalidProviderJWKSURL"
	reasonInvalidProviderJWKSURLScheme              = "InvalidProviderJWKSURLScheme"
	reasonInvalidTLSConfiguration                   = "InvalidTLSConfiguration"
	reasonInvalidDiscoveryProbe                     = "InvalidDiscoveryProbe"
	reasonInvalidAuthenticator                      = "InvalidAuthenticator"
	reasonInvalidCouldNotFetchJWKS                  = "InvalidCouldNotFetchJWKS"

	msgUnableToValidate = "unable to validate; see other conditions for details"

	// These default values come from the way that the Supervisor issues and signs tokens. We make these
	// the defaults for a JWTAuthenticator so that they can easily integrate with the Supervisor.
	defaultUsernameClaim = oidcapi.IDTokenClaimUsername
	defaultGroupsClaim   = oidcapi.IDTokenClaimGroups

	// This hardcoded JWT will be used below to trick coreosoidc.RemoteKeySet into immediately fetching the remote JWKS.
	// Unfortunately, coreosoidc.RemoteKeySet has no public API to ask it to perform this fetch. However, calling
	// VerifySignature() and passing in any valid JWT will cause it to immediately fetch the remote JWKS, and return
	// any errors that might have occurred during the fetch. This controller wants to be able to tell the user
	// about those fetch errors to aid in user debugging of configuration. It is also a benefit for the in-memory
	// cached authenticator to have already preloaded the JWKS, so it is immediately ready to perform authentications.
	// Because we are passing a hardcoded JWT that was signed by a randomly generated signing key, the code below
	// expects that VerifySignature() should always return a signature error for this JWT (with the side effect of
	// fetching the remote JWKS) because no OIDC provider in the world should be using this signing key in its JWKS.
	// If somehow this JWT is considered verified by a remote JWKS, then the code below will treat it as an error.
	// This JWT and its signing key will not be used for any other purpose.
	minimalJWTToTriggerJWKSFetch = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.e30.bqGS21VimxEQES46lfR6-AKt_IQjZKykJGD7uyfer2QAp9d63lzcKZJq8qLj-hnLDJFnvy8F2IU1w26n4RX8s5IWxtkaeS2IZctruZzxg-TngPv4yslOznTPROIx_YOk8TMoz6-qTXWUjVTsu4RcVFnbFtdhRF0V-rfdL7Fah_DGxQM2lteb1nPB0hcN81Q8ony5Kw-NxKIpXXGr977u_SYqnafhlYIyL8W4iMN39xO3F7U3JuiySOUmJjBQPd7jL2XnWQwVcxpiZkjzWpnfEX-jqORMzDMRhbD3EfCBJsc-8NQvC4E9VoIgw2KEsfRHhyPyHITGzYOU7XUA5MnBKg"
)

type providerJSON struct {
	JWKSURL string `json:"jwks_uri"`
}

// defaultSupportedSigningAlgos returns the default signing algos that this JWTAuthenticator
// supports (i.e., if none are supplied by the user).
func defaultSupportedSigningAlgos() []string {
	return []string{
		// RS256 is recommended by the OIDC spec and required, in some capacity. Since we want the
		// JWTAuthenticator to be able to support many OIDC ID tokens out of the box, we include this
		// algorithm by default.
		string(jose.RS256),
		// ES256 is what the Supervisor does, by default. We want integration with the JWTAuthenticator
		// to be as seamless as possible, so we include this algorithm by default.
		string(jose.ES256),
	}
}

type tokenAuthenticatorCloser interface {
	authenticator.Token
	pinnipedauthenticator.Closer
}

type cachedJWTAuthenticator struct {
	authenticator.Token
	spec   *authenticationv1alpha1.JWTAuthenticatorSpec
	cancel context.CancelFunc
}

func (c *cachedJWTAuthenticator) Close() {
	if c == nil {
		return
	}
	c.cancel()
}

var _ tokenAuthenticatorCloser = (*cachedJWTAuthenticator)(nil)

// New instantiates a new controllerlib.Controller which will populate the provided authncache.Cache.
func New(
	namespace string,
	cache *authncache.Cache,
	client conciergeclientset.Interface,
	jwtAuthenticators authinformers.JWTAuthenticatorInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	clock clock.Clock,
	log plog.Logger,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: controllerName,
			Syncer: &jwtCacheFillerController{
				namespace:         namespace,
				cache:             cache,
				client:            client,
				jwtAuthenticators: jwtAuthenticators,
				secretInformer:    secretInformer,
				configMapInformer: configMapInformer,
				clock:             clock,
				log:               log.WithName(controllerName),
			},
		},
		withInformer(
			jwtAuthenticators,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
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
			), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
		withInformer(
			configMapInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

type jwtCacheFillerController struct {
	namespace         string
	cache             *authncache.Cache
	jwtAuthenticators authinformers.JWTAuthenticatorInformer
	secretInformer    corev1informers.SecretInformer
	configMapInformer corev1informers.ConfigMapInformer
	client            conciergeclientset.Interface
	clock             clock.Clock
	log               plog.Logger
}

// Sync implements controllerlib.Syncer.
func (c *jwtCacheFillerController) Sync(ctx controllerlib.Context) error {
	obj, err := c.jwtAuthenticators.Lister().Get(ctx.Key.Name)
	if err != nil && apierrors.IsNotFound(err) {
		c.log.Info("Sync() found that the JWTAuthenticator does not exist yet or was deleted")
		return nil
	}
	if err != nil {
		// no unit test for this failure
		return fmt.Errorf("failed to get JWTAuthenticator %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	cacheKey := authncache.Key{
		APIGroup: authenticationv1alpha1.GroupName,
		Kind:     "JWTAuthenticator",
		Name:     ctx.Key.Name,
	}

	// Only revalidate and update the cache if the cached authenticator is different from the desired authenticator.
	// There is no need to repeat validations for a spec that was already successfully validated. We are making a
	// design decision to avoid repeating the validation which dials the server, even though the server's TLS
	// configuration could have changed, because it is also possible that the network could be flaky. We are choosing
	// to prefer to keep the authenticator cached (available for end-user auth attempts) during times of network flakes
	// rather than trying to show the most up-to-date status possible. These validations are for administrator
	// convenience at the time of a configuration change, to catch typos and blatant misconfigurations, rather
	// than to constantly monitor for external issues.
	var jwtAuthenticatorFromCache *cachedJWTAuthenticator
	if valueFromCache := c.cache.Get(cacheKey); valueFromCache != nil {
		jwtAuthenticatorFromCache = c.cacheValueAsJWTAuthenticator(valueFromCache)
		if jwtAuthenticatorFromCache != nil && reflect.DeepEqual(jwtAuthenticatorFromCache.spec, &obj.Spec) {
			c.log.WithValues("jwtAuthenticator", klog.KObj(obj), "issuer", obj.Spec.Issuer).
				Info("actual jwt authenticator and desired jwt authenticator are the same")
			// Stop, no more work to be done. This authenticator is already validated and cached.
			return nil
		}
	}

	conditions := make([]*metav1.Condition, 0)
	var errs []error

	rootCAs, conditions, tlsOk := c.validateTLSBundle(obj.Spec.TLS, c.namespace, conditions)
	_, conditions, issuerOk := c.validateIssuer(obj.Spec.Issuer, conditions)
	okSoFar := tlsOk && issuerOk

	client := phttp.Default(rootCAs)
	client.Timeout = 30 * time.Second // copied from Kube OIDC code
	coreOSCtx := coreosoidc.ClientContext(context.Background(), client)

	pJSON, provider, conditions, providerErr := c.validateProviderDiscovery(coreOSCtx, obj.Spec.Issuer, conditions, okSoFar)
	errs = append(errs, providerErr)
	okSoFar = okSoFar && providerErr == nil

	jwksURL, conditions, jwksErr := c.validateProviderJWKSURL(provider, pJSON, conditions, okSoFar)
	errs = append(errs, jwksErr)
	okSoFar = okSoFar && jwksErr == nil

	keySet, conditions, jwksFetchErr := c.validateJWKSFetch(coreOSCtx, jwksURL, conditions, okSoFar)
	errs = append(errs, jwksFetchErr)
	okSoFar = okSoFar && jwksFetchErr == nil

	newJWTAuthenticatorForCache, conditions, err := c.newCachedJWTAuthenticator(
		client,
		obj.Spec.DeepCopy(), // deep copy to avoid caching original object
		keySet,
		conditions,
		okSoFar)
	errs = append(errs, err)

	if conditionsutil.HadErrorCondition(conditions) {
		// The authenticator was determined to be invalid. Remove it from the cache, in case it was previously
		// validated and cached. Do not allow an old, previously validated spec of the authenticator to continue
		// being used for authentication.
		c.cache.Delete(cacheKey)
	} else {
		c.cache.Store(cacheKey, newJWTAuthenticatorForCache)
		c.log.WithValues("jwtAuthenticator", klog.KObj(obj), "issuer", obj.Spec.Issuer).
			Info("added new jwt authenticator")
	}

	// In case we just overwrote or deleted the authenticator from the cache, clean up the old instance
	// to avoid leaking goroutines. It's safe to call Close() on nil. We avoid calling Close() until it is
	// removed from the cache, because we do not want any end-user authentications to use a closed authenticator.
	jwtAuthenticatorFromCache.Close()

	err = c.updateStatus(ctx.Context, obj, conditions)
	errs = append(errs, err)

	// Sync loop errors:
	// - Should not be configuration errors. Config errors a user must correct belong on the .Status
	//   object. The controller simply must wait for a user to correct before running again.
	// - Other errors, such as networking errors, etc. are the types of errors that should return here
	//   and signal the controller to retry the sync loop. These may be corrected by machines.
	return utilerrors.NewAggregate(errs)
}

func (c *jwtCacheFillerController) cacheValueAsJWTAuthenticator(value authncache.Value) *cachedJWTAuthenticator {
	jwtAuthenticator, ok := value.(*cachedJWTAuthenticator)
	if !ok {
		actualType := "<nil>"
		if t := reflect.TypeOf(value); t != nil {
			actualType = t.String()
		}
		c.log.WithValues("actualType", actualType).Info("wrong JWT authenticator type in cache")
		return nil
	}
	return jwtAuthenticator
}

func (c *jwtCacheFillerController) validateTLSBundle(tlsSpec *authenticationv1alpha1.TLSSpec, namespace string, conditions []*metav1.Condition) (*x509.CertPool, []*metav1.Condition, bool) {
	condition, _, rootCAs, _ := tlsconfigutil.ValidateTLSConfig(
		tlsconfigutil.TlsSpecForConcierge(tlsSpec),
		"spec.tls",
		namespace,
		c.secretInformer,
		c.configMapInformer)

	conditions = append(conditions, condition)
	return rootCAs, conditions, condition.Status == metav1.ConditionTrue
}

func (c *jwtCacheFillerController) validateIssuer(issuer string, conditions []*metav1.Condition) (*url.URL, []*metav1.Condition, bool) {
	issuerURL, err := url.Parse(issuer)
	if err != nil {
		msg := fmt.Sprintf("%s: %s", "spec.issuer URL is invalid", err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeIssuerURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidIssuerURL,
			Message: msg,
		})
		return nil, conditions, false
	}

	if issuerURL.Scheme != "https" {
		msg := fmt.Sprintf("spec.issuer %s has invalid scheme, require 'https'", issuer)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeIssuerURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidIssuerURLScheme,
			Message: msg,
		})
		return nil, conditions, false
	}

	if strings.HasSuffix(issuerURL.Path, "/.well-known/openid-configuration") {
		msg := fmt.Sprintf("spec.issuer %s cannot include path '/.well-known/openid-configuration'", issuer)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeIssuerURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidIssuerURLContainsWellKnownEndpoint,
			Message: msg,
		})
		return nil, conditions, false
	}

	if len(issuerURL.Query()) != 0 {
		msg := fmt.Sprintf("spec.issuer %s cannot include query params", issuer)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeIssuerURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidIssuerURLQueryParams,
			Message: msg,
		})
		return nil, conditions, false
	}

	if issuerURL.Fragment != "" {
		msg := fmt.Sprintf("spec.issuer %s cannot include fragment", issuer)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeIssuerURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidIssuerURLFragment,
			Message: msg,
		})
		return nil, conditions, false
	}

	conditions = append(conditions, &metav1.Condition{
		Type:    typeIssuerURLValid,
		Status:  metav1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: "issuer is a valid URL",
	})
	return issuerURL, conditions, true
}

func (c *jwtCacheFillerController) validateProviderDiscovery(ctx context.Context, issuer string, conditions []*metav1.Condition, prereqOk bool) (*providerJSON, *coreosoidc.Provider, []*metav1.Condition, error) {
	if !prereqOk {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeDiscoveryValid,
			Status:  metav1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: msgUnableToValidate,
		})
		return nil, nil, conditions, nil
	}

	provider, err := coreosoidc.NewProvider(ctx, issuer)
	pJSON := &providerJSON{}
	if err != nil {
		errText := "could not perform oidc discovery on provider issuer"
		msg := fmt.Sprintf("%s: %s", errText, pinnipedcontroller.TruncateMostLongErr(err))
		conditions = append(conditions, &metav1.Condition{
			Type:    typeDiscoveryValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidDiscoveryProbe,
			Message: msg,
		})
		// resync err, may be machine or other types of non-config error
		return nil, nil, conditions, fmt.Errorf("%s: %s", errText, err)
	}
	msg := "discovery performed successfully"
	conditions = append(conditions, &metav1.Condition{
		Type:    typeDiscoveryValid,
		Status:  metav1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: msg,
	})
	return pJSON, provider, conditions, nil
}

func (c *jwtCacheFillerController) validateProviderJWKSURL(provider *coreosoidc.Provider, pJSON *providerJSON, conditions []*metav1.Condition, prereqOk bool) (string, []*metav1.Condition, error) {
	if provider == nil || pJSON == nil || !prereqOk {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSURLValid,
			Status:  metav1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: msgUnableToValidate,
		})
		return "", conditions, nil
	}
	// should be impossible because coreosoidc.NewProvider validates this, thus we can't write a test to get in this state (currently)
	if err := provider.Claims(pJSON); err != nil {
		errText := "could not get provider jwks_uri"
		msg := fmt.Sprintf("%s: %s", errText, err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidProviderJWKSURL,
			Message: msg,
		})
		// resync err, the user may not be able to fix this via config, it may be the server may be misbehaving.
		return pJSON.JWKSURL, conditions, fmt.Errorf("%s: %w", errText, err)
	}

	parsedJWKSURL, err := url.Parse(pJSON.JWKSURL)
	if err != nil {
		errText := "could not parse provider jwks_uri"
		msg := fmt.Sprintf("%s: %s", errText, err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidProviderJWKSURL,
			Message: msg,
		})
		// resync err, the user may not be able to fix this via config, it may be the server may be misbehaving.
		return pJSON.JWKSURL, conditions, fmt.Errorf("%s: %w", errText, err)
	}

	// spec asserts https is required. https://openid.net/specs/openid-connect-discovery-1_0.html
	if parsedJWKSURL.Scheme != "https" {
		msg := fmt.Sprintf("jwks_uri %s has invalid scheme, require 'https'", pJSON.JWKSURL)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSURLValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidProviderJWKSURLScheme,
			Message: msg,
		})
		return pJSON.JWKSURL, conditions, fmt.Errorf("%s", msg)
	}

	conditions = append(conditions, &metav1.Condition{
		Type:    typeJWKSURLValid,
		Status:  metav1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: "jwks_uri is a valid URL",
	})
	return pJSON.JWKSURL, conditions, nil
}

// validateJWKSFetch deliberately takes an unsigned JWT to trigger coreosoidc.NewRemoteKeySet to
// indirectly fetch the JWKS.  This lets us report a status about the endpoint, even though
// we expect the verification checks to actually fail.  This also pre-warms the cache of keys
// in the remote keyset object.
func (c *jwtCacheFillerController) validateJWKSFetch(ctx context.Context, jwksURL string, conditions []*metav1.Condition, prereqOk bool) (*coreosoidc.RemoteKeySet, []*metav1.Condition, error) {
	if !prereqOk {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSFetchValid,
			Status:  metav1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: msgUnableToValidate,
		})
		return nil, conditions, nil
	}
	keySet := coreosoidc.NewRemoteKeySet(ctx, jwksURL)

	// keySet.verifySignature calls functions which may error in a couple of ways that
	// we will treat as success because we are really only concerned here that we could
	// fetch the keys at all.
	_, verifyWithKeySetErr := keySet.VerifySignature(ctx, minimalJWTToTriggerJWKSFetch)
	if verifyWithKeySetErr == nil {
		// Since we hard-coded this token we expect there to always be a verification error.
		// The purpose of this function is really to test if we can get the JWKS, not to actually validate a token.
		// Therefore, we should never hit this path, nevertheless, lets handle just in case something unexpected happens.
		errText := "remote jwks should not have been able to verify hardcoded test jwt token"
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSFetchValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidCouldNotFetchJWKS,
			Message: errText,
		})
		return nil, conditions, errors.New(errText)
	}

	verifyErrString := verifyWithKeySetErr.Error()
	// We need to fetch the keys. This is the main concern of this function.
	if strings.HasPrefix(verifyErrString, "fetching keys") {
		errText := "could not fetch keys"
		msg := fmt.Sprintf("%s: %s", errText, verifyErrString)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSFetchValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidCouldNotFetchJWKS,
			Message: msg,
		})
		return nil, conditions, fmt.Errorf("%s: %w", errText, verifyWithKeySetErr)
	}
	// This error indicates success of this check. We only wanted to test if we could fetch, we aren't actually
	// testing for valid signature verification.
	if strings.Contains(verifyErrString, "failed to verify id token signature") {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSFetchValid,
			Status:  metav1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "successfully fetched jwks",
		})
		return keySet, conditions, nil
	}

	// No unit tests, currently no way to reach this code path.
	errText := "unexpected verification error while fetching jwks"
	msg := fmt.Sprintf("%s: %s", errText, verifyErrString)
	conditions = append(conditions, &metav1.Condition{
		Type:    typeJWKSFetchValid,
		Status:  metav1.ConditionUnknown,
		Reason:  reasonUnableToValidate,
		Message: msg,
	})
	return nil, conditions, fmt.Errorf("%s: %w", errText, verifyWithKeySetErr)
}

// newCachedJWTAuthenticator creates a jwt authenticator from the provided spec.
func (c *jwtCacheFillerController) newCachedJWTAuthenticator(client *http.Client, spec *authenticationv1alpha1.JWTAuthenticatorSpec, keySet *coreosoidc.RemoteKeySet, conditions []*metav1.Condition, prereqOk bool) (*cachedJWTAuthenticator, []*metav1.Condition, error) {
	if !prereqOk {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeAuthenticatorValid,
			Status:  metav1.ConditionUnknown,
			Reason:  reasonUnableToValidate,
			Message: msgUnableToValidate,
		})
		return nil, conditions, nil
	}

	usernameClaim := spec.Claims.Username
	if usernameClaim == "" {
		usernameClaim = defaultUsernameClaim
	}
	groupsClaim := spec.Claims.Groups
	if groupsClaim == "" {
		groupsClaim = defaultGroupsClaim
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	oidcAuthenticator, err := oidc.New(cancelCtx, oidc.Options{
		JWTAuthenticator: apiserver.JWTAuthenticator{
			Issuer: apiserver.Issuer{
				URL:       spec.Issuer,
				Audiences: []string{spec.Audience},
			},
			ClaimMappings: apiserver.ClaimMappings{
				Username: apiserver.PrefixedClaimOrExpression{
					Claim:  usernameClaim,
					Prefix: ptr.To(""),
				},
				Groups: apiserver.PrefixedClaimOrExpression{
					Claim:  groupsClaim,
					Prefix: ptr.To(""),
				},
			},
		},
		KeySet:               keySet,
		SupportedSigningAlgs: defaultSupportedSigningAlgos(),
		Client:               client,
	})
	if err != nil {
		// no unit test for this failure.
		// it seems that our production code doesn't provide config knobs that would allow
		// incorrect configuration of oidc.New().  We validate inputs before we get to this point
		// and exit early if there are problems. In the future, if we allow more configuration,
		// such as supported signing algorithm config, we may be able to test this.
		errText := "could not initialize oidc authenticator"
		msg := fmt.Sprintf("%s: %s", errText, err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeAuthenticatorValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidAuthenticator,
			Message: msg,
		})
		cancel()
		// resync err, lots of possible issues that may or may not be machine related
		return nil, conditions, fmt.Errorf("%s: %w", errText, err)
	}
	msg := "authenticator initialized"
	conditions = append(conditions, &metav1.Condition{
		Type:    typeAuthenticatorValid,
		Status:  metav1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: msg,
	})
	return &cachedJWTAuthenticator{
		Token:  oidcAuthenticator,
		spec:   spec,
		cancel: cancel,
	}, conditions, nil
}

func (c *jwtCacheFillerController) updateStatus(
	ctx context.Context,
	original *authenticationv1alpha1.JWTAuthenticator,
	conditions []*metav1.Condition,
) error {
	updated := original.DeepCopy()

	if conditionsutil.HadErrorCondition(conditions) {
		updated.Status.Phase = authenticationv1alpha1.JWTAuthenticatorPhaseError
		conditions = append(conditions, &metav1.Condition{
			Type:    typeReady,
			Status:  metav1.ConditionFalse,
			Reason:  reasonNotReady,
			Message: "the JWTAuthenticator is not ready: see other conditions for details",
		})
	} else {
		updated.Status.Phase = authenticationv1alpha1.JWTAuthenticatorPhaseReady
		conditions = append(conditions, &metav1.Condition{
			Type:    typeReady,
			Status:  metav1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the JWTAuthenticator is ready",
		})
	}

	_ = conditionsutil.MergeConditions(
		conditions,
		original.Generation,
		&updated.Status.Conditions,
		plog.New().WithName(controllerName),
		metav1.NewTime(c.clock.Now()),
	)

	if equality.Semantic.DeepEqual(original, updated) {
		return nil
	}
	_, err := c.client.AuthenticationV1alpha1().JWTAuthenticators().UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}
