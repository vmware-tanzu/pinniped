// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package jwtcachefiller implements a controller for filling an authncache.Cache with each
// added/updated JWTAuthenticator.
package jwtcachefiller

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite/token/jwt"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	errorsutil "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/apis/apiserver"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
	"k8s.io/klog/v2"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	auth1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/authentication/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	conciergeclientset "go.pinniped.dev/generated/latest/client/concierge/clientset/versioned"
	authinformers "go.pinniped.dev/generated/latest/client/concierge/informers/externalversions/authentication/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	pinnipedauthenticator "go.pinniped.dev/internal/controller/authenticator"
	"go.pinniped.dev/internal/controller/authenticator/authncache"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
)

// These default values come from the way that the Supervisor issues and signs tokens. We make these
// the defaults for a JWTAuthenticator so that they can easily integrate with the Supervisor.
const (
	controllerName = "jwtcachefiller-controller"

	typeReady                 = "Ready"
	typeTLSConfigurationValid = "TLSConfigurationValid"
	typeIssuerURLValid        = "IssuerURLValid"
	typeDiscoveryValid        = "DiscoveryURLValid"
	typeJWKSURLValid          = "JWKSURLValid"
	typeJWKSFetchValid        = "JWKSFetchValid"
	typeAuthenticatorValid    = "AuthenticatorValid"

	reasonSuccess                      = "Success"
	reasonNotReady                     = "NotReady"
	reasonUnableToValidate             = "UnableToValidate"
	reasonInvalidIssuerURL             = "InvalidIssuerURL"
	reasonInvalidIssuerURLScheme       = "InvalidIssuerURLScheme"
	reasonInvalidProviderJWKSURL       = "InvalidProviderJWKSURL"
	reasonInvalidProviderJWKSURLScheme = "InvalidProviderJWKSURLScheme"
	reasonInvalidTLSConfiguration      = "InvalidTLSConfiguration"
	reasonInvalidDiscoveryProbe        = "InvalidDiscoveryProbe"
	reasonInvalidAuthenticator         = "InvalidAuthenticator"
	reasonInvalidTokenSigning          = "InvalidTokenSigning"
	reasonInvalidCouldNotFetchJWKS     = "InvalidCouldNotFetchJWKS"

	msgUnableToValidate = "unable to validate; see other conditions for details"

	defaultUsernameClaim = oidcapi.IDTokenClaimUsername
	defaultGroupsClaim   = oidcapi.IDTokenClaimGroups
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
	tokenAuthenticatorCloser
	spec *auth1alpha1.JWTAuthenticatorSpec
}

// New instantiates a new controllerlib.Controller which will populate the provided authncache.Cache.
func New(
	cache *authncache.Cache,
	client conciergeclientset.Interface,
	jwtAuthenticators authinformers.JWTAuthenticatorInformer,
	clock clock.Clock,
	log plog.Logger,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: controllerName,
			Syncer: &jwtCacheFillerController{
				cache:             cache,
				client:            client,
				jwtAuthenticators: jwtAuthenticators,
				clock:             clock,
				log:               log.WithName(controllerName),
			},
		},
		controllerlib.WithInformer(
			jwtAuthenticators,
			pinnipedcontroller.MatchAnythingFilter(nil), // nil parent func is fine because each event is distinct
			controllerlib.InformerOption{},
		),
	)
}

type jwtCacheFillerController struct {
	cache             *authncache.Cache
	jwtAuthenticators authinformers.JWTAuthenticatorInformer
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
		return fmt.Errorf("failed to get JWTAuthenticator %s/%s: %w", ctx.Key.Namespace, ctx.Key.Name, err)
	}

	cacheKey := authncache.Key{
		APIGroup: auth1alpha1.GroupName,
		Kind:     "JWTAuthenticator",
		Name:     ctx.Key.Name,
	}

	// If this authenticator already exists, then only recreate it if is different from the desired
	// authenticator. We don't want to be creating a new authenticator for every resync period.
	//
	// If we do need to recreate the authenticator, then make sure we close the old one to avoid
	// goroutine leaks.
	if value := c.cache.Get(cacheKey); value != nil {
		jwtAuthenticator := c.extractValueAsJWTAuthenticator(value)
		if jwtAuthenticator != nil {
			if reflect.DeepEqual(jwtAuthenticator.spec, &obj.Spec) {
				c.log.WithValues("jwtAuthenticator", klog.KObj(obj), "issuer", obj.Spec.Issuer).Info("actual jwt authenticator and desired jwt authenticator are the same")
				return nil
			}
			jwtAuthenticator.Close()
		}
	}

	conditions := make([]*metav1.Condition, 0)
	specCopy := obj.Spec.DeepCopy()
	var errs []error

	rootCAs, conditions, tlsOk := c.validateTLS(specCopy.TLS, conditions)
	_, conditions, issuerOk := c.validateIssuer(specCopy.Issuer, conditions)

	client := phttp.Default(rootCAs)
	client.Timeout = 30 * time.Second // copied from Kube OIDC code
	coreOSCtx := coreosoidc.ClientContext(context.Background(), client)

	pJSON, provider, conditions, providerErr := c.validateProviderDiscovery(coreOSCtx, specCopy.Issuer, conditions, tlsOk && issuerOk)
	errs = append(errs, providerErr)

	jwksURL, conditions, jwksErr := c.validateProviderJWKSURL(provider, pJSON, conditions, tlsOk && issuerOk && providerErr == nil)
	errs = append(errs, jwksErr)

	keySet, conditions, jwksFetchErr := c.validateJWKSFetch(coreOSCtx, jwksURL, conditions, tlsOk && issuerOk && providerErr == nil && jwksErr == nil)
	errs = append(errs, jwksFetchErr)

	// Make a deep copy of the spec so we aren't storing pointers to something that the informer cache
	// may mutate! We don't store status as status is derived from spec.
	cachedAuthenticator, conditions, err := c.newCachedJWTAuthenticator(
		client,
		obj.Spec.DeepCopy(),
		keySet,
		conditions,
		tlsOk && issuerOk && providerErr == nil && jwksErr == nil && jwksFetchErr == nil)
	errs = append(errs, err)

	if !conditionsutil.HadErrorCondition(conditions) {
		c.cache.Store(cacheKey, cachedAuthenticator)
		c.log.Info("added new jwt authenticator", "jwtAuthenticator", klog.KObj(obj), "issuer", obj.Spec.Issuer)
	}

	err = c.updateStatus(ctx.Context, obj, conditions)
	errs = append(errs, err)

	// sync loop errors:
	// - should not be configuration errors. config errors a user must correct belong on the .Status
	//   object. The controller simply must wait for a user to correct before running again.
	// - other errors, such as networking errors, etc. are the types of errors that should return here
	//   and signal the controller to retry the sync loop. These may be corrected by machines.
	return errorsutil.NewAggregate(errs)
}

func (c *jwtCacheFillerController) extractValueAsJWTAuthenticator(value authncache.Value) *cachedJWTAuthenticator {
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

func (c *jwtCacheFillerController) updateStatus(
	ctx context.Context,
	original *auth1alpha1.JWTAuthenticator,
	conditions []*metav1.Condition,
) error {
	updated := original.DeepCopy()

	if conditionsutil.HadErrorCondition(conditions) {
		updated.Status.Phase = auth1alpha1.JWTAuthenticatorPhaseError
		conditions = append(conditions, &metav1.Condition{
			Type:    typeReady,
			Status:  metav1.ConditionFalse,
			Reason:  reasonNotReady,
			Message: "the JWTAuthenticator is not ready: see other conditions for details",
		})
	} else {
		updated.Status.Phase = auth1alpha1.JWTAuthenticatorPhaseReady
		conditions = append(conditions, &metav1.Condition{
			Type:    typeReady,
			Status:  metav1.ConditionTrue,
			Reason:  reasonSuccess,
			Message: "the JWTAuthenticator is ready",
		})
	}

	_ = conditionsutil.MergeConfigConditions(
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
	testJWTToken := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"aud": "fake-audience-for-verification-probe",
	})
	rawToken, signErr := testJWTToken.SignedString(jwt.UnsafeAllowNoneSignatureType)
	// no unit tests for this block.
	// this is not configurable, there is no way to change the token we are using
	// for testing, so we simply shouldn't hit this block.
	if signErr != nil {
		errText := "could not sign tokens"
		msg := fmt.Sprintf("%s: %s", errText, signErr.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSFetchValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidTokenSigning,
			Message: msg,
		})
		return keySet, conditions, fmt.Errorf("%s: %w", errText, signErr)
	}
	_, verifyWithKeySetErr := keySet.VerifySignature(ctx, rawToken)
	verifyErrString := verifyWithKeySetErr.Error()
	// we need to fetch the keys. this is the main concern of this function
	if strings.Contains(verifyErrString, "fetching keys") {
		errText := "could not fetch keys"
		msg := fmt.Sprintf("%s: %s", errText, verifyErrString)
		conditions = append(conditions, &metav1.Condition{
			Type:    typeJWKSFetchValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidCouldNotFetchJWKS,
			Message: msg,
		})
		return keySet, conditions, fmt.Errorf("%s: %w", errText, verifyWithKeySetErr)
	}
	// this error indicates success of this check.  we only wanted to test if we could fetch, we aren't actually
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
	// any other errors we will ignore and treat this as a success.
	return keySet, conditions, nil
}

// newCachedJWTAuthenticator creates a jwt authenticator from the provided spec.
func (c *jwtCacheFillerController) newCachedJWTAuthenticator(client *http.Client, spec *auth1alpha1.JWTAuthenticatorSpec, keySet *coreosoidc.RemoteKeySet, conditions []*metav1.Condition, prereqOk bool) (*cachedJWTAuthenticator, []*metav1.Condition, error) {
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

	oidcAuthenticator, err := oidc.New(oidc.Options{
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
		tokenAuthenticatorCloser: oidcAuthenticator,
		spec:                     spec,
	}, conditions, nil
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
		msg := fmt.Sprintf("%s: %s", errText, err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeDiscoveryValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidDiscoveryProbe,
			Message: msg,
		})
		// resync err, may be machine or other types of non-config error
		return nil, nil, conditions, fmt.Errorf("%s: %w", errText, err)
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

func (c *jwtCacheFillerController) validateTLS(tlsSpec *auth1alpha1.TLSSpec, conditions []*metav1.Condition) (*x509.CertPool, []*metav1.Condition, bool) {
	rootCAs, _, err := pinnipedauthenticator.CABundle(tlsSpec)
	if err != nil {
		msg := fmt.Sprintf("%s: %s", "invalid TLS configuration", err.Error())
		conditions = append(conditions, &metav1.Condition{
			Type:    typeTLSConfigurationValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidTLSConfiguration,
			Message: msg,
		})
		return rootCAs, conditions, false
	}

	msg := "successfully parsed specified CA bundle"
	if rootCAs == nil {
		msg = "no CA bundle specified"
	}
	conditions = append(conditions, &metav1.Condition{
		Type:    typeTLSConfigurationValid,
		Status:  metav1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: msg,
	})
	return rootCAs, conditions, true
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

	conditions = append(conditions, &metav1.Condition{
		Type:    typeIssuerURLValid,
		Status:  metav1.ConditionTrue,
		Reason:  reasonSuccess,
		Message: "issuer is a valid URL",
	})
	return issuerURL, conditions, true
}
