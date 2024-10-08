// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package oidcupstreamwatcher implements a controller which watches OIDCIdentityProviders.
package oidcupstreamwatcher

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/cache"
	"k8s.io/apimachinery/pkg/util/sets"
	corev1informers "k8s.io/client-go/informers/core/v1"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/upstreamoidc"
)

const (
	// Setup for the name of our controller in logs.
	oidcControllerName = "oidc-upstream-observer"

	// Constants related to the client credentials Secret.
	oidcClientSecretType corev1.SecretType = "secrets.pinniped.dev/oidc-client"

	clientIDDataKey     = "clientID"
	clientSecretDataKey = "clientSecret"

	// Constants related to the OIDC provider discovery cache. These do not affect the cache of JWKS.
	oidcValidatorCacheTTL = 15 * time.Minute

	// Constants related to conditions.
	typeClientCredentialsSecretValid       = "ClientCredentialsSecretValid" //nolint:gosec // this is not a credential
	typeAdditionalAuthorizeParametersValid = "AdditionalAuthorizeParametersValid"
	typeOIDCDiscoverySucceeded             = "OIDCDiscoverySucceeded"

	reasonUnreachable             = "Unreachable"
	reasonInvalidResponse         = "InvalidResponse"
	reasonDisallowedParameterName = "DisallowedParameterName"
	allParamNamesAllowedMsg       = "additionalAuthorizeParameters parameter names are allowed"
)

var (
	disallowedAdditionalAuthorizeParameters = map[string]bool{ //nolint:gochecknoglobals
		// Reject these AdditionalAuthorizeParameters to avoid allowing the user's config to overwrite the parameters
		// that are always used by Pinniped in authcode authorization requests. The OIDC library used would otherwise
		// happily treat the user's config as an override. Users can already set the "client_id" and "scope" params
		// using other settings, and the others never make sense to override. This map should be treated as read-only
		// since it is a global variable.
		"response_type":         true,
		"scope":                 true,
		"client_id":             true,
		"state":                 true,
		"nonce":                 true,
		"code_challenge":        true,
		"code_challenge_method": true,
		"redirect_uri":          true,

		// Reject "hd" for now because it is not safe to use with Google's OIDC provider until Pinniped also
		// performs the corresponding validation on the ID token.
		"hd": true,
	}
)

// UpstreamOIDCIdentityProviderICache is a thread safe cache that holds a list of validated upstream OIDC IDP configurations.
type UpstreamOIDCIdentityProviderICache interface {
	SetOIDCIdentityProviders([]upstreamprovider.UpstreamOIDCIdentityProviderI)
}

// oidcDiscoveryCacheKey is the type of keys in an oidcDiscoveryCache.
type oidcDiscoveryCacheKey struct {
	issuer       string
	caBundleHash tlsconfigutil.CABundleHash
}

// oidcDiscoveryCacheValue is the type of cache entries in an oidcDiscoveryCache.
type oidcDiscoveryCacheValue struct {
	provider *coreosoidc.Provider
	client   *http.Client
}

// oidcDiscoveryCache caches the discovered provider along with the http Client to use for making calls to that provider,
// for a particular combination OIDC issuer and CA bundle for that issuer.
type oidcDiscoveryCache interface {
	getProvider(oidcDiscoveryCacheKey) *oidcDiscoveryCacheValue
	putProvider(oidcDiscoveryCacheKey, *oidcDiscoveryCacheValue)
}

// ttlProviderCache caches the *coreosoidc.Provider associated with a particular issuer/TLS configuration,
// for a limited time (TTL).
type ttlProviderCache struct{ cache *cache.Expiring }

// ttlProviderCache implements the oidcDiscoveryCache interface.
var _ oidcDiscoveryCache = (*ttlProviderCache)(nil)

// getProvider gets an entry from the ttlProviderCache.
func (c *ttlProviderCache) getProvider(key oidcDiscoveryCacheKey) *oidcDiscoveryCacheValue {
	if result, ok := c.cache.Get(key); ok {
		entry := result.(*oidcDiscoveryCacheValue)
		return entry
	}
	return nil
}

// putProvider adds to the ttlProviderCache for a limited period of time.
func (c *ttlProviderCache) putProvider(key oidcDiscoveryCacheKey, value *oidcDiscoveryCacheValue) {
	c.cache.Set(key, value, oidcValidatorCacheTTL)
}

type oidcWatcherController struct {
	cache                        UpstreamOIDCIdentityProviderICache
	log                          plog.Logger
	client                       supervisorclientset.Interface
	oidcIdentityProviderInformer idpinformers.OIDCIdentityProviderInformer
	secretInformer               corev1informers.SecretInformer
	configMapInformer            corev1informers.ConfigMapInformer
	validatorCache               oidcDiscoveryCache
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamOIDCIdentityProviderICache.
func New(
	idpCache UpstreamOIDCIdentityProviderICache,
	client supervisorclientset.Interface,
	oidcIdentityProviderInformer idpinformers.OIDCIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	log plog.Logger,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	validatorCache *cache.Expiring,
) controllerlib.Controller {
	c := oidcWatcherController{
		cache:                        idpCache,
		log:                          log.WithName(oidcControllerName),
		client:                       client,
		oidcIdentityProviderInformer: oidcIdentityProviderInformer,
		secretInformer:               secretInformer,
		configMapInformer:            configMapInformer,
		validatorCache:               &ttlProviderCache{cache: validatorCache},
	}
	return controllerlib.New(
		controllerlib.Config{Name: oidcControllerName, Syncer: &c},
		withInformer(
			oidcIdentityProviderInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypesFilter(
				[]corev1.SecretType{
					oidcClientSecretType,
					corev1.SecretTypeOpaque,
					corev1.SecretTypeTLS,
				},
				pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			configMapInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *oidcWatcherController) Sync(ctx controllerlib.Context) error {
	actualUpstreams, err := c.oidcIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list OIDCIdentityProviders: %w", err)
	}

	requeue := false
	validatedUpstreams := make([]upstreamprovider.UpstreamOIDCIdentityProviderI, 0, len(actualUpstreams))
	for _, upstream := range actualUpstreams {
		valid := c.validateUpstream(ctx, upstream)
		if valid == nil {
			requeue = true
		} else {
			validatedUpstreams = append(validatedUpstreams, upstreamprovider.UpstreamOIDCIdentityProviderI(valid))
		}
	}
	c.cache.SetOIDCIdentityProviders(validatedUpstreams)
	if requeue {
		return controllerlib.ErrSyntheticRequeue
	}
	return nil
}

// validateUpstream validates the provided idpv1alpha1.OIDCIdentityProvider and returns the validated configuration as a
// provider.UpstreamOIDCIdentityProvider. As a side effect, it also updates the status of the idpv1alpha1.OIDCIdentityProvider.
func (c *oidcWatcherController) validateUpstream(ctx controllerlib.Context, upstream *idpv1alpha1.OIDCIdentityProvider) *upstreamoidc.ProviderConfig {
	authorizationConfig := upstream.Spec.AuthorizationConfig

	additionalAuthcodeAuthorizeParameters := map[string]string{}
	var rejectedAuthcodeAuthorizeParameters []string
	for _, p := range authorizationConfig.AdditionalAuthorizeParameters {
		if disallowedAdditionalAuthorizeParameters[p.Name] {
			rejectedAuthcodeAuthorizeParameters = append(rejectedAuthcodeAuthorizeParameters, p.Name)
		} else {
			additionalAuthcodeAuthorizeParameters[p.Name] = p.Value
		}
	}

	result := upstreamoidc.ProviderConfig{
		Name: upstream.Name,
		Config: &oauth2.Config{
			Scopes: computeScopes(authorizationConfig.AdditionalScopes),
		},
		UsernameClaim:            upstream.Spec.Claims.Username,
		GroupsClaim:              upstream.Spec.Claims.Groups,
		AllowPasswordGrant:       authorizationConfig.AllowPasswordGrant,
		AdditionalAuthcodeParams: additionalAuthcodeAuthorizeParameters,
		AdditionalClaimMappings:  upstream.Spec.Claims.AdditionalClaimMappings,
		ResourceUID:              upstream.UID,
	}

	conditions := []*metav1.Condition{
		c.validateSecret(upstream, &result),
	}
	conditions = append(conditions, c.validateIssuer(ctx.Context, upstream, &result)...)

	if len(rejectedAuthcodeAuthorizeParameters) > 0 {
		conditions = append(conditions, &metav1.Condition{
			Type:   typeAdditionalAuthorizeParametersValid,
			Status: metav1.ConditionFalse,
			Reason: reasonDisallowedParameterName,
			Message: fmt.Sprintf("the following additionalAuthorizeParameters are not allowed: %s",
				strings.Join(rejectedAuthcodeAuthorizeParameters, ",")),
		})
	} else {
		conditions = append(conditions, &metav1.Condition{
			Type:    typeAdditionalAuthorizeParametersValid,
			Status:  metav1.ConditionTrue,
			Reason:  conditionsutil.ReasonSuccess,
			Message: allParamNamesAllowedMsg,
		})
	}

	hadErrorCondition := c.updateStatus(ctx.Context, upstream, conditions)

	if hadErrorCondition {
		return nil
	}
	return &result
}

// validateSecret validates the .spec.client.secretName field and returns the appropriate ClientCredentialsSecretValid condition.
func (c *oidcWatcherController) validateSecret(upstream *idpv1alpha1.OIDCIdentityProvider, result *upstreamoidc.ProviderConfig) *metav1.Condition {
	secretName := upstream.Spec.Client.SecretName

	// Fetch the Secret from informer cache.
	secret, err := c.secretInformer.Lister().Secrets(upstream.Namespace).Get(secretName)
	if err != nil {
		return &metav1.Condition{
			Type:    typeClientCredentialsSecretValid,
			Status:  metav1.ConditionFalse,
			Reason:  upstreamwatchers.ReasonNotFound,
			Message: err.Error(),
		}
	}

	// Validate the secret .type field.
	if secret.Type != oidcClientSecretType {
		return &metav1.Condition{
			Type:    typeClientCredentialsSecretValid,
			Status:  metav1.ConditionFalse,
			Reason:  upstreamwatchers.ReasonWrongType,
			Message: fmt.Sprintf("referenced Secret %q has wrong type %q (should be %q)", secretName, secret.Type, oidcClientSecretType),
		}
	}

	// Validate the secret .data field.
	clientID := secret.Data[clientIDDataKey]
	clientSecret := secret.Data[clientSecretDataKey]
	if len(clientID) == 0 || len(clientSecret) == 0 {
		return &metav1.Condition{
			Type:    typeClientCredentialsSecretValid,
			Status:  metav1.ConditionFalse,
			Reason:  upstreamwatchers.ReasonMissingKeys,
			Message: fmt.Sprintf("referenced Secret %q is missing required keys %q", secretName, []string{clientIDDataKey, clientSecretDataKey}),
		}
	}

	// If everything is valid, update the result and set the condition to true.
	result.Config.ClientID = string(clientID)
	result.Config.ClientSecret = string(clientSecret)
	return &metav1.Condition{
		Type:    typeClientCredentialsSecretValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: "loaded client credentials",
	}
}

// validateIssuer validates the .spec.issuer field, performs OIDC discovery, and returns the appropriate OIDCDiscoverySucceeded condition.
func (c *oidcWatcherController) validateIssuer(ctx context.Context, upstream *idpv1alpha1.OIDCIdentityProvider, result *upstreamoidc.ProviderConfig) []*metav1.Condition {
	tlsCondition, caBundle := tlsconfigutil.ValidateTLSConfig(
		tlsconfigutil.TLSSpecForSupervisor(upstream.Spec.TLS),
		"spec.tls",
		upstream.Namespace,
		c.secretInformer,
		c.configMapInformer)

	// When the TLS config is invalid, return some error conditions.
	if tlsCondition.Reason != conditionsutil.ReasonSuccess {
		return []*metav1.Condition{
			{
				Type:    typeOIDCDiscoverySucceeded,
				Status:  metav1.ConditionUnknown,
				Reason:  conditionsutil.ReasonUnableToValidate,
				Message: conditionsutil.MessageUnableToValidate,
			},
			tlsCondition,
		}
	}

	var discoveredProvider *coreosoidc.Provider
	var httpClient *http.Client

	// Get the discovered provider and HTTP client from cache, if they are found in the cache.
	cacheKey := oidcDiscoveryCacheKey{
		issuer:       upstream.Spec.Issuer,
		caBundleHash: caBundle.Hash(),
	}
	if cacheEntry := c.validatorCache.getProvider(cacheKey); cacheEntry != nil {
		discoveredProvider = cacheEntry.provider
		httpClient = cacheEntry.client
		c.log.WithValues(
			"namespace", upstream.Namespace,
			"name", upstream.Name,
			"issuer", upstream.Spec.Issuer,
		).Debug("found previous OIDC discovery result in cache")
	}

	// If the provider does not exist in the cache, do a fresh discovery lookup and save to the cache.
	if discoveredProvider == nil {
		httpClient = defaultClientShortTimeout(caBundle.CertPool())

		_, issuerURLCondition := validateHTTPSURL(upstream.Spec.Issuer, "issuer", reasonUnreachable)
		if issuerURLCondition != nil {
			return []*metav1.Condition{issuerURLCondition, tlsCondition}
		}

		var err error
		discoveredProvider, err = coreosoidc.NewProvider(coreosoidc.ClientContext(ctx, httpClient), upstream.Spec.Issuer)
		if err != nil {
			c.log.WithValues(
				"namespace", upstream.Namespace,
				"name", upstream.Name,
				"issuer", upstream.Spec.Issuer,
			).Error("failed to perform OIDC discovery", err)
			return []*metav1.Condition{
				{
					Type:   typeOIDCDiscoverySucceeded,
					Status: metav1.ConditionFalse,
					Reason: reasonUnreachable,
					Message: fmt.Sprintf("failed to perform OIDC discovery against %q:\n%s",
						upstream.Spec.Issuer, pinnipedcontroller.TruncateMostLongErr(err)),
				},
				tlsCondition,
			}
		}

		// Update the cache with the newly discovered value.
		c.validatorCache.putProvider(cacheKey, &oidcDiscoveryCacheValue{provider: discoveredProvider, client: httpClient})
	}

	// Get the revocation endpoint, if there is one. Many providers do not offer a revocation endpoint.
	var additionalDiscoveryClaims struct {
		// "revocation_endpoint" is specified by https://datatracker.ietf.org/doc/html/rfc8414#section-2
		RevocationEndpoint string `json:"revocation_endpoint"`
	}
	if err := discoveredProvider.Claims(&additionalDiscoveryClaims); err != nil {
		// This shouldn't actually happen because the above call to NewProvider() would have already returned this error.
		return []*metav1.Condition{
			{
				Type:    typeOIDCDiscoverySucceeded,
				Status:  metav1.ConditionFalse,
				Reason:  reasonInvalidResponse,
				Message: fmt.Sprintf("failed to unmarshal OIDC discovery response from %q:\n%s", upstream.Spec.Issuer, pinnipedcontroller.TruncateMostLongErr(err)),
			},
			tlsCondition,
		}
	}
	if additionalDiscoveryClaims.RevocationEndpoint != "" {
		// Found a revocation URL. Validate it.
		revocationURL, revocationURLCondition := validateHTTPSURL(
			additionalDiscoveryClaims.RevocationEndpoint,
			"revocation endpoint",
			reasonInvalidResponse,
		)
		if revocationURLCondition != nil {
			return []*metav1.Condition{revocationURLCondition, tlsCondition}
		}
		// Remember the URL for later use.
		result.RevocationURL = revocationURL
	}

	_, authorizeURLCondition := validateHTTPSURL(
		discoveredProvider.Endpoint().AuthURL,
		"authorization endpoint",
		reasonInvalidResponse,
	)
	if authorizeURLCondition != nil {
		return []*metav1.Condition{authorizeURLCondition, tlsCondition}
	}

	_, tokenURLCondition := validateHTTPSURL(
		discoveredProvider.Endpoint().TokenURL,
		"token endpoint",
		reasonInvalidResponse,
	)
	if tokenURLCondition != nil {
		return []*metav1.Condition{tokenURLCondition, tlsCondition}
	}

	// If everything is valid, update the result and set the condition to true.
	result.Config.Endpoint = discoveredProvider.Endpoint()
	result.Provider = discoveredProvider
	result.Client = httpClient
	return []*metav1.Condition{
		{
			Type:    typeOIDCDiscoverySucceeded,
			Status:  metav1.ConditionTrue,
			Reason:  conditionsutil.ReasonSuccess,
			Message: "discovered issuer configuration",
		},
		tlsCondition,
	}
}

func (c *oidcWatcherController) updateStatus(
	ctx context.Context,
	upstream *idpv1alpha1.OIDCIdentityProvider,
	conditions []*metav1.Condition,
) bool {
	log := c.log.WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConditions(
		conditions,
		&updated.Status.Conditions,
		upstream.Generation,
		metav1.Now(),
		log,
	)

	updated.Status.Phase = idpv1alpha1.PhaseReady
	if hadErrorCondition {
		updated.Status.Phase = idpv1alpha1.PhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return hadErrorCondition
	}

	_, err := c.client.
		IDPV1alpha1().
		OIDCIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	if err != nil {
		log.Error("failed to update status", err)
	}

	return hadErrorCondition
}

func defaultClientShortTimeout(rootCAs *x509.CertPool) *http.Client {
	c := phttp.Default(rootCAs)
	c.Timeout = time.Minute
	return c
}

func computeScopes(additionalScopes []string) []string {
	// If none are set then provide a reasonable default which only tries to use scopes defined in the OIDC spec.
	if len(additionalScopes) == 0 {
		return []string{oidcapi.ScopeOpenID, oidcapi.ScopeOfflineAccess, oidcapi.ScopeEmail, oidcapi.ScopeProfile}
	}

	// Otherwise, first compute the unique set of scopes, including "openid" (de-duplicate).
	set := sets.NewString()
	set.Insert(oidcapi.ScopeOpenID)
	for _, s := range additionalScopes {
		set.Insert(s)
	}

	// Return the set as a sorted list.
	return set.List()
}

func validateHTTPSURL(maybeHTTPSURL, endpointType, reason string) (*url.URL, *metav1.Condition) {
	parsedURL, err := url.Parse(maybeHTTPSURL)
	if err != nil {
		return nil, &metav1.Condition{
			Type:    typeOIDCDiscoverySucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: fmt.Sprintf("failed to parse %s URL: %v", endpointType, pinnipedcontroller.TruncateMostLongErr(err)),
		}
	}
	if parsedURL.Scheme != "https" {
		return nil, &metav1.Condition{
			Type:    typeOIDCDiscoverySucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: fmt.Sprintf(`%s URL '%s' must have "https" scheme, not %q`, endpointType, maybeHTTPSURL, parsedURL.Scheme),
		}
	}
	if len(parsedURL.Query()) != 0 || parsedURL.Fragment != "" {
		return nil, &metav1.Condition{
			Type:    typeOIDCDiscoverySucceeded,
			Status:  metav1.ConditionFalse,
			Reason:  reason,
			Message: fmt.Sprintf(`%s URL '%s' cannot contain query or fragment component`, endpointType, maybeHTTPSURL),
		}
	}
	return parsedURL, nil
}
