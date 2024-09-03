// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package githubupstreamwatcher implements a controller which watches GitHubIdentityProviders.
package githubupstreamwatcher

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/cache"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/utils/clock"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/endpointaddr"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/setutil"
	"go.pinniped.dev/internal/upstreamgithub"
)

const (
	controllerName = "github-upstream-observer"

	// Constants related to the client credentials Secret.
	gitHubClientSecretType               corev1.SecretType = "secrets.pinniped.dev/github-client"
	clientIDDataKey, clientSecretDataKey string            = "clientID", "clientSecret"

	countExpectedConditions = 6

	HostValid                    string = "HostValid"
	TLSConfigurationValid        string = "TLSConfigurationValid"
	OrganizationsPolicyValid     string = "OrganizationsPolicyValid"
	ClientCredentialsSecretValid string = "ClientCredentialsSecretValid" //nolint:gosec // this is not a credential
	GitHubConnectionValid        string = "GitHubConnectionValid"
	ClaimsValid                  string = "ClaimsValid"

	reasonInvalid     = "Invalid"
	reasonInvalidHost = "InvalidHost"

	apiDotGithubDotCom = "api.github.com"
	githubDotCom       = "github.com"
)

// UpstreamGitHubIdentityProviderICache is a thread safe cache that holds a list of validated upstream GitHub IDP configurations.
type UpstreamGitHubIdentityProviderICache interface {
	SetGitHubIdentityProviders([]upstreamprovider.UpstreamGithubIdentityProviderI)
}

type GitHubValidatedAPICacheI interface {
	MarkAsValidated(address string, caBundleHash tlsconfigutil.CABundleHash)
	IsValid(address string, caBundleHash tlsconfigutil.CABundleHash) bool
}

type GitHubValidatedAPICache struct {
	cache *cache.Expiring
}

type GitHubValidatedAPICacheKey struct {
	address      string
	caBundleHash tlsconfigutil.CABundleHash
}

func (g *GitHubValidatedAPICache) MarkAsValidated(address string, caBundleHash tlsconfigutil.CABundleHash) {
	key := GitHubValidatedAPICacheKey{
		address:      address,
		caBundleHash: caBundleHash,
	}
	// Existence in the cache means it has been validated.
	// The TTL in the cache is not important, it's just a "really long time".
	g.cache.Set(key, nil, 365*24*time.Hour)
}

func (g *GitHubValidatedAPICache) IsValid(address string, caBundleHash tlsconfigutil.CABundleHash) bool {
	key := GitHubValidatedAPICacheKey{
		address:      address,
		caBundleHash: caBundleHash,
	}
	_, ok := g.cache.Get(key)
	return ok
}

func NewGitHubValidatedAPICache(cache *cache.Expiring) GitHubValidatedAPICacheI {
	return &GitHubValidatedAPICache{cache: cache}
}

type gitHubWatcherController struct {
	namespace                      string
	cache                          UpstreamGitHubIdentityProviderICache
	log                            plog.Logger
	client                         supervisorclientset.Interface
	gitHubIdentityProviderInformer idpinformers.GitHubIdentityProviderInformer
	secretInformer                 corev1informers.SecretInformer
	configMapInformer              corev1informers.ConfigMapInformer
	clock                          clock.Clock
	dialer                         ptls.Dialer
	validatedCache                 GitHubValidatedAPICacheI
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamGitHubIdentityProviderICache.
func New(
	namespace string,
	idpCache UpstreamGitHubIdentityProviderICache,
	client supervisorclientset.Interface,
	gitHubIdentityProviderInformer idpinformers.GitHubIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	configMapInformer corev1informers.ConfigMapInformer,
	log plog.Logger,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	clock clock.Clock,
	dialer ptls.Dialer,
	validatedCache *cache.Expiring,
) controllerlib.Controller {
	c := gitHubWatcherController{
		namespace:                      namespace,
		cache:                          idpCache,
		client:                         client,
		log:                            log.WithName(controllerName),
		gitHubIdentityProviderInformer: gitHubIdentityProviderInformer,
		secretInformer:                 secretInformer,
		configMapInformer:              configMapInformer,
		clock:                          clock,
		dialer:                         dialer,
		validatedCache:                 NewGitHubValidatedAPICache(validatedCache),
	}

	return controllerlib.New(
		controllerlib.Config{Name: controllerName, Syncer: &c},
		withInformer(
			gitHubIdentityProviderInformer,
			pinnipedcontroller.MatchAnythingFilter(pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypesFilter(
				[]corev1.SecretType{
					gitHubClientSecretType,
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

// Sync implements controllerlib.Syncer.
func (c *gitHubWatcherController) Sync(ctx controllerlib.Context) error {
	actualUpstreams, err := c.gitHubIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil { // untested
		return fmt.Errorf("failed to list GitHubIdentityProviders: %w", err)
	}

	// Sort them by name just so that the logs output is consistent
	slices.SortStableFunc(actualUpstreams, func(a, b *idpv1alpha1.GitHubIdentityProvider) int {
		return strings.Compare(a.Name, b.Name)
	})

	var applicationErrors []error
	validatedUpstreams := make([]upstreamprovider.UpstreamGithubIdentityProviderI, 0, len(actualUpstreams))
	for _, upstream := range actualUpstreams {
		validatedUpstream, applicationErr := c.validateUpstreamAndUpdateConditions(ctx, upstream)
		if applicationErr != nil {
			applicationErrors = append(applicationErrors, applicationErr)
		} else if validatedUpstream != nil {
			validatedUpstreams = append(validatedUpstreams, validatedUpstream)
		}
		// Else:
		// If both validatedUpstream and applicationErr are nil, this must be because the upstream had configuration errors.
		// This controller should take no action until the user has reconfigured the upstream.
	}
	c.cache.SetGitHubIdentityProviders(validatedUpstreams)

	// If we have recoverable application errors, let's do a requeue and capture all the applicationErrors too
	if len(applicationErrors) > 0 {
		applicationErrors = append([]error{controllerlib.ErrSyntheticRequeue}, applicationErrors...)
	}

	return utilerrors.NewAggregate(applicationErrors)
}

func (c *gitHubWatcherController) validateClientSecret(secretName string) (*metav1.Condition, string, string, error) {
	secret, unableToRetrieveSecretErr := c.secretInformer.Lister().Secrets(c.namespace).Get(secretName)

	// This error requires user interaction, so ignore it.
	if apierrors.IsNotFound(unableToRetrieveSecretErr) {
		unableToRetrieveSecretErr = nil
	}

	buildFalseCondition := func(prefix string) (*metav1.Condition, string, string, error) {
		return &metav1.Condition{
			Type:   ClientCredentialsSecretValid,
			Status: metav1.ConditionFalse,
			Reason: upstreamwatchers.ReasonNotFound,
			Message: fmt.Sprintf("%s: secret from spec.client.SecretName (%q) must be found in namespace %q with type %q and keys %q and %q",
				prefix,
				secretName,
				c.namespace,
				gitHubClientSecretType,
				clientIDDataKey,
				clientSecretDataKey),
		}, "", "", unableToRetrieveSecretErr
	}

	if unableToRetrieveSecretErr != nil || secret == nil {
		return buildFalseCondition(fmt.Sprintf("secret %q not found", secretName))
	}

	if secret.Type != gitHubClientSecretType {
		return buildFalseCondition(fmt.Sprintf("wrong secret type %q", secret.Type))
	}

	clientID := string(secret.Data[clientIDDataKey])
	if len(clientID) < 1 {
		return buildFalseCondition(fmt.Sprintf("missing key %q", clientIDDataKey))
	}

	clientSecret := string(secret.Data[clientSecretDataKey])
	if len(clientSecret) < 1 {
		return buildFalseCondition(fmt.Sprintf("missing key %q", clientSecretDataKey))
	}

	if len(secret.Data) != 2 {
		return buildFalseCondition("extra keys found")
	}

	return &metav1.Condition{
		Type:    ClientCredentialsSecretValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: fmt.Sprintf("clientID and clientSecret have been read from spec.client.SecretName (%q)", secretName),
	}, clientID, clientSecret, nil
}

func validateOrganizationsPolicy(organizationsSpec *idpv1alpha1.GitHubOrganizationsSpec) *metav1.Condition {
	var policy idpv1alpha1.GitHubAllowedAuthOrganizationsPolicy
	if organizationsSpec.Policy != nil {
		policy = *organizationsSpec.Policy
	}

	// Should not happen due to CRD defaulting, enum validation, and CEL validation (for recent versions of K8s only!)
	// That is why the message here is very minimal
	if (policy == idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers && len(organizationsSpec.Allowed) == 0) ||
		(policy == idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations && len(organizationsSpec.Allowed) > 0) {
		return &metav1.Condition{
			Type:    OrganizationsPolicyValid,
			Status:  metav1.ConditionTrue,
			Reason:  conditionsutil.ReasonSuccess,
			Message: fmt.Sprintf("spec.allowAuthentication.organizations.policy (%q) is valid", policy),
		}
	}

	if len(organizationsSpec.Allowed) > 0 {
		return &metav1.Condition{
			Type:    OrganizationsPolicyValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalid,
			Message: "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",
		}
	}

	return &metav1.Condition{
		Type:    OrganizationsPolicyValid,
		Status:  metav1.ConditionFalse,
		Reason:  reasonInvalid,
		Message: "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
	}
}

func (c *gitHubWatcherController) validateUpstreamAndUpdateConditions(ctx controllerlib.Context, upstream *idpv1alpha1.GitHubIdentityProvider) (
	*upstreamgithub.Provider, // If validated, returns the config
	error, // This error will only refer to programmatic errors such as inability to perform a Dial or dereference a pointer, not configuration errors
) {
	conditions := make([]*metav1.Condition, 0)
	applicationErrors := make([]error, 0)

	clientSecretCondition, clientID, clientSecret, clientSecretErr := c.validateClientSecret(upstream.Spec.Client.SecretName)
	conditions = append(conditions, clientSecretCondition)
	if clientSecretErr != nil { // untested
		applicationErrors = append(applicationErrors, clientSecretErr)
	}

	// Should there be some sort of catch-all condition to capture this?
	// This does not actually prevent a GitHub IDP from being added to the cache.
	// CRD defaulting and validation should eliminate the possibility of an error here.
	userAndGroupCondition, groupNameAttribute, usernameAttribute := validateUserAndGroupAttributes(upstream)
	conditions = append(conditions, userAndGroupCondition)

	organizationPolicyCondition := validateOrganizationsPolicy(&upstream.Spec.AllowAuthentication.Organizations)
	conditions = append(conditions, organizationPolicyCondition)

	hostCondition, apiHostPort := validateHost(upstream.Spec.GitHubAPI.Host)
	conditions = append(conditions, hostCondition)

	tlsConfigCondition, caBundle := tlsconfigutil.ValidateTLSConfig(
		tlsconfigutil.TLSSpecForSupervisor(upstream.Spec.GitHubAPI.TLS),
		"spec.githubAPI.tls",
		c.namespace,
		c.secretInformer,
		c.configMapInformer)
	conditions = append(conditions, tlsConfigCondition)

	githubConnectionCondition, httpClient, githubConnectionErr := c.validateGitHubConnection(
		apiHostPort,
		upstream.Spec.GitHubAPI.Host,
		caBundle,
		hostCondition.Status == metav1.ConditionTrue,
		tlsConfigCondition.Status == metav1.ConditionTrue,
	)
	if githubConnectionErr != nil {
		applicationErrors = append(applicationErrors, githubConnectionErr)
	}
	conditions = append(conditions, githubConnectionCondition)

	// The critical pattern to maintain is that every run of the sync loop will populate the exact number of the exact
	// same set of conditions.  Conditions depending on other conditions should get Status: metav1.ConditionUnknown, or
	// Status: metav1.ConditionFalse, never be omitted.
	if len(conditions) != countExpectedConditions { // untested since all code paths return the same number of conditions
		applicationErrors = append(applicationErrors, fmt.Errorf("expected %d conditions but found %d conditions", countExpectedConditions, len(conditions)))
		return nil, utilerrors.NewAggregate(applicationErrors)
	}
	hadErrorCondition, updateStatusErr := c.updateStatus(ctx.Context, upstream, conditions)
	if updateStatusErr != nil {
		applicationErrors = append(applicationErrors, updateStatusErr)
	}
	// Any error condition means we will not add the IDP to the cache, so just return nil here
	if hadErrorCondition {
		return nil, utilerrors.NewAggregate(applicationErrors)
	}

	oauthBaseURL := oauthBaseUrl(apiHostPort)

	provider := upstreamgithub.New(
		upstreamgithub.ProviderConfig{
			Name:               upstream.Name,
			ResourceUID:        upstream.UID,
			APIBaseURL:         apiBaseUrl(apiHostPort),
			GroupNameAttribute: groupNameAttribute,
			UsernameAttribute:  usernameAttribute,
			OAuth2Config: &oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
				// See https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps
				Endpoint: oauth2.Endpoint{
					AuthURL:       fmt.Sprintf("%s/authorize", oauthBaseURL),
					DeviceAuthURL: "", // we do not use device code flow
					TokenURL:      fmt.Sprintf("%s/access_token", oauthBaseURL),
					AuthStyle:     oauth2.AuthStyleInParams,
				},
				RedirectURL: "", // this will be different for each FederationDomain, so we do not set it here
				Scopes:      []string{"read:user", "read:org"},
			},
			AllowedOrganizations: setutil.NewCaseInsensitiveSet(upstream.Spec.AllowAuthentication.Organizations.Allowed...),
			HttpClient:           httpClient,
		},
	)
	return provider, utilerrors.NewAggregate(applicationErrors)
}

func apiBaseUrl(apiHostPort *endpointaddr.HostPort) string {
	endpoint := hostPortForHTTPS(apiHostPort)

	if strings.ToLower(apiHostPort.Host) == apiDotGithubDotCom {
		return fmt.Sprintf("https://%s", endpoint)
	}
	// URL for GitHub Enterprise Server's API.
	return fmt.Sprintf("https://%s/api/v3", endpoint)
}

func oauthBaseUrl(apiHostPort *endpointaddr.HostPort) string {
	var oauthHost string
	if strings.ToLower(apiHostPort.Host) == apiDotGithubDotCom {
		oauthHost = githubDotCom
	} else {
		// Base OAuth URL for GitHub Enterprise Server.
		oauthHost = hostPortForHTTPS(apiHostPort)
	}
	return fmt.Sprintf("https://%s/login/oauth", oauthHost)
}

func hostPortForHTTPS(apiHostPort *endpointaddr.HostPort) string {
	if apiHostPort.Port == 443 {
		// Remove the port specification from the host, because 443 is the default for HTTPS.
		return apiHostPort.Host
	}
	return apiHostPort.Endpoint()
}

func validateHost(specifiedHost *string) (*metav1.Condition, *endpointaddr.HostPort) {
	buildInvalidHost := func(host, reason string) *metav1.Condition {
		return &metav1.Condition{
			Type:    HostValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalidHost,
			Message: fmt.Sprintf("spec.githubAPI.host (%q) is not valid: %s", host, reason),
		}
	}

	// Should not happen due to CRD defaulting
	if specifiedHost == nil || len(*specifiedHost) < 1 {
		return buildInvalidHost("", "must not be empty"), nil
	}

	// First parse exactly what the user specified.
	hostPort, addressParseErr := endpointaddr.Parse(*specifiedHost, 443)
	if addressParseErr != nil {
		// addressParseErr is not recoverable. It requires user interaction, so do not return the error.
		return buildInvalidHost(*specifiedHost, addressParseErr.Error()), nil
	}

	// As a special case, if the user specified "github.com" or "api.github.com" with any port number,
	// then actually use "api.github.com" with the same port number. Use lowercased host internally for readability.
	if strings.ToLower(hostPort.Host) == githubDotCom || strings.ToLower(hostPort.Host) == apiDotGithubDotCom {
		hostPort.Host = apiDotGithubDotCom
	}

	return &metav1.Condition{
		Type:    HostValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: fmt.Sprintf("spec.githubAPI.host (%q) is valid", *specifiedHost),
	}, &hostPort
}

func (c *gitHubWatcherController) validateGitHubConnection(
	apiHostPort *endpointaddr.HostPort,
	specifiedHost *string,
	caBundle *tlsconfigutil.CABundle,
	hostConditionOk, tlsConfigConditionOk bool,
) (*metav1.Condition, *http.Client, error) {
	if !hostConditionOk || !tlsConfigConditionOk {
		return &metav1.Condition{
			Type:    GitHubConnectionValid,
			Status:  metav1.ConditionUnknown,
			Reason:  conditionsutil.ReasonUnableToValidate,
			Message: conditionsutil.MessageUnableToValidate,
		}, nil, nil
	}

	apiAddress := apiHostPort.Endpoint()

	if !c.validatedCache.IsValid(apiAddress, caBundle.Hash()) {
		tlsDialErr := c.dialer.IsReachableAndTLSValidationSucceeds(apiAddress, caBundle.CertPool(), c.log)
		if tlsDialErr != nil {
			return &metav1.Condition{
				Type:   GitHubConnectionValid,
				Status: metav1.ConditionFalse,
				Reason: conditionsutil.ReasonUnableToDialServer,
				Message: fmt.Sprintf("cannot dial %q for spec.githubAPI.host (%q): %s",
					apiAddress, *specifiedHost, buildDialErrorMessage(tlsDialErr)),
			}, nil, tlsDialErr
		}
	}

	c.validatedCache.MarkAsValidated(apiAddress, caBundle.Hash())

	return &metav1.Condition{
		Type:   GitHubConnectionValid,
		Status: metav1.ConditionTrue,
		Reason: conditionsutil.ReasonSuccess,
		Message: fmt.Sprintf("dialed %q for spec.githubAPI.host (%q): host is reachable and TLS verification succeeds",
			apiAddress, *specifiedHost),
	}, phttp.Default(caBundle.CertPool()), nil
}

// buildDialErrorMessage standardizes DNS error messages that appear differently on different platforms, so that tests and log grepping is uniform.
func buildDialErrorMessage(tlsDialErr error) string {
	reason := tlsDialErr.Error()

	var opError *net.OpError
	var dnsError *net.DNSError
	if errors.As(tlsDialErr, &opError) && errors.As(tlsDialErr, &dnsError) {
		dnsError.Server = ""
		opError.Err = dnsError
		return opError.Error()
	}

	return reason
}

func validateUserAndGroupAttributes(upstream *idpv1alpha1.GitHubIdentityProvider) (*metav1.Condition, idpv1alpha1.GitHubGroupNameAttribute, idpv1alpha1.GitHubUsernameAttribute) {
	buildInvalidCondition := func(message string) *metav1.Condition {
		return &metav1.Condition{
			Type:    ClaimsValid,
			Status:  metav1.ConditionFalse,
			Reason:  reasonInvalid,
			Message: message,
		}
	}

	var usernameAttribute idpv1alpha1.GitHubUsernameAttribute
	if upstream.Spec.Claims.Username == nil {
		return buildInvalidCondition("spec.claims.username is required"), "", ""
	} else {
		usernameAttribute = *upstream.Spec.Claims.Username
	}

	var groupNameAttribute idpv1alpha1.GitHubGroupNameAttribute
	if upstream.Spec.Claims.Groups == nil {
		return buildInvalidCondition("spec.claims.groups is required"), "", ""
	} else {
		groupNameAttribute = *upstream.Spec.Claims.Groups
	}

	switch usernameAttribute {
	case idpv1alpha1.GitHubUsernameLoginAndID:
	case idpv1alpha1.GitHubUsernameLogin:
	case idpv1alpha1.GitHubUsernameID:
	default:
		// Should not happen due to CRD enum validation
		return buildInvalidCondition(fmt.Sprintf("spec.claims.username (%q) is not valid", usernameAttribute)), "", ""
	}

	switch groupNameAttribute {
	case idpv1alpha1.GitHubUseTeamNameForGroupName:
	case idpv1alpha1.GitHubUseTeamSlugForGroupName:
	default:
		// Should not happen due to CRD enum validation
		return buildInvalidCondition(fmt.Sprintf("spec.claims.groups (%q) is not valid", groupNameAttribute)), "", ""
	}

	return &metav1.Condition{
		Type:    ClaimsValid,
		Status:  metav1.ConditionTrue,
		Reason:  conditionsutil.ReasonSuccess,
		Message: "spec.claims are valid",
	}, groupNameAttribute, usernameAttribute
}

func (c *gitHubWatcherController) updateStatus(
	ctx context.Context,
	upstream *idpv1alpha1.GitHubIdentityProvider,
	conditions []*metav1.Condition) (bool, error) {
	log := c.log.WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConditions(
		conditions,
		&updated.Status.Conditions,
		upstream.Generation,
		metav1.NewTime(c.clock.Now()),
		log,
	)

	updated.Status.Phase = idpv1alpha1.GitHubPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = idpv1alpha1.GitHubPhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return hadErrorCondition, nil
	}

	log.Info("updating GitHubIdentityProvider status", "phase", updated.Status.Phase)

	_, updateStatusError := c.client.
		IDPV1alpha1().
		GitHubIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return hadErrorCondition, updateStatusError
}
