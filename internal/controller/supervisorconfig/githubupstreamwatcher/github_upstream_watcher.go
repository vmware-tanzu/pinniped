// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package githubupstreamwatcher implements a controller which watches GitHubIdentityProviders.
package githubupstreamwatcher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"

	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	k8sapierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	errorsutil "k8s.io/apimachinery/pkg/util/errors"
	k8sutilerrors "k8s.io/apimachinery/pkg/util/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"
	"k8s.io/utils/clock"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/crypto/ptls"
	"go.pinniped.dev/internal/endpointaddr"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/upstreamgithub"
)

const (
	controllerName = "github-upstream-observer"

	// Constants related to the client credentials Secret.
	gitHubClientSecretType               corev1.SecretType = "secrets.pinniped.dev/github-client"
	clientIDDataKey, clientSecretDataKey string            = "clientID", "clientSecret"

	countExpectedConditions = 6

	HostValid                string = "HostValid"
	TLSConfigurationValid    string = "TLSConfigurationValid"
	OrganizationsPolicyValid string = "OrganizationsPolicyValid"
	// ClientCredentialsObtained is different from other status conditions because it only checks that the client credentials
	// have been obtained. The controller has no way to verify whether they are valid.
	ClientCredentialsObtained string = "ClientCredentialsObtained" //nolint:gosec // this is not a credential
	GitHubConnectionValid     string = "GitHubConnectionValid"
	ClaimsValid               string = "ClaimsValid"
)

// UpstreamGitHubIdentityProviderICache is a thread safe cache that holds a list of validated upstream GitHub IDP configurations.
type UpstreamGitHubIdentityProviderICache interface {
	SetGitHubIdentityProviders([]upstreamprovider.UpstreamGithubIdentityProviderI)
}

type gitHubWatcherController struct {
	namespace                      string
	cache                          UpstreamGitHubIdentityProviderICache
	log                            plog.Logger
	client                         supervisorclientset.Interface
	gitHubIdentityProviderInformer idpinformers.GitHubIdentityProviderInformer
	secretInformer                 corev1informers.SecretInformer
	clock                          clock.Clock
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamGitHubIdentityProviderICache.
func New(
	namespace string,
	idpCache UpstreamGitHubIdentityProviderICache,
	client supervisorclientset.Interface,
	gitHubIdentityProviderInformer idpinformers.GitHubIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	log plog.Logger,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
	clock clock.Clock,
) controllerlib.Controller {
	c := gitHubWatcherController{
		namespace:                      namespace,
		cache:                          idpCache,
		client:                         client,
		log:                            log.WithName(controllerName),
		gitHubIdentityProviderInformer: gitHubIdentityProviderInformer,
		secretInformer:                 secretInformer,
		clock:                          clock,
	}

	return controllerlib.New(
		controllerlib.Config{Name: controllerName, Syncer: &c},
		withInformer(
			gitHubIdentityProviderInformer,
			pinnipedcontroller.SimpleFilter(func(obj metav1.Object) bool {
				gitHubIDP, ok := obj.(*v1alpha1.GitHubIdentityProvider)
				return ok && gitHubIDP.Namespace == namespace
			}, pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypeFilter(gitHubClientSecretType, pinnipedcontroller.SingletonQueue(), namespace),
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
	slices.SortStableFunc(actualUpstreams, func(a, b *v1alpha1.GitHubIdentityProvider) int {
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

	return errorsutil.NewAggregate(applicationErrors)
}

func (c *gitHubWatcherController) validateClientSecret(secretName string) (*metav1.Condition, string, string, error) {
	secret, unableToRetrieveSecretErr := c.secretInformer.Lister().Secrets(c.namespace).Get(secretName)

	// This error requires user interaction, so ignore it.
	if k8sapierrors.IsNotFound(unableToRetrieveSecretErr) {
		unableToRetrieveSecretErr = nil
	}

	buildFalseCondition := func(prefix string) (*metav1.Condition, string, string, error) {
		return &metav1.Condition{
			Type:   ClientCredentialsObtained,
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
		Type:    ClientCredentialsObtained,
		Status:  metav1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: fmt.Sprintf("clientID and clientSecret have been read from spec.client.SecretName (%q)", secretName),
	}, clientID, clientSecret, nil
}

func validateOrganizationsPolicy(organizationsSpec *v1alpha1.GitHubOrganizationsSpec) (*metav1.Condition, v1alpha1.GitHubAllowedAuthOrganizationsPolicy) {
	var policy v1alpha1.GitHubAllowedAuthOrganizationsPolicy
	if organizationsSpec.Policy != nil {
		policy = *organizationsSpec.Policy
	}

	// Should not happen due to CRD defaulting, enum validation, and CEL validation (for recent versions of K8s only!)
	// That is why the message here is very minimal
	if (policy == v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers && len(organizationsSpec.Allowed) == 0) ||
		(policy == v1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations && len(organizationsSpec.Allowed) > 0) {
		return &metav1.Condition{
			Type:    OrganizationsPolicyValid,
			Status:  metav1.ConditionTrue,
			Reason:  upstreamwatchers.ReasonSuccess,
			Message: fmt.Sprintf("spec.allowAuthentication.organizations.policy (%q) is valid", policy),
		}, policy
	}

	if len(organizationsSpec.Allowed) > 0 {
		return &metav1.Condition{
			Type:    OrganizationsPolicyValid,
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid",
			Message: "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",
		}, policy
	}

	return &metav1.Condition{
		Type:    OrganizationsPolicyValid,
		Status:  metav1.ConditionFalse,
		Reason:  "Invalid",
		Message: "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
	}, policy
}

func (c *gitHubWatcherController) validateUpstreamAndUpdateConditions(ctx controllerlib.Context, upstream *v1alpha1.GitHubIdentityProvider) (
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

	organizationPolicyCondition, policy := validateOrganizationsPolicy(&upstream.Spec.AllowAuthentication.Organizations)
	conditions = append(conditions, organizationPolicyCondition)

	hostCondition, hostPort := validateHost(upstream.Spec.GitHubAPI)
	conditions = append(conditions, hostCondition)

	tlsConfigCondition, certPool := c.validateTLSConfiguration(upstream.Spec.GitHubAPI.TLS)
	conditions = append(conditions, tlsConfigCondition)

	githubConnectionCondition, hostURL, httpClient, githubConnectionErr := c.validateGitHubConnection(
		hostPort,
		certPool,
		hostCondition.Status == metav1.ConditionTrue && tlsConfigCondition.Status == metav1.ConditionTrue,
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
		return nil, k8sutilerrors.NewAggregate(applicationErrors)
	}
	hadErrorCondition, updateStatusErr := c.updateStatus(ctx.Context, upstream, conditions)
	if updateStatusErr != nil {
		applicationErrors = append(applicationErrors, updateStatusErr)
	}
	// Any error condition means we will not add the IDP to the cache, so just return nil here
	if hadErrorCondition {
		return nil, k8sutilerrors.NewAggregate(applicationErrors)
	}

	provider := upstreamgithub.New(
		upstreamgithub.ProviderConfig{
			Name:               upstream.Name,
			ResourceUID:        upstream.UID,
			Host:               hostURL,
			GroupNameAttribute: groupNameAttribute,
			UsernameAttribute:  usernameAttribute,
			OAuth2Config: &oauth2.Config{
				ClientID:     clientID,
				ClientSecret: clientSecret,
			},
			AllowedOrganizations:    upstream.Spec.AllowAuthentication.Organizations.Allowed,
			OrganizationLoginPolicy: policy,
			AuthorizationURL:        fmt.Sprintf("%s/login/oauth/authorize", hostURL),
			HttpClient:              httpClient,
		},
	)
	return provider, k8sutilerrors.NewAggregate(applicationErrors)
}

func validateHost(gitHubAPIConfig v1alpha1.GitHubAPIConfig) (*metav1.Condition, *endpointaddr.HostPort) {
	buildInvalidHost := func(host, reason string) *metav1.Condition {
		return &metav1.Condition{
			Type:    HostValid,
			Status:  metav1.ConditionFalse,
			Reason:  "InvalidHost",
			Message: fmt.Sprintf("spec.githubAPI.host (%q) is not valid: %s", host, reason),
		}
	}

	// Should not happen due to CRD defaulting
	if gitHubAPIConfig.Host == nil || len(*gitHubAPIConfig.Host) < 1 {
		return buildInvalidHost("", "must not be empty"), nil
	}

	host := *gitHubAPIConfig.Host
	hostPort, addressParseErr := endpointaddr.Parse(host, 443)
	if addressParseErr != nil {
		// addressParseErr is not recoverable. It requires user interaction, so do not return the error.
		return buildInvalidHost(host, addressParseErr.Error()), nil
	}

	return &metav1.Condition{
		Type:    HostValid,
		Status:  metav1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: fmt.Sprintf("spec.githubAPI.host (%q) is valid", host),
	}, &hostPort
}

func (c *gitHubWatcherController) validateTLSConfiguration(tlsSpec *v1alpha1.TLSSpec) (*metav1.Condition, *x509.CertPool) {
	certPool, _, buildCertPoolErr := pinnipedcontroller.BuildCertPoolIDP(tlsSpec)
	if buildCertPoolErr != nil {
		// buildCertPoolErr is not recoverable with a resync.
		// It requires user interaction, so do not return the error.
		return &metav1.Condition{
			Type:    TLSConfigurationValid,
			Status:  metav1.ConditionFalse,
			Reason:  "InvalidTLSConfig",
			Message: fmt.Sprintf("spec.githubAPI.tls.certificateAuthorityData is not valid: %s", buildCertPoolErr),
		}, nil
	}

	return &metav1.Condition{
		Type:    TLSConfigurationValid,
		Status:  metav1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: "spec.githubAPI.tls.certificateAuthorityData is valid",
	}, certPool
}

func (c *gitHubWatcherController) validateGitHubConnection(
	hostPort *endpointaddr.HostPort,
	certPool *x509.CertPool,
	validSoFar bool,
) (*metav1.Condition, string, *http.Client, error) {
	if !validSoFar {
		return &metav1.Condition{
			Type:    GitHubConnectionValid,
			Status:  metav1.ConditionUnknown,
			Reason:  "UnableToValidate",
			Message: "unable to validate; see other conditions for details",
		}, "", nil, nil
	}

	conn, tlsDialErr := tls.Dial("tcp", hostPort.Endpoint(), ptls.Default(certPool))
	if tlsDialErr != nil {
		return &metav1.Condition{
			Type:    GitHubConnectionValid,
			Status:  metav1.ConditionFalse,
			Reason:  "UnableToDialServer",
			Message: fmt.Sprintf("cannot dial server spec.githubAPI.host (%q): %s", hostPort.Endpoint(), buildDialErrorMessage(tlsDialErr)),
		}, "", nil, tlsDialErr
	}

	return &metav1.Condition{
		Type:    GitHubConnectionValid,
		Status:  metav1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: fmt.Sprintf("spec.githubAPI.host (%q) is reachable and TLS verification succeeds", hostPort.Endpoint()),
	}, fmt.Sprintf("https://%s", hostPort.Endpoint()), phttp.Default(certPool), conn.Close()
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

func validateUserAndGroupAttributes(upstream *v1alpha1.GitHubIdentityProvider) (*metav1.Condition, v1alpha1.GitHubGroupNameAttribute, v1alpha1.GitHubUsernameAttribute) {
	buildInvalidCondition := func(message string) *metav1.Condition {
		return &metav1.Condition{
			Type:    ClaimsValid,
			Status:  metav1.ConditionFalse,
			Reason:  "Invalid",
			Message: message,
		}
	}

	var usernameAttribute v1alpha1.GitHubUsernameAttribute
	if upstream.Spec.Claims.Username == nil {
		return buildInvalidCondition("spec.claims.username is required"), "", ""
	} else {
		usernameAttribute = *upstream.Spec.Claims.Username
	}

	var groupNameAttribute v1alpha1.GitHubGroupNameAttribute
	if upstream.Spec.Claims.Groups == nil {
		return buildInvalidCondition("spec.claims.groups is required"), "", ""
	} else {
		groupNameAttribute = *upstream.Spec.Claims.Groups
	}

	switch usernameAttribute {
	case v1alpha1.GitHubUsernameLoginAndID:
	case v1alpha1.GitHubUsernameLogin:
	case v1alpha1.GitHubUsernameID:
	default:
		// Should not happen due to CRD enum validation
		return buildInvalidCondition(fmt.Sprintf("spec.claims.username (%q) is not valid", usernameAttribute)), "", ""
	}

	switch groupNameAttribute {
	case v1alpha1.GitHubUseTeamNameForGroupName:
	case v1alpha1.GitHubUseTeamSlugForGroupName:
	default:
		// Should not happen due to CRD enum validation
		return buildInvalidCondition(fmt.Sprintf("spec.claims.groups (%q) is not valid", groupNameAttribute)), "", ""
	}

	return &metav1.Condition{
		Type:    ClaimsValid,
		Status:  metav1.ConditionTrue,
		Reason:  upstreamwatchers.ReasonSuccess,
		Message: "spec.claims are valid",
	}, groupNameAttribute, usernameAttribute
}

func (c *gitHubWatcherController) updateStatus(
	ctx context.Context,
	upstream *v1alpha1.GitHubIdentityProvider,
	conditions []*metav1.Condition) (bool, error) {
	log := c.log.WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConditions(
		conditions,
		upstream.Generation,
		&updated.Status.Conditions,
		log,
		metav1.NewTime(c.clock.Now()),
	)

	updated.Status.Phase = v1alpha1.GitHubPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = v1alpha1.GitHubPhaseError
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
