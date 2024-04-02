// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package githubupstreamwatcher implements a controller which watches GitHubIdentityProviders.
package githubupstreamwatcher

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	errorsutil "k8s.io/apimachinery/pkg/util/errors"
	corev1informers "k8s.io/client-go/informers/core/v1"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	idpinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/idp/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/upstreamgithub"
)

const (
	// Setup for the name of our controller in logs.
	controllerName = "github-upstream-observer"

	// Constants related to the client credentials Secret.
	gitHubClientSecretType corev1.SecretType = "secrets.pinniped.dev/github-client"

	//
	// clientIDDataKey     = "clientID"
	// clientSecretDataKey = "clientSecret"
	//
	// // Constants related to conditions.
	// typeClientCredentialsValid = "ClientCredentialsValid" //nolint:gosec // this is not a credential.
)

// UpstreamGitHubIdentityProviderICache is a thread safe cache that holds a list of validated upstream GitHub IDP configurations.
type UpstreamGitHubIdentityProviderICache interface {
	SetGitHubIdentityProviders([]upstreamprovider.UpstreamGithubIdentityProviderI)
}

type gitHubWatcherController struct {
	cache                          UpstreamGitHubIdentityProviderICache
	log                            plog.Logger
	client                         supervisorclientset.Interface
	gitHubIdentityProviderInformer idpinformers.GitHubIdentityProviderInformer
	secretInformer                 corev1informers.SecretInformer
}

// New instantiates a new controllerlib.Controller which will populate the provided UpstreamGitHubIdentityProviderICache.
func New(
	idpCache UpstreamGitHubIdentityProviderICache,
	client supervisorclientset.Interface,
	gitHubIdentityProviderInformer idpinformers.GitHubIdentityProviderInformer,
	secretInformer corev1informers.SecretInformer,
	log plog.Logger,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	c := gitHubWatcherController{
		cache:                          idpCache,
		client:                         client,
		log:                            log.WithName(controllerName),
		gitHubIdentityProviderInformer: gitHubIdentityProviderInformer,
		secretInformer:                 secretInformer,
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
			pinnipedcontroller.MatchAnySecretOfTypeFilter(gitHubClientSecretType, pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *gitHubWatcherController) Sync(ctx controllerlib.Context) error {
	actualUpstreams, err := c.gitHubIdentityProviderInformer.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list GitHubIdentityProviders: %w", err)
	}

	var errs []error

	requeue := false
	validatedUpstreams := make([]upstreamprovider.UpstreamGithubIdentityProviderI, 0, len(actualUpstreams))
	for _, upstream := range actualUpstreams {
		valid, err := c.validateUpstream(ctx, upstream)
		if valid == nil {
			requeue = true
			errs = append(errs, err)
		} else {
			validatedUpstreams = append(validatedUpstreams, upstreamprovider.UpstreamGithubIdentityProviderI(valid))
		}
	}
	c.cache.SetGitHubIdentityProviders(validatedUpstreams)
	if requeue {
		return controllerlib.ErrSyntheticRequeue
	}

	// Sync loop errors:
	// - Should not be configuration errors. Config errors a user must correct belong on the .Status
	//   object. The controller simply must wait for a user to correct before running again.
	// - Other errors, such as networking errors, etc. are the types of errors that should return here
	//   and signal the controller to retry the sync loop. These may be corrected by machines.
	return errorsutil.NewAggregate(errs)
}

func (c *gitHubWatcherController) validateUpstream(ctx controllerlib.Context, upstream *v1alpha1.GitHubIdentityProvider) (*upstreamgithub.ProviderConfig, error) {
	result := upstreamgithub.ProviderConfig{
		Name: upstream.Name,
	}

	// TODO: once we firm up the proposal doc & merge, then firm up the CRD & merge, we can fill out these validations.
	// The critical pattern to maintain is that every run of the sync loop will populate the exact number of the exact
	// same set of conditions.  Conditions depending on other conditions should get Status:  metav1.ConditionUnknown, or
	// Status:  metav1.ConditionFalse, never be omitted.
	conditions := []*metav1.Condition{
		// we may opt to split this up into smaller validation functions.
		// Each function should be responsible for validating one logical unit and setting one condition.
		// c.validateGitHubAPI(),
		// c.validateClaims(),
		// c.validateAllowedAuthentication(),
		// c.validateClient(),
	}

	err := c.updateStatus(ctx.Context, upstream, conditions)
	return &result, err
}

func (c *gitHubWatcherController) updateStatus(
	ctx context.Context,
	upstream *v1alpha1.GitHubIdentityProvider,
	conditions []*metav1.Condition) error {
	log := c.log.WithValues("namespace", upstream.Namespace, "name", upstream.Name)
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeIDPConditions(conditions, upstream.Generation, &updated.Status.Conditions, log)

	updated.Status.Phase = v1alpha1.GitHubPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = v1alpha1.GitHubPhaseError
	}

	if equality.Semantic.DeepEqual(upstream, updated) {
		return nil
	}

	_, err := c.client.
		IDPV1alpha1().
		GitHubIdentityProviders(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}
