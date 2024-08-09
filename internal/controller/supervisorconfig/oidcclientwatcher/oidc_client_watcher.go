// Copyright 2022-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package oidcclientwatcher

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	corev1informers "k8s.io/client-go/informers/core/v1"

	supervisorconfigv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
	oidcapi "go.pinniped.dev/generated/latest/apis/supervisor/oidc"
	supervisorclientset "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned"
	configInformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions/config/v1alpha1"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/oidcclientvalidator"
	"go.pinniped.dev/internal/oidcclientsecretstorage"
	"go.pinniped.dev/internal/plog"
)

const (
	secretTypeToObserve       = "storage.pinniped.dev/oidc-client-secret" //nolint:gosec // this is not a credential
	oidcClientPrefixToObserve = oidcapi.ClientIDRequiredOIDCClientPrefix
)

type oidcClientWatcherController struct {
	pinnipedClient     supervisorclientset.Interface
	oidcClientInformer configInformers.OIDCClientInformer
	secretInformer     corev1informers.SecretInformer
}

// NewOIDCClientWatcherController returns a controllerlib.Controller that watches OIDCClients and updates
// their status with validation errors.
func NewOIDCClientWatcherController(
	pinnipedClient supervisorclientset.Interface,
	secretInformer corev1informers.SecretInformer,
	oidcClientInformer configInformers.OIDCClientInformer,
	withInformer pinnipedcontroller.WithInformerOptionFunc,
) controllerlib.Controller {
	return controllerlib.New(
		controllerlib.Config{
			Name: "OIDCClientWatcherController",
			Syncer: &oidcClientWatcherController{
				pinnipedClient:     pinnipedClient,
				secretInformer:     secretInformer,
				oidcClientInformer: oidcClientInformer,
			},
		},
		// We want to be notified when an OIDCClient's corresponding secret gets updated or deleted.
		withInformer(
			secretInformer,
			pinnipedcontroller.MatchAnySecretOfTypeFilter(secretTypeToObserve, pinnipedcontroller.SingletonQueue()),
			controllerlib.InformerOption{},
		),
		// We want to be notified when anything happens to an OIDCClient.
		withInformer(
			oidcClientInformer,
			pinnipedcontroller.SimpleFilterWithSingletonQueue(func(obj metav1.Object) bool {
				return strings.HasPrefix(obj.GetName(), oidcClientPrefixToObserve)
			}),
			controllerlib.InformerOption{},
		),
	)
}

// Sync implements controllerlib.Syncer.
func (c *oidcClientWatcherController) Sync(ctx controllerlib.Context) error {
	// Sync could be called on either a Secret or an OIDCClient, so to keep it simple, revalidate
	// all OIDCClients whenever anything changes.
	oidcClients, err := c.oidcClientInformer.Lister().List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list OIDCClients: %w", err)
	}

	// We're only going to use storage to call GetName(), which happens to not need the constructor params.
	// This is because we can read the Secrets from the informer cache here, instead of doing live reads.
	storage := oidcclientsecretstorage.New(nil)

	for _, oidcClient := range oidcClients {
		// Skip the OIDCClients that we are not trying to observe.
		if !strings.HasPrefix(oidcClient.Name, oidcClientPrefixToObserve) {
			continue
		}

		correspondingSecretName := storage.GetName(oidcClient.UID)

		secret, err := c.secretInformer.Lister().Secrets(oidcClient.Namespace).Get(correspondingSecretName)
		if err != nil {
			if !apierrors.IsNotFound(err) {
				// Anything other than a NotFound error is unexpected when reading from an informer.
				return fmt.Errorf("failed to get %s/%s secret: %w", oidcClient.Namespace, correspondingSecretName, err)
			}
			// Got a NotFound error, so continue. The Secret just doesn't exist yet, which is okay.
			plog.DebugErr(
				"OIDCClientWatcherController error getting storage Secret for OIDCClient's client secrets", err,
				"oidcClientName", oidcClient.Name,
				"oidcClientNamespace", oidcClient.Namespace,
				"secretName", correspondingSecretName,
			)
			secret = nil
		}

		_, conditions, clientSecrets := oidcclientvalidator.Validate(oidcClient, secret, oidcclientvalidator.DefaultMinBcryptCost)

		if err := c.updateStatus(ctx.Context, oidcClient, conditions, len(clientSecrets)); err != nil {
			return fmt.Errorf("cannot update OIDCClient '%s/%s': %w", oidcClient.Namespace, oidcClient.Name, err)
		}

		plog.Debug(
			"OIDCClientWatcherController Sync updated an OIDCClient",
			"oidcClientName", oidcClient.Name,
			"oidcClientNamespace", oidcClient.Namespace,
			"conditionsCount", len(conditions),
		)
	}

	return nil
}

func (c *oidcClientWatcherController) updateStatus(
	ctx context.Context,
	upstream *supervisorconfigv1alpha1.OIDCClient,
	conditions []*metav1.Condition,
	totalClientSecrets int,
) error {
	updated := upstream.DeepCopy()

	hadErrorCondition := conditionsutil.MergeConditions(
		conditions,
		&updated.Status.Conditions,
		upstream.Generation,
		metav1.Now(),
		plog.New(),
	)

	updated.Status.Phase = supervisorconfigv1alpha1.OIDCClientPhaseReady
	if hadErrorCondition {
		updated.Status.Phase = supervisorconfigv1alpha1.OIDCClientPhaseError
	}

	updated.Status.TotalClientSecrets = int32(totalClientSecrets)

	if equality.Semantic.DeepEqual(upstream, updated) {
		return nil
	}

	_, err := c.pinnipedClient.
		ConfigV1alpha1().
		OIDCClients(upstream.Namespace).
		UpdateStatus(ctx, updated, metav1.UpdateOptions{})
	return err
}
