// Copyright 2020-2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	apiregistrationv1 "k8s.io/kube-aggregator/pkg/apis/apiregistration/v1"

	conciergeconfigv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/config/v1alpha1"
	supervisorconfigv1alpha1 "go.pinniped.dev/generated/1.20/apis/supervisor/config/v1alpha1"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/ownerref"
	"go.pinniped.dev/test/library"
)

func TestKubeClientOwnerRef(t *testing.T) {
	env := library.IntegrationEnv(t)

	regularClient := library.NewClientset(t)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	namespaces := regularClient.CoreV1().Namespaces()

	namespace, err := namespaces.Create(
		ctx,
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "test-owner-ref-"}},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)

	defer func() {
		if t.Failed() {
			return
		}
		err := namespaces.Delete(ctx, namespace.Name, metav1.DeleteOptions{})
		require.NoError(t, err)
	}()

	// create something that we can point to
	parentSecret, err := regularClient.CoreV1().Secrets(namespace.Name).Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "parent-",
				OwnerReferences: nil, // no owner refs set
			},
			Data: map[string][]byte{"A": []byte("B")},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	require.Len(t, parentSecret.OwnerReferences, 0)

	// create a client that should set an owner ref back to parent on create
	ref := metav1.OwnerReference{
		APIVersion: "v1",
		Kind:       "Secret",
		Name:       parentSecret.Name,
		UID:        parentSecret.UID,
	}
	ownerRefClient, err := kubeclient.New(
		kubeclient.WithMiddleware(ownerref.New(ref)),
		kubeclient.WithConfig(library.NewClientConfig(t)),
	)
	require.NoError(t, err)

	ownerRefSecrets := ownerRefClient.Kubernetes.CoreV1().Secrets(namespace.Name)

	// we expect this secret to have the owner ref set even though we did not set it explicitly
	childSecret, err := ownerRefSecrets.Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "child-",
				OwnerReferences: nil, // no owner refs set
			},
			Data: map[string][]byte{"C": []byte("D")},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	hasOwnerRef(t, childSecret, ref)

	preexistingRef := *ref.DeepCopy()
	preexistingRef.Name = "different"
	preexistingRef.UID = "different"

	// we expect this secret to keep the owner ref that is was created with
	otherSecret, err := ownerRefSecrets.Create(
		ctx,
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "child-",
				OwnerReferences: []metav1.OwnerReference{preexistingRef}, // owner ref set explicitly
			},
			Data: map[string][]byte{"C": []byte("D")},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	hasOwnerRef(t, otherSecret, preexistingRef)
	require.NotEqual(t, ref, preexistingRef)
	// the secret has no owner so it should be immediately deleted
	isEventuallyDeleted(t, func() error {
		_, err := ownerRefSecrets.Get(ctx, otherSecret.Name, metav1.GetOptions{})
		return err
	})

	// we expect no owner ref to be set on update
	parentSecretUpdate := parentSecret.DeepCopy()
	parentSecretUpdate.Data = map[string][]byte{"E": []byte("F ")}
	updatedParentSecret, err := ownerRefSecrets.Update(ctx, parentSecretUpdate, metav1.UpdateOptions{})
	require.NoError(t, err)
	require.Equal(t, parentSecret.UID, updatedParentSecret.UID)
	require.NotEqual(t, parentSecret.ResourceVersion, updatedParentSecret.ResourceVersion)
	require.Len(t, updatedParentSecret.OwnerReferences, 0)

	// delete the parent object
	err = ownerRefSecrets.Delete(ctx, parentSecret.Name, metav1.DeleteOptions{})
	require.NoError(t, err)

	// the child object should be cleaned up on its own
	isEventuallyDeleted(t, func() error {
		_, err := ownerRefSecrets.Get(ctx, childSecret.Name, metav1.GetOptions{})
		return err
	})

	// TODO: update middleware code to not set owner references on cluster-scoped objects.
	//
	// The Kube 1.20 garbage collector asserts some new behavior in regards to invalid owner
	// references (i.e., when you have a namespace-scoped owner references for a cluster-scoped
	// dependent, the cluster-scoped dependent is not removed). We also found a bug in the 1.20
	// garbage collector where namespace-scoped dependents are not garbage collected if their owner
	// had been used as an invalid owner reference before - this bug causes our test to fallover
	// because we are setting a namespace-scoped owner ref on this APIService.
	//
	// We believe that the best way to get around this problem is to update our kubeclient code to
	// never set owner references on cluster-scoped objects. After we do that, we will uncomment this
	// part of the test.
	if false {
		// sanity check API service client
		apiService, err := ownerRefClient.Aggregation.ApiregistrationV1().APIServices().Create(
			ctx,
			&apiregistrationv1.APIService{
				ObjectMeta: metav1.ObjectMeta{
					Name:            "v1.pandas.dev",
					OwnerReferences: nil, // no owner refs set
				},
				Spec: apiregistrationv1.APIServiceSpec{
					Version:              "v1",
					Group:                "pandas.dev",
					GroupPriorityMinimum: 10_000,
					VersionPriority:      500,
				},
			},
			metav1.CreateOptions{},
		)
		require.NoError(t, err)
		hasOwnerRef(t, apiService, ref)
		// this owner ref is invalid for an API service so it should be immediately deleted
		isEventuallyDeleted(t, func() error {
			_, err := ownerRefClient.Aggregation.ApiregistrationV1().APIServices().Get(ctx, apiService.Name, metav1.GetOptions{})
			return err
		})
	}

	// sanity check concierge client
	credentialIssuer, err := ownerRefClient.PinnipedConcierge.ConfigV1alpha1().CredentialIssuers(namespace.Name).Create(
		ctx,
		&conciergeconfigv1alpha1.CredentialIssuer{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "owner-ref-test-",
				OwnerReferences: nil, // no owner refs set
			},
			Status: conciergeconfigv1alpha1.CredentialIssuerStatus{
				Strategies: []conciergeconfigv1alpha1.CredentialIssuerStrategy{},
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	hasOwnerRef(t, credentialIssuer, ref)
	// this owner has already been deleted so the cred issuer should be immediately deleted
	isEventuallyDeleted(t, func() error {
		_, err := ownerRefClient.PinnipedConcierge.ConfigV1alpha1().CredentialIssuers(namespace.Name).Get(ctx, credentialIssuer.Name, metav1.GetOptions{})
		return err
	})

	// sanity check supervisor client
	federationDomain, err := ownerRefClient.PinnipedSupervisor.ConfigV1alpha1().FederationDomains(namespace.Name).Create(
		ctx,
		&supervisorconfigv1alpha1.FederationDomain{
			ObjectMeta: metav1.ObjectMeta{
				GenerateName:    "owner-ref-test-",
				OwnerReferences: nil, // no owner refs set
			},
			Spec: supervisorconfigv1alpha1.FederationDomainSpec{
				Issuer: "https://pandas.dev",
			},
		},
		metav1.CreateOptions{},
	)
	require.NoError(t, err)
	hasOwnerRef(t, federationDomain, ref)
	// this owner has already been deleted so the federation domain should be immediately deleted
	isEventuallyDeleted(t, func() error {
		_, err := ownerRefClient.PinnipedSupervisor.ConfigV1alpha1().FederationDomains(namespace.Name).Get(ctx, federationDomain.Name, metav1.GetOptions{})
		return err
	})

	// check some well-known, always created secrets to make sure they have an owner ref back to their deployment

	dref := metav1.OwnerReference{}
	dref.APIVersion, dref.Kind = appsv1.SchemeGroupVersion.WithKind("Deployment").ToAPIVersionAndKind()

	supervisorDeployment, err := ownerRefClient.Kubernetes.AppsV1().Deployments(env.SupervisorNamespace).Get(ctx, env.SupervisorAppName, metav1.GetOptions{})
	require.NoError(t, err)

	supervisorKey, err := ownerRefClient.Kubernetes.CoreV1().Secrets(env.SupervisorNamespace).Get(ctx, env.SupervisorAppName+"-key", metav1.GetOptions{})
	require.NoError(t, err)

	supervisorDref := *dref.DeepCopy()
	supervisorDref.Name = env.SupervisorAppName
	supervisorDref.UID = supervisorDeployment.UID
	hasOwnerRef(t, supervisorKey, supervisorDref)

	conciergeDeployment, err := ownerRefClient.Kubernetes.AppsV1().Deployments(env.ConciergeNamespace).Get(ctx, env.ConciergeAppName, metav1.GetOptions{})
	require.NoError(t, err)

	conciergeCert, err := ownerRefClient.Kubernetes.CoreV1().Secrets(env.ConciergeNamespace).Get(ctx, env.ConciergeAppName+"-api-tls-serving-certificate", metav1.GetOptions{})
	require.NoError(t, err)

	conciergeDref := *dref.DeepCopy()
	conciergeDref.Name = env.ConciergeAppName
	conciergeDref.UID = conciergeDeployment.UID
	hasOwnerRef(t, conciergeCert, conciergeDref)
}

func hasOwnerRef(t *testing.T, obj metav1.Object, ref metav1.OwnerReference) {
	t.Helper()

	ownerReferences := obj.GetOwnerReferences()
	require.Len(t, ownerReferences, 1)
	require.Equal(t, ref, ownerReferences[0])
}

func isEventuallyDeleted(t *testing.T, f func() error) {
	t.Helper()

	library.RequireEventuallyWithoutError(t, func() (bool, error) {
		err := f()
		switch {
		case err == nil:
			return false, nil
		case errors.IsNotFound(err):
			return true, nil
		default:
			return false, err
		}
	}, time.Minute, time.Second)
}
