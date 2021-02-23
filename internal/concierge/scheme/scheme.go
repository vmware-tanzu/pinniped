// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scheme contains code to construct a proper runtime.Scheme for the Concierge aggregated
// API.
package scheme

import (
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	identityapi "go.pinniped.dev/generated/latest/apis/concierge/identity"
	identityv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/identity/v1alpha1"
	loginapi "go.pinniped.dev/generated/latest/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
)

// New returns a runtime.Scheme for use by the Concierge aggregated API running with the provided
// apiGroupSuffix.
func New(apiGroupSuffix string) (_ *runtime.Scheme, login, identity schema.GroupVersion) {
	// standard set up of the server side scheme
	scheme := runtime.NewScheme()

	// add the options to empty v1
	metav1.AddToGroupVersion(scheme, metav1.Unversioned)

	// nothing fancy is required if using the standard group suffix
	if apiGroupSuffix == groupsuffix.PinnipedDefaultSuffix {
		schemeBuilder := runtime.NewSchemeBuilder(
			loginv1alpha1.AddToScheme,
			loginapi.AddToScheme,
			identityv1alpha1.AddToScheme,
			identityapi.AddToScheme,
		)
		utilruntime.Must(schemeBuilder.AddToScheme(scheme))
		return scheme, loginv1alpha1.SchemeGroupVersion, identityv1alpha1.SchemeGroupVersion
	}

	loginConciergeGroupData, identityConciergeGroupData := groupsuffix.ConciergeAggregatedGroups(apiGroupSuffix)

	addToSchemeAtNewGroup(scheme, loginv1alpha1.GroupName, loginConciergeGroupData.Group, loginv1alpha1.AddToScheme, loginapi.AddToScheme)
	addToSchemeAtNewGroup(scheme, identityv1alpha1.GroupName, identityConciergeGroupData.Group, identityv1alpha1.AddToScheme, identityapi.AddToScheme)

	// manually register conversions and defaulting into the correct scheme since we cannot directly call AddToScheme
	schemeBuilder := runtime.NewSchemeBuilder(
		loginv1alpha1.RegisterConversions,
		loginv1alpha1.RegisterDefaults,
		identityv1alpha1.RegisterConversions,
		identityv1alpha1.RegisterDefaults,
	)
	utilruntime.Must(schemeBuilder.AddToScheme(scheme))

	// we do not want to return errors from the scheme and instead would prefer to defer
	// to the REST storage layer for consistency.  The simplest way to do this is to force
	// a cache miss from the authenticator cache.  Kube API groups are validated via the
	// IsDNS1123Subdomain func thus we can easily create a group that is guaranteed never
	// to be in the authenticator cache.  Add a timestamp just to be extra sure.
	const authenticatorCacheMissPrefix = "_INVALID_API_GROUP_"
	authenticatorCacheMiss := authenticatorCacheMissPrefix + time.Now().UTC().String()

	// we do not have any defaulting functions for *loginv1alpha1.TokenCredentialRequest
	// today, but we may have some in the future.  Calling AddTypeDefaultingFunc overwrites
	// any previously registered defaulting function.  Thus to make sure that we catch
	// a situation where we add a defaulting func, we attempt to call it here with a nil
	// *loginv1alpha1.TokenCredentialRequest.  This will do nothing when there is no
	// defaulting func registered, but it will almost certainly panic if one is added.
	scheme.Default((*loginv1alpha1.TokenCredentialRequest)(nil))

	// on incoming requests, restore the authenticator API group to the standard group
	// note that we are responsible for duplicating this logic for every external API version
	scheme.AddTypeDefaultingFunc(&loginv1alpha1.TokenCredentialRequest{}, func(obj interface{}) {
		credentialRequest := obj.(*loginv1alpha1.TokenCredentialRequest)

		if credentialRequest.Spec.Authenticator.APIGroup == nil {
			// force a cache miss because this is an invalid request
			plog.Debug("invalid token credential request, nil group", "authenticator", credentialRequest.Spec.Authenticator)
			credentialRequest.Spec.Authenticator.APIGroup = &authenticatorCacheMiss
			return
		}

		restoredGroup, ok := groupsuffix.Unreplace(*credentialRequest.Spec.Authenticator.APIGroup, apiGroupSuffix)
		if !ok {
			// force a cache miss because this is an invalid request
			plog.Debug("invalid token credential request, wrong group", "authenticator", credentialRequest.Spec.Authenticator)
			credentialRequest.Spec.Authenticator.APIGroup = &authenticatorCacheMiss
			return
		}

		credentialRequest.Spec.Authenticator.APIGroup = &restoredGroup
	})

	return scheme, schema.GroupVersion(loginConciergeGroupData), schema.GroupVersion(identityConciergeGroupData)
}

func addToSchemeAtNewGroup(scheme *runtime.Scheme, oldGroup, newGroup string, funcs ...func(*runtime.Scheme) error) {
	// we need a temporary place to register our types to avoid double registering them
	tmpScheme := runtime.NewScheme()
	schemeBuilder := runtime.NewSchemeBuilder(funcs...)
	utilruntime.Must(schemeBuilder.AddToScheme(tmpScheme))

	for gvk := range tmpScheme.AllKnownTypes() {
		if gvk.GroupVersion() == metav1.Unversioned {
			continue // metav1.AddToGroupVersion registers types outside of our aggregated API group that we need to ignore
		}

		if gvk.Group != oldGroup {
			panic(fmt.Errorf("tmp scheme has type not in the old aggregated API group %s: %s", oldGroup, gvk)) // programmer error
		}

		obj, err := tmpScheme.New(gvk)
		if err != nil {
			panic(err) // programmer error, scheme internal code is broken
		}
		newGVK := schema.GroupVersionKind{
			Group:   newGroup,
			Version: gvk.Version,
			Kind:    gvk.Kind,
		}

		// register the existing type but with the new group in the correct scheme
		scheme.AddKnownTypeWithName(newGVK, obj)
	}
}
