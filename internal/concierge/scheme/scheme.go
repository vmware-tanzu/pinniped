// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scheme contains code to construct a proper runtime.Scheme for the Concierge aggregated
// API.
package scheme

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	loginapi "go.pinniped.dev/generated/1.20/apis/concierge/login"
	loginv1alpha1 "go.pinniped.dev/generated/1.20/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/groupsuffix"
	"go.pinniped.dev/internal/plog"
)

// New returns a runtime.Scheme for use by the Concierge aggregated API. The provided
// loginConciergeAPIGroup should be the API group that the Concierge is serving (e.g.,
// login.concierge.pinniped.dev, login.concierge.walrus.tld, etc.). The provided apiGroupSuffix is
// the API group suffix of the provided loginConciergeAPIGroup (e.g., pinniped.dev, walrus.tld,
// etc.).
func New(loginConciergeAPIGroup, apiGroupSuffix string) *runtime.Scheme {
	// standard set up of the server side scheme
	scheme := runtime.NewScheme()

	// add the options to empty v1
	metav1.AddToGroupVersion(scheme, metav1.Unversioned)

	// nothing fancy is required if using the standard group
	if loginConciergeAPIGroup == loginv1alpha1.GroupName {
		utilruntime.Must(loginv1alpha1.AddToScheme(scheme))
		utilruntime.Must(loginapi.AddToScheme(scheme))
		return scheme
	}

	// we need a temporary place to register our types to avoid double registering them
	tmpScheme := runtime.NewScheme()
	utilruntime.Must(loginv1alpha1.AddToScheme(tmpScheme))
	utilruntime.Must(loginapi.AddToScheme(tmpScheme))

	for gvk := range tmpScheme.AllKnownTypes() {
		if gvk.GroupVersion() == metav1.Unversioned {
			continue // metav1.AddToGroupVersion registers types outside of our aggregated API group that we need to ignore
		}

		if gvk.Group != loginv1alpha1.GroupName {
			panic("tmp scheme has types not in the aggregated API group: " + gvk.Group) // programmer error
		}

		obj, err := tmpScheme.New(gvk)
		if err != nil {
			panic(err) // programmer error, scheme internal code is broken
		}
		newGVK := schema.GroupVersionKind{
			Group:   loginConciergeAPIGroup,
			Version: gvk.Version,
			Kind:    gvk.Kind,
		}

		// register the existing type but with the new group in the correct scheme
		scheme.AddKnownTypeWithName(newGVK, obj)
	}

	// manually register conversions and defaulting into the correct scheme since we cannot directly call loginv1alpha1.AddToScheme
	utilruntime.Must(loginv1alpha1.RegisterConversions(scheme))
	utilruntime.Must(loginv1alpha1.RegisterDefaults(scheme))

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

	return scheme
}
