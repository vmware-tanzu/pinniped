// Copyright 2022 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scheme contains code to construct a proper runtime.Scheme for the Concierge aggregated
// API.
package scheme

import (
	"fmt"

	oauthapi "go.pinniped.dev/generated/latest/apis/supervisor/virtual/oauth"
	oauthv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/virtual/oauth/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"go.pinniped.dev/internal/groupsuffix"
)

// New returns a runtime.Scheme for use by the Supervisor aggregated API running with the provided
// apiGroupSuffix.
func New(apiGroupSuffix string) (_ *runtime.Scheme, oauth schema.GroupVersion) {
	// standard set up of the server side scheme
	scheme := runtime.NewScheme()

	// add the options to empty v1
	metav1.AddToGroupVersion(scheme, metav1.Unversioned)

	// nothing fancy is required if using the standard group suffix
	if apiGroupSuffix == groupsuffix.PinnipedDefaultSuffix {
		schemeBuilder := runtime.NewSchemeBuilder(
			oauthv1alpha1.AddToScheme,
			oauthapi.AddToScheme,
		)
		utilruntime.Must(schemeBuilder.AddToScheme(scheme))
		return scheme, oauthv1alpha1.SchemeGroupVersion
	}

	oauthVirtualSupervisorGroupData := groupsuffix.SupervisorAggregatedGroups(apiGroupSuffix)

	addToSchemeAtNewGroup(scheme, oauthv1alpha1.GroupName, oauthVirtualSupervisorGroupData.Group, oauthv1alpha1.AddToScheme, oauthapi.AddToScheme)

	// manually register conversions and defaulting into the correct scheme since we cannot directly call AddToScheme
	schemeBuilder := runtime.NewSchemeBuilder(
		oauthv1alpha1.RegisterConversions,
		oauthv1alpha1.RegisterDefaults,
	)
	utilruntime.Must(schemeBuilder.AddToScheme(scheme))

	// we do not have any defaulting functions for *loginv1alpha1.OIDCClientSecretRequest
	// today, but we may have some in the future.  Calling AddTypeDefaultingFunc overwrites
	// any previously registered defaulting function.  Thus to make sure that we catch
	// a situation where we add a defaulting func, we attempt to call it here with a nil
	// *oauthv1alpha1.OIDCClientSecretRequest.  This will do nothing when there is no
	// defaulting func registered, but it will almost certainly panic if one is added.
	scheme.Default((*oauthv1alpha1.OIDCClientSecretRequest)(nil))

	return scheme, schema.GroupVersion(oauthVirtualSupervisorGroupData)
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
