// Copyright 2021 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package groupsuffix

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apimachinery/pkg/util/validation"

	loginv1alpha1 "go.pinniped.dev/generated/latest/apis/concierge/login/v1alpha1"
	"go.pinniped.dev/internal/constable"
	"go.pinniped.dev/internal/kubeclient"
	"go.pinniped.dev/internal/plog"
)

const (
	PinnipedDefaultSuffix        = "pinniped.dev"
	pinnipedDefaultSuffixWithDot = ".pinniped.dev"
)

func New(apiGroupSuffix string) kubeclient.Middleware {
	// return a no-op middleware by default
	if len(apiGroupSuffix) == 0 || apiGroupSuffix == PinnipedDefaultSuffix {
		return nil
	}

	return kubeclient.Middlewares{
		kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
			group := rt.Resource().Group
			newGroup, ok := Replace(group, apiGroupSuffix)
			if !ok {
				return // ignore APIs that do not have our group
			}

			rt.MutateRequest(func(obj kubeclient.Object) error {
				typeMeta := obj.GetObjectKind()
				origGVK := typeMeta.GroupVersionKind()
				newGVK := schema.GroupVersionKind{
					Group:   newGroup,
					Version: origGVK.Version,
					Kind:    origGVK.Kind,
				}
				typeMeta.SetGroupVersionKind(newGVK)
				return nil
			})
		}),

		kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
			// we should not mess with owner refs on things we did not create
			if rt.Verb() != kubeclient.VerbCreate {
				return
			}

			// we probably do not want mess with an owner ref on a subresource
			if len(rt.Subresource()) != 0 {
				return
			}

			rt.MutateRequest(mutateOwnerRefs(Replace, apiGroupSuffix))
		}),

		kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
			// we only care if this is a create on a TokenCredentialRequest without a subresource
			if rt.Resource() != loginv1alpha1.SchemeGroupVersion.WithResource("tokencredentialrequests") ||
				rt.Verb() != kubeclient.VerbCreate ||
				rt.Subresource() != "" {
				return
			}

			// we only do this on the way out, since on the way back in we don't set a spec in our
			// TokenCredentialRequest
			rt.MutateRequest(func(obj kubeclient.Object) error {
				tokenCredentialRequest, ok := obj.(*loginv1alpha1.TokenCredentialRequest)
				if !ok {
					return fmt.Errorf("cannot cast obj of type %T to *loginv1alpha1.TokenCredentialRequest", obj)
				}

				if tokenCredentialRequest.Spec.Authenticator.APIGroup == nil {
					// technically, the APIGroup field is optional, so clients are free to do this, but we
					// want our middleware to be opinionated so that it can be really good at a specific task
					// and give us specific feedback when it can't do that specific task
					return fmt.Errorf(
						"cannot replace token credential request %q without authenticator API group",
						plog.KObj(obj),
					)
				}

				mutatedAuthenticatorAPIGroup, ok := Replace(*tokenCredentialRequest.Spec.Authenticator.APIGroup, apiGroupSuffix)
				if !ok {
					// see comment above about specificity of middleware
					return fmt.Errorf(
						"cannot replace token credential request %q authenticator API group %q with group suffix %q",
						plog.KObj(obj),
						*tokenCredentialRequest.Spec.Authenticator.APIGroup,
						apiGroupSuffix,
					)
				}

				tokenCredentialRequest.Spec.Authenticator.APIGroup = &mutatedAuthenticatorAPIGroup

				return nil
			})
		}),

		kubeclient.MiddlewareFunc(func(_ context.Context, rt kubeclient.RoundTrip) {
			// always unreplace owner refs with apiGroupSuffix because we can consume those objects across all verbs
			rt.MutateResponse(mutateOwnerRefs(Unreplace, apiGroupSuffix))
		}),
	}
}

func mutateOwnerRefs(replaceFunc func(baseAPIGroup, apiGroupSuffix string) (string, bool), apiGroupSuffix string) func(kubeclient.Object) error {
	return func(obj kubeclient.Object) error {
		// fix up owner refs because they are consumed by external and internal actors
		oldRefs := obj.GetOwnerReferences()
		if len(oldRefs) == 0 {
			return nil
		}

		var changedGroup bool

		newRefs := make([]metav1.OwnerReference, 0, len(oldRefs))
		for _, ref := range oldRefs {
			ref := *ref.DeepCopy()

			gv, _ := schema.ParseGroupVersion(ref.APIVersion) // error is safe to ignore, empty gv is fine

			if newGroup, ok := replaceFunc(gv.Group, apiGroupSuffix); ok {
				changedGroup = true
				gv.Group = newGroup
				ref.APIVersion = gv.String()
			}

			newRefs = append(newRefs, ref)
		}

		if !changedGroup {
			return nil
		}

		obj.SetOwnerReferences(newRefs)

		return nil
	}
}

// Replace constructs an API group from a baseAPIGroup and a parameterized apiGroupSuffix.
//
// We assume that all baseAPIGroup's will end in "pinniped.dev", and therefore we can safely replace
// the reference to "pinniped.dev" with the provided apiGroupSuffix. If the provided baseAPIGroup
// does not end in "pinniped.dev", then this function will return an empty string and false.
//
// See ExampleReplace_loginv1alpha1 and ExampleReplace_string for more information on input/output pairs.
func Replace(baseAPIGroup, apiGroupSuffix string) (string, bool) {
	if !strings.HasSuffix(baseAPIGroup, pinnipedDefaultSuffixWithDot) {
		return "", false
	}
	return strings.TrimSuffix(baseAPIGroup, PinnipedDefaultSuffix) + apiGroupSuffix, true
}

// Unreplace is like performing an undo of Replace().
func Unreplace(baseAPIGroup, apiGroupSuffix string) (string, bool) {
	if !strings.HasSuffix(baseAPIGroup, "."+apiGroupSuffix) {
		return "", false
	}
	return strings.TrimSuffix(baseAPIGroup, apiGroupSuffix) + PinnipedDefaultSuffix, true
}

// Validate validates the provided apiGroupSuffix is usable as an API group suffix. Specifically, it
// makes sure that the provided apiGroupSuffix is a valid DNS-1123 subdomain with at least one dot,
// to match Kubernetes behavior.
func Validate(apiGroupSuffix string) error {
	var errs []error //nolint: prealloc

	if len(strings.Split(apiGroupSuffix, ".")) < 2 {
		errs = append(errs, constable.Error("must contain '.'"))
	}

	errorStrings := validation.IsDNS1123Subdomain(apiGroupSuffix)
	for _, errorString := range errorStrings {
		errorString := errorString
		errs = append(errs, constable.Error(errorString))
	}

	return errors.NewAggregate(errs)
}
