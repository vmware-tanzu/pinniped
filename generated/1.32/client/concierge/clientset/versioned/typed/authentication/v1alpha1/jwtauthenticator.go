// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Code generated by client-gen. DO NOT EDIT.

package v1alpha1

import (
	context "context"

	authenticationv1alpha1 "go.pinniped.dev/generated/1.32/apis/concierge/authentication/v1alpha1"
	scheme "go.pinniped.dev/generated/1.32/client/concierge/clientset/versioned/scheme"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// JWTAuthenticatorsGetter has a method to return a JWTAuthenticatorInterface.
// A group's client should implement this interface.
type JWTAuthenticatorsGetter interface {
	JWTAuthenticators() JWTAuthenticatorInterface
}

// JWTAuthenticatorInterface has methods to work with JWTAuthenticator resources.
type JWTAuthenticatorInterface interface {
	Create(ctx context.Context, jWTAuthenticator *authenticationv1alpha1.JWTAuthenticator, opts v1.CreateOptions) (*authenticationv1alpha1.JWTAuthenticator, error)
	Update(ctx context.Context, jWTAuthenticator *authenticationv1alpha1.JWTAuthenticator, opts v1.UpdateOptions) (*authenticationv1alpha1.JWTAuthenticator, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, jWTAuthenticator *authenticationv1alpha1.JWTAuthenticator, opts v1.UpdateOptions) (*authenticationv1alpha1.JWTAuthenticator, error)
	Delete(ctx context.Context, name string, opts v1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error
	Get(ctx context.Context, name string, opts v1.GetOptions) (*authenticationv1alpha1.JWTAuthenticator, error)
	List(ctx context.Context, opts v1.ListOptions) (*authenticationv1alpha1.JWTAuthenticatorList, error)
	Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *authenticationv1alpha1.JWTAuthenticator, err error)
	JWTAuthenticatorExpansion
}

// jWTAuthenticators implements JWTAuthenticatorInterface
type jWTAuthenticators struct {
	*gentype.ClientWithList[*authenticationv1alpha1.JWTAuthenticator, *authenticationv1alpha1.JWTAuthenticatorList]
}

// newJWTAuthenticators returns a JWTAuthenticators
func newJWTAuthenticators(c *AuthenticationV1alpha1Client) *jWTAuthenticators {
	return &jWTAuthenticators{
		gentype.NewClientWithList[*authenticationv1alpha1.JWTAuthenticator, *authenticationv1alpha1.JWTAuthenticatorList](
			"jwtauthenticators",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *authenticationv1alpha1.JWTAuthenticator { return &authenticationv1alpha1.JWTAuthenticator{} },
			func() *authenticationv1alpha1.JWTAuthenticatorList {
				return &authenticationv1alpha1.JWTAuthenticatorList{}
			},
		),
	}
}
