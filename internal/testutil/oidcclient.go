// Copyright 2022-2023 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	configv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/config/v1alpha1"
)

const (
	AllDynamicClientScopesSpaceSep = "openid offline_access pinniped:request-audience username groups"

	// PlaintextPassword1 is a fake client secret for use in unit tests, along with several flavors of the bcrypt
	// hashed version of the password. Do not use for integration tests.
	PlaintextPassword1                        = "password1"
	HashedPassword1AtGoMinCost                = "$2a$04$JfX1ba/ctAt3AGk73E9Zz.Fdki5GiQtj.O/CnPbRRSKQWWfv1svoe" //nolint:gosec // this is not a credential
	HashedPassword1JustBelowSupervisorMinCost = "$2a$11$w/incy7Z1/ljLYvv2XRg4.WrPgY9oR7phebcgr6rGA3u/5TG9MKOe" //nolint:gosec // this is not a credential
	HashedPassword1AtSupervisorMinCost        = "$2a$12$id4i/yFYxS99txKOFEeboea2kU6DyZY0Nh4ul0eR46sDuoFoNTRV." //nolint:gosec // this is not a credential
	HashedPassword1InvalidFormat              = "$2a$12$id4i/yFYxS99txKOFEeboea2kU6DyZY0Nh4ul0eR46sDuo"        //nolint:gosec // this is not a credential

	// PlaintextPassword2 is a second fake client secret for use in unit tests, along with several flavors of the bcrypt
	// hashed version of the password. Do not use for integration tests.
	PlaintextPassword2                 = "password2"
	HashedPassword2AtGoMinCost         = "$2a$04$VQ5z6kkgU8JPLGSGctg.s.iYyoac3Oisa/SIM3sDK5BxTrVbCkyNm" //nolint:gosec // this is not a credential
	HashedPassword2AtSupervisorMinCost = "$2a$12$SdUqoJOn4/3yEQfJx616V.q.f76KaXD.ISgJT1oydqFdgfjJpBh6u" //nolint:gosec // this is not a credential
)

// allDynamicClientScopes returns a slice of all scopes that are supported by the Supervisor for dynamic clients.
func allDynamicClientScopes() []configv1alpha1.Scope {
	scopes := []configv1alpha1.Scope{}
	for _, s := range strings.Split(AllDynamicClientScopesSpaceSep, " ") {
		scopes = append(scopes, configv1alpha1.Scope(s))
	}
	return scopes
}

func newOIDCClient(
	namespace string,
	clientID string,
	clientUID string,
	redirectURI string,
	allowedGrantTypes []configv1alpha1.GrantType,
	allowedScopes []configv1alpha1.Scope,
) *configv1alpha1.OIDCClient {
	return &configv1alpha1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: clientID, Generation: 1, UID: types.UID(clientUID)},
		Spec: configv1alpha1.OIDCClientSpec{
			AllowedGrantTypes:   allowedGrantTypes,
			AllowedScopes:       allowedScopes,
			AllowedRedirectURIs: []configv1alpha1.RedirectURI{configv1alpha1.RedirectURI(redirectURI)},
		},
	}
}

// OIDCClientValidatorFunc is an interface-like type that allows these test helpers to avoid having a direct dependency
// on the production code, to avoid circular module dependencies. Implemented by oidcclientvalidator.Validate.
type OIDCClientValidatorFunc func(oidcClient *configv1alpha1.OIDCClient, secret *corev1.Secret, minBcryptCost int) (bool, []*metav1.Condition, []string)

// FullyCapableOIDCClientAndStorageSecret returns an OIDC client which is allowed to use all grant types and all scopes
// that are supported by the Supervisor for dynamic clients, along with a corresponding client secret storage Secret.
func FullyCapableOIDCClientAndStorageSecret(
	t *testing.T,
	namespace string,
	clientID string,
	clientUID string,
	redirectURI string,
	hashes []string,
	validateFunc OIDCClientValidatorFunc,
) (*configv1alpha1.OIDCClient, *corev1.Secret) {
	allScopes := allDynamicClientScopes()

	allGrantTypes := []configv1alpha1.GrantType{
		"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token",
	}

	return OIDCClientAndStorageSecret(t, namespace, clientID, clientUID, allGrantTypes, allScopes, redirectURI, hashes, validateFunc)
}

// OIDCClientAndStorageSecret returns an OIDC client which is allowed to use the specified grant types and scopes,
// along with a corresponding client secret storage Secret. It also validates the client to make sure that the specified
// combination of grant types and scopes is considered valid before returning the client.
func OIDCClientAndStorageSecret(
	t *testing.T,
	namespace string,
	clientID string,
	clientUID string,
	allowedGrantTypes []configv1alpha1.GrantType,
	allowedScopes []configv1alpha1.Scope,
	redirectURI string,
	hashes []string,
	validateFunc OIDCClientValidatorFunc,
) (*configv1alpha1.OIDCClient, *corev1.Secret) {
	oidcClient := newOIDCClient(namespace, clientID, clientUID, redirectURI, allowedGrantTypes, allowedScopes)
	secret := OIDCClientSecretStorageSecretForUID(t, namespace, clientUID, hashes)

	// If a test made an invalid OIDCClient then inform the author of the test, so they can fix the test case.
	// This is an easy mistake to make when writing tests because there are lots of validations on OIDCClients.
	valid, conditions, _ := validateFunc(oidcClient, secret, bcrypt.MinCost)
	require.True(t, valid, "Test's OIDCClient should have been valid. See conditions for errors: %s", conditions)

	return oidcClient, secret
}
