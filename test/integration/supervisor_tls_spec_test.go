// Copyright 2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
package integration

import (
	"fmt"
	"testing"

	"go.pinniped.dev/internal/here"
	"go.pinniped.dev/test/testlib"
)

// TestTLSSpecKubeBuilderValidationSupervisor_Parallel tests kubebuilder validation
// on the TLSSpec in Pinniped supervisor CRDs using OIDCIdentityProvider as an example.
func TestTLSSpecKubeBuilderValidationSupervisor_Parallel(t *testing.T) {
	env := testlib.IntegrationEnv(t)
	testCases := []struct {
		name               string
		customResourceYaml string
		customResourceName string
		expectedError      string
	}{
		// TODO: make this a loop to also run the same tests on LDAP, AD, GitHub??
		{
			name: "should disallow certificate authority data source with missing name",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-missing-name",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for name",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: ""
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-empty-name",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.name: Invalid value: "": spec.tls.certificateAuthorityDataSource.name in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing key",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-missing-key",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value for key",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: ""
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-empty-key",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.key: Invalid value: "": spec.tls.certificateAuthorityDataSource.key in body should be at least 1 chars long`,
		},
		{
			name: "should disallow certificate authority data source with missing kind",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						name: foo
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-missing-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Required value`,
		},
		{
			name: "should disallow certificate authority data source with empty value kind",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: ""
						name: foo
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-invalid-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "": supported values: "Secret", "ConfigMap"`,
		},
		{
			name: "should disallow certificate authority data source with invalid kind",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: sorcery
						name: foo
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "invalid-oidc-idp-invalid-kind",
			expectedError:      `The %s "%s" is invalid: spec.tls.certificateAuthorityDataSource.kind: Unsupported value: "sorcery": supported values: "Secret", "ConfigMap"`,
		},
		{
			name: "should create a custom resource passing all validations using a Secret source",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: Secret
						name: foo
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "valid-oidc-idp-secret-kind",
			expectedError:      "",
		},
		{
			name: "should create a custom resource passing all validations using a ConfigMap source",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				tls:
					certificateAuthorityDataSource:
						kind: ConfigMap
						name: foo
						key: bar
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "valid-oidc-idp-cm-kind",
			expectedError:      "",
		},
		{
			name: "should create a custom resource without any tls spec",
			customResourceYaml: here.Doc(`
			---
			apiVersion: idp.supervisor.%s/v1alpha1
			kind: OIDCIdentityProvider
			metadata:
				name: %s
			spec:
				issuer: %s
				authorizationConfig:
					additionalScopes: [offline_access, email]
					allowPasswordGrant: true
				client:
					secretName: foo-bar-client-credentials
			`),
			customResourceName: "no-tls-spec",
			expectedError:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resourceName := tc.customResourceName + "-" + testlib.RandHex(t, 7)
			yamlBytes := []byte(fmt.Sprintf(tc.customResourceYaml, env.APIGroupSuffix, resourceName, env.SupervisorUpstreamOIDC.Issuer))

			performKubectlApply(t, yamlBytes, `oidcidentityprovider.idp.supervisor.pinniped.dev`, tc.expectedError, "OIDCIdentityProvider", resourceName)
		})
	}
}
