// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubupstreamwatcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	"go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	pinnipedfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	pinnipedinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	pinnipedcontroller "go.pinniped.dev/internal/controller"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/internal/upstreamgithub"
)

const countExpectedConditions = 5

var (
	githubIDPGVR = schema.GroupVersionResource{
		Group:    v1alpha1.SchemeGroupVersion.Group,
		Version:  v1alpha1.SchemeGroupVersion.Version,
		Resource: "githubidentityproviders",
	}

	githubIDPKind = v1alpha1.SchemeGroupVersion.WithKind("GitHubIdentityProvider")
)

func TestController(t *testing.T) {
	require.Equal(t, 5, countExpectedConditions)

	goodServer, goodServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}), tlsserver.RecordTLSHello)
	goodServerDomain, _ := strings.CutPrefix(goodServer.URL, "https://")
	goodServerCAB64 := base64.StdEncoding.EncodeToString(goodServerCA)

	goodServerIPv6, goodServerIPv6CA := tlsserver.TestServerIPv6(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}), tlsserver.RecordTLSHello)
	goodServerIPv6Domain, _ := strings.CutPrefix(goodServerIPv6.URL, "https://")
	goodServerIPv6CAB64 := base64.StdEncoding.EncodeToString(goodServerIPv6CA)

	caForUnknownServer, err := certauthority.New("Some Unknown CA", time.Hour)
	require.NoError(t, err)
	unknownServerCABytes, _, err := caForUnknownServer.IssueServerCertPEM(
		[]string{"some-dns-name", "some-other-dns-name"},
		[]net.IP{net.ParseIP("10.2.3.4")},
		time.Hour,
	)
	require.NoError(t, err)

	generation := int64(1234)
	lastTransitionTime := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}
	namespace := "some-namespace"

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	goodSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-secret-name",
			Namespace: namespace,
		},
		Type: "secrets.pinniped.dev/github-client",
		Data: map[string][]byte{
			"clientID":     []byte("some-client-id"),
			"clientSecret": []byte("some-client-secret"),
		},
	}

	validMinimalIDP := &v1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "minimal-idp-name",
			Namespace:  namespace,
			UID:        types.UID("minimal-uid"),
			Generation: generation,
		},
		Spec: v1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: v1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &v1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			Client: v1alpha1.GitHubClientSpec{
				SecretName: goodSecret.Name,
			},
			Claims: v1alpha1.GitHubClaims{
				Username: ptr.To(v1alpha1.GitHubUsernameLogin),
				Groups:   ptr.To(v1alpha1.GitHubUseTeamSlugForGroupName),
			},
			AllowAuthentication: v1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: v1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
		},
	}

	validFilledOutIDP := &v1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "some-idp-name",
			Namespace:  namespace,
			UID:        types.UID("some-resource-uid"),
			Generation: generation,
		},
		Spec: v1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: v1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &v1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			Claims: v1alpha1.GitHubClaims{
				Username: ptr.To(v1alpha1.GitHubUsernameID),
				Groups:   ptr.To(v1alpha1.GitHubUseTeamNameForGroupName),
			},
			AllowAuthentication: v1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: v1alpha1.GitHubOrganizationsSpec{
					Policy:  ptr.To(v1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					Allowed: []string{"organization1", "org2"},
				},
			},
			Client: v1alpha1.GitHubClientSpec{
				SecretName: goodSecret.Name,
			},
		},
	}

	buildHostValidTrue := func(t *testing.T, host string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               HostValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             upstreamwatchers.ReasonSuccess,
			Message:            fmt.Sprintf("spec.githubAPI.host (%q) is valid", host),
		}
	}

	buildHostValidFalse := func(t *testing.T, host, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               HostValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             "InvalidHost",
			Message:            fmt.Sprintf(`spec.githubAPI.host (%q) is not valid: %s`, host, message),
		}
	}

	buildTLSConfigurationValidTrue := func(t *testing.T) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               TLSConfigurationValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             upstreamwatchers.ReasonSuccess,
			Message:            "spec.githubAPI.tls.certificateAuthorityData is valid",
		}
	}

	buildTLSConfigurationValidFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               TLSConfigurationValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             "InvalidTLSConfig",
			Message:            message,
		}
	}

	buildOrganizationsPolicyValidTrue := func(t *testing.T, policy v1alpha1.GitHubAllowedAuthOrganizationsPolicy) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               OrganizationsPolicyValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             upstreamwatchers.ReasonSuccess,
			Message:            fmt.Sprintf("spec.allowAuthentication.organizations.policy (%q) is valid", policy),
		}
	}

	buildOrganizationsPolicyValidFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               OrganizationsPolicyValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             "Invalid",
			Message:            message,
		}
	}

	buildClientCredentialsObtainedTrue := func(t *testing.T, secretName string) metav1.Condition {
		t.Helper()
		return metav1.Condition{
			Type:               ClientCredentialsObtained,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             upstreamwatchers.ReasonSuccess,
			Message:            fmt.Sprintf("clientID and clientSecret have been read from spec.client.SecretName (%q)", secretName),
		}
	}

	buildClientCredentialsObtainedFalse := func(t *testing.T, prefix, secretName, namespace, reason string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               ClientCredentialsObtained,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             reason,
			Message: fmt.Sprintf(
				`%s: secret from spec.client.SecretName (%q) must be found in namespace %q with type "secrets.pinniped.dev/github-client" and keys "clientID" and "clientSecret"`,
				prefix,
				secretName,
				namespace,
			),
		}
	}

	buildGitHubConnectionValidTrue := func(t *testing.T, host string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               GitHubConnectionValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             upstreamwatchers.ReasonSuccess,
			Message:            fmt.Sprintf("spec.githubAPI.host (%q) is reachable and TLS verification succeeds", host),
		}
	}

	buildGitHubConnectionValidFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               GitHubConnectionValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             "UnableToDialServer",
			Message:            message,
		}
	}

	buildGitHubConnectionValidUnknown := func(t *testing.T) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               GitHubConnectionValid,
			Status:             metav1.ConditionUnknown,
			ObservedGeneration: generation,
			LastTransitionTime: lastTransitionTime,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}

	buildLogForUpdatingClientCredentialsObtained := func(name, status, reason, message string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"ClientCredentialsObtained","status":"%s","reason":"%s","message":"%s"}`, name, status, reason, message)
	}

	buildLogForUpdatingOrganizationPolicyValid := func(name, status, reason, message string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"OrganizationsPolicyValid","status":"%s","reason":"%s","message":"%s"}`, name, status, reason, message)
	}

	buildLogForUpdatingHostValid := func(name, status, reason, messageFmt, host string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"HostValid","status":"%s","reason":"%s","message":"%s"}`, name, status, reason, fmt.Sprintf(messageFmt, host))
	}

	buildLogForUpdatingTLSConfigurationValid := func(name, status, reason, message string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"TLSConfigurationValid","status":"%s","reason":"%s","message":"%s"}`, name, status, reason, message)
	}

	buildLogForUpdatingGitHubConnectionValid := func(name, status, reason, messageFmt, host string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"GitHubConnectionValid","status":"%s","reason":"%s","message":"%s"}`, name, status, reason, fmt.Sprintf(messageFmt, host))
	}

	buildLogForUpdatingGitHubConnectionValidUnknown := func(name string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"GitHubConnectionValid","status":"Unknown","reason":"UnableToValidate","message":"unable to validate; see other conditions for details"}`, name)
	}

	buildLogForUpdatingPhase := func(name, phase string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"githubupstreamwatcher/github_upstream_watcher.go:<line>$githubupstreamwatcher.(*gitHubWatcherController).updateStatus","message":"updating GitHubIdentityProvider status","namespace":"some-namespace","name":"%s","phase":"%s"}`, name, phase)
	}

	tests := []struct {
		name                    string
		githubIdentityProviders []runtime.Object
		secrets                 []runtime.Object
		wantErr                 string
		wantLogs                []string
		wantResultingCache      []*upstreamgithub.ProviderConfig
		wantResultingUpstreams  []v1alpha1.GitHubIdentityProvider
	}{
		{
			name: "no GitHubIdentityProviders",
		},
		{
			name:    "happy path with all fields",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				validFilledOutIDP,
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "some-idp-name",
					ResourceUID:        "some-resource-uid",
					Host:               fmt.Sprintf("https://%s", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
					},
					AllowedOrganizations:    []string{"organization1", "org2"},
					OrganizationLoginPolicy: "OnlyUsersFromAllowedOrganizations",
					AuthorizationURL:        fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
					HttpClient:              nil, // let the test runner populate this for us
				},
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec:       validFilledOutIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:    "happy path with minimal fields",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				validMinimalIDP,
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "minimal-idp-name",
					ResourceUID:        "minimal-uid",
					Host:               fmt.Sprintf("https://%s", goodServerDomain),
					UsernameAttribute:  "login",
					GroupNameAttribute: "slug",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
					},
					OrganizationLoginPolicy: "AllGitHubUsers",
					AuthorizationURL:        fmt.Sprintf("https://%s/login/oauth/authorize", goodServerDomain),
					HttpClient:              nil, // let the test runner populate this for us
				},
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Ready"),
			},
		},
		{
			name:    "happy path with IPv6",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					ipv6IDP := validMinimalIDP.DeepCopy()
					ipv6IDP.Spec.GitHubAPI.Host = ptr.To(goodServerIPv6Domain)
					ipv6IDP.Spec.GitHubAPI.TLS = &v1alpha1.TLSSpec{
						CertificateAuthorityData: goodServerIPv6CAB64,
					}
					return ipv6IDP
				}(),
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "minimal-idp-name",
					ResourceUID:        "minimal-uid",
					Host:               fmt.Sprintf("https://%s", goodServerIPv6Domain),
					UsernameAttribute:  "login",
					GroupNameAttribute: "slug",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
					},
					OrganizationLoginPolicy: "AllGitHubUsers",
					AuthorizationURL:        fmt.Sprintf("https://%s/login/oauth/authorize", goodServerIPv6Domain),
					HttpClient:              nil, // let the test runner populate this for us
				},
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validMinimalIDP.Spec.DeepCopy()
						otherSpec.GitHubAPI.Host = ptr.To(goodServerIPv6Domain)
						otherSpec.GitHubAPI.TLS = &v1alpha1.TLSSpec{
							CertificateAuthorityData: goodServerIPv6CAB64,
						}
						return *otherSpec
					}(),

					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, goodServerIPv6Domain),
							buildHostValidTrue(t, goodServerIPv6Domain),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, goodServerIPv6Domain),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, goodServerIPv6Domain),
				buildLogForUpdatingPhase("minimal-idp-name", "Ready"),
			},
		},
		{
			name: "multiple idps - two good, one invalid",
			secrets: []runtime.Object{
				goodSecret,
				func() runtime.Object {
					otherSecret := goodSecret.DeepCopy()
					otherSecret.Name = "other-secret-name"
					otherSecret.Data["clientID"] = []byte("other-client-id")
					otherSecret.Data["clientSecret"] = []byte("other-client-secret")
					return otherSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{
				validFilledOutIDP,
				func() runtime.Object {
					otherIDP := validFilledOutIDP.DeepCopy()
					otherIDP.Name = "other-idp-name"
					otherIDP.Spec.Client.SecretName = "other-secret-name"

					// No other test happens to that this particular value passes validation
					otherIDP.Spec.Claims.Username = ptr.To(v1alpha1.GitHubUsernameLoginAndID)
					return otherIDP
				}(),
				func() runtime.Object {
					invalidIDP := validFilledOutIDP.DeepCopy()
					invalidIDP.Name = "invalid-idp-name"
					invalidIDP.Spec.Client.SecretName = "no-secret-with-this-name"
					return invalidIDP
				}(),
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "some-idp-name",
					ResourceUID:        "some-resource-uid",
					Host:               fmt.Sprintf("https://%s", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
					},
					AllowedOrganizations:    []string{"organization1", "org2"},
					OrganizationLoginPolicy: "OnlyUsersFromAllowedOrganizations",
					AuthorizationURL:        fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
					HttpClient:              nil, // let the test runner populate this for us
				},
				{
					Name:               "other-idp-name",
					ResourceUID:        "some-resource-uid",
					Host:               fmt.Sprintf("https://%s", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "login:id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "other-client-id",
						ClientSecret: "other-client-secret",
					},
					AllowedOrganizations:    []string{"organization1", "org2"},
					OrganizationLoginPolicy: "OnlyUsersFromAllowedOrganizations",
					AuthorizationURL:        fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
					HttpClient:              nil, // let the test runner populate this for us
				},
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: func() metav1.ObjectMeta {
						otherMeta := validFilledOutIDP.ObjectMeta.DeepCopy()
						otherMeta.Name = "invalid-idp-name"
						return *otherMeta
					}(),
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validFilledOutIDP.Spec.DeepCopy()
						otherSpec.Client.SecretName = "no-secret-with-this-name"
						return *otherSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedFalse(
								t,
								`secret "no-secret-with-this-name" not found`,
								"no-secret-with-this-name",
								namespace,
								upstreamwatchers.ReasonNotFound,
							),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
				{
					ObjectMeta: func() metav1.ObjectMeta {
						otherMeta := validFilledOutIDP.ObjectMeta.DeepCopy()
						otherMeta.Name = "other-idp-name"
						return *otherMeta
					}(),
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validFilledOutIDP.Spec.DeepCopy()
						otherSpec.Client.SecretName = "other-secret-name"
						otherSpec.Claims.Username = ptr.To(v1alpha1.GitHubUsernameLoginAndID)
						return *otherSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, "other-secret-name"),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec:       validFilledOutIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("invalid-idp-name", "False", "SecretNotFound", `secret \"no-secret-with-this-name\" not found: secret from spec.client.SecretName (\"no-secret-with-this-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingOrganizationPolicyValid("invalid-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("invalid-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("invalid-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("invalid-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("invalid-idp-name", "Error"),

				buildLogForUpdatingClientCredentialsObtained("other-idp-name", "True", "Success", `clientID and clientSecret have been read from spec.client.SecretName (\"other-secret-name\")`),
				buildLogForUpdatingOrganizationPolicyValid("other-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("other-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("other-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("other-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("other-idp-name", "Ready"),

				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:    "Host error - missing spec.githubAPI.host",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = nil
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "", "must not be empty"),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: must not be empty`, ""),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValidUnknown("some-idp-name"),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Host error - protocol/schema is specified",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("https://example.com")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("https://example.com")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "https://example.com", `invalid port "//example.com"`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: invalid port \"//example.com\"`, "https://example.com"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:    "Host error - path is specified",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("example.com/foo")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("example.com/foo")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "example.com/foo", `host "example.com/foo" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: host \"example.com/foo\" is not a valid hostname or IP address`, "example.com/foo"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:    "Host error - userinfo is specified",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("u:p@example.com")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("u:p@example.com")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "u:p@example.com", `invalid port "p@example.com"`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: invalid port \"p@example.com\"`, "u:p@example.com"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:    "Host error - query is specified",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("example.com?a=b")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("example.com?a=b")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "example.com?a=b", `host "example.com?a=b" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: host \"example.com?a=b\" is not a valid hostname or IP address`, "example.com?a=b"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:    "Host error - fragment is specified",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("example.com#a")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("example.com#a")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "example.com#a", `host "example.com#a" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: host \"example.com#a\" is not a valid hostname or IP address`, "example.com#a"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:    "TLS error - invalid bundle",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.TLS = &v1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("foo")),
					}
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.TLS = &v1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("foo")),
						}
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidFalse(t, "spec.githubAPI.tls.certificateAuthorityData is not valid: certificateAuthorityData is not valid PEM: data does not contain any valid RSA or ECDSA certificates"),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "False", "InvalidTLSConfig", "spec.githubAPI.tls.certificateAuthorityData is not valid: certificateAuthorityData is not valid PEM: data does not contain any valid RSA or ECDSA certificates"),
				buildLogForUpdatingGitHubConnectionValidUnknown("some-idp-name"),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Connection error - no such host",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("nowhere.bad-tld")
					return badIDP
				}(),
			},
			wantErr: "dial tcp: lookup nowhere.bad-tld: no such host",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("nowhere.bad-tld")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidFalse(t, fmt.Sprintf(`cannot dial server spec.githubAPI.host (%q): dial tcp: lookup nowhere.bad-tld: no such host`, "nowhere.bad-tld:443")),
							buildHostValidTrue(t, "nowhere.bad-tld"),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, "nowhere.bad-tld"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "False", "UnableToDialServer", `cannot dial server spec.githubAPI.host (\"%s\"): dial tcp: lookup nowhere.bad-tld: no such host`, "nowhere.bad-tld:443"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:    "Connection error - host not trusted by system certs",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.TLS = nil
					return badIDP
				}(),
			},
			wantErr: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.TLS = nil
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidFalse(t, fmt.Sprintf(`cannot dial server spec.githubAPI.host (%q): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host)),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "False", "UnableToDialServer", `cannot dial server spec.githubAPI.host (\"%s\"): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Connection error - host not trusted by provided CA bundle",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.TLS = &v1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(unknownServerCABytes),
					}
					return badIDP
				}(),
			},
			wantErr: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.TLS = &v1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(unknownServerCABytes),
						}
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidFalse(t, fmt.Sprintf(`cannot dial server spec.githubAPI.host (%q): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host)),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "False", "UnableToDialServer", `cannot dial server spec.githubAPI.host (\"%s\"): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Organization Policy error - missing spec.allowAuthentication.organizations.policy",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Policy = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Policy = nil
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Organization Policy error - invalid spec.allowAuthentication.organizations.policy",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Policy = ptr.To[v1alpha1.GitHubAllowedAuthOrganizationsPolicy]("a")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Policy = ptr.To[v1alpha1.GitHubAllowedAuthOrganizationsPolicy]("a")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Organization Policy error - spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Policy = ptr.To(v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Policy = ptr.To(v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Organization Policy error - spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Allowed = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Allowed = nil
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:    "Invalid Claims - missing spec.claims.username",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Username = nil
					return badIDP
				}(),
			},
			wantErr: "spec.claims.groups and spec.claims.username are required",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Username = nil
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:    "Invalid Claims - invalid spec.claims.username",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Username = ptr.To[v1alpha1.GitHubUsernameAttribute]("a")
					return badIDP
				}(),
			},
			wantErr: "invalid spec.claims.username",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Username = ptr.To[v1alpha1.GitHubUsernameAttribute]("a")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:    "Invalid Claims - missing spec.claims.groups",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Groups = nil
					return badIDP
				}(),
			},
			wantErr: "spec.claims.groups and spec.claims.username are required",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Groups = nil
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:    "Invalid Claims - invalid spec.claims.groups",
			secrets: []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Groups = ptr.To[v1alpha1.GitHubGroupNameAttribute]("a")
					return badIDP
				}(),
			},
			wantErr: "invalid spec.claims.groups",
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() v1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Groups = ptr.To[v1alpha1.GitHubGroupNameAttribute]("a")
						return *badSpec
					}(),
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name: "Client Secret error - in different namespace",
			secrets: []runtime.Object{
				func() runtime.Object {
					badSecret := goodSecret.DeepCopy()
					badSecret.Namespace = "other-namespace"
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedFalse(
								t,
								fmt.Sprintf("secret %q not found", validMinimalIDP.Spec.Client.SecretName),
								validMinimalIDP.Spec.Client.SecretName,
								validMinimalIDP.Namespace,
								upstreamwatchers.ReasonNotFound,
							),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "False", "SecretNotFound", `secret \"some-secret-name\" not found: secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - wrong type",
			secrets: []runtime.Object{
				func() runtime.Object {
					badSecret := goodSecret.DeepCopy()
					badSecret.Type = "other-type"
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedFalse(
								t,
								`wrong secret type "other-type"`,
								validMinimalIDP.Spec.Client.SecretName,
								validMinimalIDP.Namespace,
								upstreamwatchers.ReasonNotFound,
							),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "False", "SecretNotFound", `wrong secret type \"other-type\": secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - missing clientId",
			secrets: []runtime.Object{
				func() runtime.Object {
					badSecret := goodSecret.DeepCopy()
					delete(badSecret.Data, "clientID")
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedFalse(
								t,
								`missing key "clientID"`,
								validMinimalIDP.Spec.Client.SecretName,
								validMinimalIDP.Namespace,
								upstreamwatchers.ReasonNotFound,
							),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "False", "SecretNotFound", `missing key \"clientID\": secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - missing clientSecret",
			secrets: []runtime.Object{
				func() runtime.Object {
					badSecret := goodSecret.DeepCopy()
					delete(badSecret.Data, "clientSecret")
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedFalse(
								t,
								`missing key "clientSecret"`,
								validMinimalIDP.Spec.Client.SecretName,
								validMinimalIDP.Namespace,
								upstreamwatchers.ReasonNotFound,
							),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "False", "SecretNotFound", `missing key \"clientSecret\": secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - additional data",
			secrets: []runtime.Object{
				func() runtime.Object {
					badSecret := goodSecret.DeepCopy()
					badSecret.Data["foo"] = []byte("bar")
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []v1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: v1alpha1.GitHubIdentityProviderStatus{
						Phase: v1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClientCredentialsObtainedFalse(
								t,
								"extra keys found",
								validMinimalIDP.Spec.Client.SecretName,
								validMinimalIDP.Namespace,
								upstreamwatchers.ReasonNotFound,
							),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsObtained("minimal-idp-name", "False", "SecretNotFound", `extra keys found: secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls.certificateAuthorityData is valid"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			fakePinnipedClientForInformers := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(fakePinnipedClientForInformers, 0)

			fakeKubeClient := kubernetesfake.NewSimpleClientset(tt.secrets...)
			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(fakeKubeClient, 0)

			cache := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			cache.SetGitHubIdentityProviders([]upstreamprovider.UpstreamGithubIdentityProviderI{
				&upstreamgithub.ProviderConfig{Name: "initial-entry-to-remove"},
			})

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			gitHubIdentityProviderInformer := pinnipedInformers.IDP().V1alpha1().GitHubIdentityProviders()

			controller := New(
				namespace,
				cache,
				fakePinnipedClient,
				gitHubIdentityProviderInformer,
				kubeInformers.Core().V1().Secrets(),
				logger,
				controllerlib.WithInformer,
				frozenClock,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); len(tt.wantErr) > 0 {
				require.ErrorContains(t, err, controllerlib.ErrSyntheticRequeue.Error())
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			// Verify what's in the cache
			actualIDPList := cache.GetGitHubIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
			for i := 0; i < len(tt.wantResultingCache); i++ {
				// Do not expect any particular order in the cache
				var actualIDP *upstreamgithub.ProviderConfig
				for _, possibleIDP := range actualIDPList {
					if possibleIDP.GetName() == tt.wantResultingCache[i].Name {
						// For this check, we know that the actual IDPs are going to have type upstreamgithub.ProviderConfig
						var ok bool
						actualIDP, ok = possibleIDP.(*upstreamgithub.ProviderConfig)
						require.True(t, ok)
						break
					}
				}

				require.Equal(t, tt.wantResultingCache[i].Name, actualIDP.GetName())
				require.Equal(t, tt.wantResultingCache[i].ResourceUID, actualIDP.GetResourceUID())
				require.Equal(t, tt.wantResultingCache[i].Host, actualIDP.GetHost())
				require.Equal(t, tt.wantResultingCache[i].OAuth2Config.ClientID, actualIDP.GetClientID())
				require.Equal(t, tt.wantResultingCache[i].GroupNameAttribute, actualIDP.GetGroupNameAttribute())
				require.Equal(t, tt.wantResultingCache[i].UsernameAttribute, actualIDP.GetUsernameAttribute())
				require.Equal(t, tt.wantResultingCache[i].AllowedOrganizations, actualIDP.GetAllowedOrganizations())
				require.Equal(t, tt.wantResultingCache[i].OrganizationLoginPolicy, actualIDP.GetOrganizationLoginPolicy())
				require.Equal(t, tt.wantResultingCache[i].AuthorizationURL, actualIDP.GetAuthorizationURL())

				require.GreaterOrEqual(t, len(tt.githubIdentityProviders), i+1, "there must be at least as many input identity providers as items in the cache")
				githubIDP, ok := tt.githubIdentityProviders[i].(*v1alpha1.GitHubIdentityProvider)
				require.True(t, ok)
				certPool, _, err := pinnipedcontroller.BuildCertPoolIDP(githubIDP.Spec.GitHubAPI.TLS)
				require.NoError(t, err)

				compareTLSClientConfigWithinHttpClients(t, phttp.Default(certPool), actualIDP.GetHttpClient())
				require.Equal(t, tt.wantResultingCache[i].OAuth2Config, actualIDP.OAuth2Config)
			}

			// Verify the status conditions as reported in Kubernetes
			allGitHubIDPs, err := fakePinnipedClient.IDPV1alpha1().GitHubIdentityProviders(namespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			require.Equal(t, len(tt.wantResultingUpstreams), len(allGitHubIDPs.Items))
			for i := 0; i < len(tt.wantResultingUpstreams); i++ {
				// Do not expect any particular order in the K8s objects
				var actualIDP *v1alpha1.GitHubIdentityProvider
				for _, possibleMatch := range allGitHubIDPs.Items {
					if possibleMatch.GetName() == tt.wantResultingUpstreams[i].Name {
						actualIDP = ptr.To(possibleMatch)
						break
					}
				}

				require.NotNil(t, actualIDP, "must find IDP with name %s", tt.wantResultingUpstreams[i].Name)
				require.Equal(t, countExpectedConditions, len(actualIDP.Status.Conditions))

				// Update all expected conditions to the frozenTime.
				// TODO: Push this out to the test table
				for j := 0; j < countExpectedConditions; j++ {
					// Get this as a pointer so that we can update the value within the array
					condition := &tt.wantResultingUpstreams[i].Status.Conditions[j]
					condition.LastTransitionTime = metav1.Time{Time: frozenClock.Now()}
				}

				require.Equal(t, tt.wantResultingUpstreams[i], *actualIDP)
			}

			expectedLogs := ""
			if len(tt.wantLogs) > 0 {
				expectedLogs = strings.Join(tt.wantLogs, "\n") + "\n"
			}
			require.Equal(t, expectedLogs, log.String())

			// This needs to happen after the expected condition LastTransitionTime has been updated.
			wantActions := make([]coretesting.Action, 1+len(tt.wantResultingUpstreams))
			for i, want := range tt.wantResultingUpstreams {
				wantActions[i] = coretesting.NewUpdateSubresourceAction(githubIDPGVR, "status", want.Namespace, ptr.To(want))
			}
			wantActions[len(tt.wantResultingUpstreams)] = coretesting.NewListAction(githubIDPGVR, githubIDPKind, namespace, metav1.ListOptions{})
			require.Equal(t, wantActions, fakePinnipedClient.Actions())
		})
	}
}

func TestController_WithExistingConditions(t *testing.T) {
	require.Equal(t, 5, countExpectedConditions)

	goodServer, goodServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}), tlsserver.RecordTLSHello)
	goodServerDomain, _ := strings.CutPrefix(goodServer.URL, "https://")
	goodServerCAB64 := base64.StdEncoding.EncodeToString(goodServerCA)

	oneHourAgo := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}
	namespace := "existing-conditions-namespace"

	nowDoesntMatter := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenClock := clocktesting.NewFakeClock(nowDoesntMatter)

	alreadyInvalidExistingIDP := &v1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "already-existing-invalid-idp-name",
			Namespace:  namespace,
			UID:        types.UID("some-resource-uid"),
			Generation: 333,
		},
		Spec: v1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: v1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &v1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			AllowAuthentication: v1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: v1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(v1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
			Claims: v1alpha1.GitHubClaims{
				Username: ptr.To(v1alpha1.GitHubUsernameLogin),
				Groups:   ptr.To(v1alpha1.GitHubUseTeamSlugForGroupName),
			},
			Client: v1alpha1.GitHubClientSpec{
				SecretName: "unknown-secret",
			},
		},
		Status: v1alpha1.GitHubIdentityProviderStatus{
			Phase: v1alpha1.GitHubPhaseError,
			Conditions: []metav1.Condition{
				{
					Type:               ClientCredentialsObtained,
					Status:             metav1.ConditionFalse,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             "SecretNotFound",
					Message:            fmt.Sprintf(`secret "unknown-secret" not found: secret from spec.client.SecretName ("unknown-secret") must be found in namespace %q with type "secrets.pinniped.dev/github-client" and keys "clientID" and "clientSecret"`, namespace),
				},
				{
					Type:               GitHubConnectionValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             upstreamwatchers.ReasonSuccess,
					Message:            fmt.Sprintf("spec.githubAPI.host (%q) is reachable and TLS verification succeeds", goodServerDomain),
				},
				{
					Type:               HostValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             upstreamwatchers.ReasonSuccess,
					Message:            fmt.Sprintf("spec.githubAPI.host (%q) is valid", goodServerDomain),
				},
				{
					Type:               OrganizationsPolicyValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             upstreamwatchers.ReasonSuccess,
					Message:            `spec.allowAuthentication.organizations.policy ("AllGitHubUsers") is valid`,
				},
				{
					Type:               TLSConfigurationValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             upstreamwatchers.ReasonSuccess,
					Message:            "spec.githubAPI.tls.certificateAuthorityData is valid",
				},
			},
		},
	}

	tests := []struct {
		name                    string
		secrets                 []runtime.Object
		githubIdentityProviders []runtime.Object
		wantActions             []coretesting.Action
	}{
		{
			name:        "no GitHubIdentityProviders",
			wantActions: make([]coretesting.Action, 0),
		},
		{
			name: "already existing idp with appropriate conditions does not issue actions",
			githubIdentityProviders: []runtime.Object{
				alreadyInvalidExistingIDP,
			},
			wantActions: make([]coretesting.Action, 0),
		},
		{
			name: "already existing idp with stale conditions will issue an update action",
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					otherIDP := alreadyInvalidExistingIDP.DeepCopy()
					otherIDP.Generation = 400
					otherIDP.Status.Phase = v1alpha1.GitHubPhaseReady
					otherIDP.Status.Conditions[0].Status = metav1.ConditionTrue
					otherIDP.Status.Conditions[0].Message = "some other message indicating that things are good"
					return otherIDP
				}(),
			},
			wantActions: []coretesting.Action{
				func() coretesting.Action {
					idp := alreadyInvalidExistingIDP.DeepCopy()
					idp.Generation = 400
					for i := range idp.Status.Conditions {
						idp.Status.Conditions[i].ObservedGeneration = 400
					}
					idp.Status.Conditions[0].LastTransitionTime = metav1.Time{Time: nowDoesntMatter}
					wantAction := coretesting.NewUpdateSubresourceAction(githubIDPGVR, "status", namespace, idp)
					return wantAction
				}(),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakePinnipedClient := pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...)
			pinnipedInformers := pinnipedinformers.NewSharedInformerFactory(pinnipedfake.NewSimpleClientset(tt.githubIdentityProviders...), 0)

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(tt.secrets...), 0)

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			controller := New(
				namespace,
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				fakePinnipedClient,
				pinnipedInformers.IDP().V1alpha1().GitHubIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
				logger,
				controllerlib.WithInformer,
				frozenClock,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			pinnipedInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			err := controllerlib.TestSync(t, controller, syncCtx)
			require.NoError(t, err)

			require.Equal(t, tt.wantActions, fakePinnipedClient.Actions())
		})
	}
}

func compareTLSClientConfigWithinHttpClients(t *testing.T, expected *http.Client, actual *http.Client) {
	t.Helper()

	require.NotEmpty(t, expected)
	require.NotEmpty(t, actual)

	require.Equal(t, expected.Timeout, actual.Timeout)

	expectedConfig, err := utilnet.TLSClientConfig(expected.Transport)
	require.NoError(t, err)

	actualConfig, err := utilnet.TLSClientConfig(actual.Transport)
	require.NoError(t, err)

	require.True(t, actualConfig.RootCAs.Equal(expectedConfig.RootCAs))
	actualConfig.RootCAs = expectedConfig.RootCAs
	require.Equal(t, expectedConfig, actualConfig)
}

func TestGitHubUpstreamWatcherControllerFilterSecret(t *testing.T) {
	namespace := "some-namespace"
	goodSecret := &corev1.Secret{
		Type: "secrets.pinniped.dev/github-client",
		ObjectMeta: metav1.ObjectMeta{
			Name:      "some-name",
			Namespace: namespace,
		},
	}

	tests := []struct {
		name       string
		secret     metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "a secret of the right type",
			secret:     goodSecret,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "a secret of the right type, but in the wrong namespace",
			secret: func() *corev1.Secret {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.Namespace = "other-namespace"
				return otherSecret
			}(),
		},
		{
			name: "a secret of the wrong type",
			secret: func() *corev1.Secret {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.Type = "other-type"
				return otherSecret
			}(),
		},
		{
			name: "resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0)

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			secretInformer := kubeInformers.Core().V1().Secrets()
			observableInformers := testutil.NewObservableWithInformerOption()

			_ = New(
				namespace,
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				pinnipedfake.NewSimpleClientset(),
				pinnipedinformers.NewSharedInformerFactory(pinnipedfake.NewSimpleClientset(), 0).IDP().V1alpha1().GitHubIdentityProviders(),
				secretInformer,
				logger,
				observableInformers.WithInformer,
				clock.RealClock{},
			)

			unrelated := &corev1.Secret{}
			filter := observableInformers.GetFilterForInformer(secretInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.secret))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.secret, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.secret))
		})
	}
}

func TestGitHubUpstreamWatcherControllerFilterGitHubIDP(t *testing.T) {
	namespace := "some-namespace"
	goodIDP := &v1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
	}

	tests := []struct {
		name       string
		idp        metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "an IDP in the right namespace",
			idp:        goodIDP,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "IDP in the wrong namespace",
			idp: func() metav1.Object {
				badIDP := goodIDP.DeepCopy()
				badIDP.Namespace = "other-namespace"
				return badIDP
			}(),
		},
		{
			name: "resource of wrong data type",
			idp: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name"},
			},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			gitHubIdentityProviderInformer := pinnipedinformers.NewSharedInformerFactory(pinnipedfake.NewSimpleClientset(), 0).IDP().V1alpha1().GitHubIdentityProviders()
			observableInformers := testutil.NewObservableWithInformerOption()

			_ = New(
				namespace,
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				pinnipedfake.NewSimpleClientset(),
				gitHubIdentityProviderInformer,
				k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0).Core().V1().Secrets(),
				logger,
				observableInformers.WithInformer,
				clock.RealClock{},
			)

			unrelated := &v1alpha1.GitHubIdentityProvider{}
			filter := observableInformers.GetFilterForInformer(gitHubIdentityProviderInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.idp))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.idp))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.idp, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.idp))
		})
	}
}
