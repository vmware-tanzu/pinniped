// Copyright 2020-2024 the Pinniped contributors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package githubupstreamwatcher

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"slices"
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
	"k8s.io/apimachinery/pkg/util/cache"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	k8sinformers "k8s.io/client-go/informers"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	coretesting "k8s.io/client-go/testing"
	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
	"k8s.io/utils/ptr"

	idpv1alpha1 "go.pinniped.dev/generated/latest/apis/supervisor/idp/v1alpha1"
	supervisorfake "go.pinniped.dev/generated/latest/client/supervisor/clientset/versioned/fake"
	supervisorinformers "go.pinniped.dev/generated/latest/client/supervisor/informers/externalversions"
	"go.pinniped.dev/internal/certauthority"
	"go.pinniped.dev/internal/controller/conditionsutil"
	"go.pinniped.dev/internal/controller/supervisorconfig/upstreamwatchers"
	"go.pinniped.dev/internal/controller/tlsconfigutil"
	"go.pinniped.dev/internal/controllerlib"
	"go.pinniped.dev/internal/federationdomain/dynamicupstreamprovider"
	"go.pinniped.dev/internal/federationdomain/upstreamprovider"
	"go.pinniped.dev/internal/net/phttp"
	"go.pinniped.dev/internal/plog"
	"go.pinniped.dev/internal/setutil"
	"go.pinniped.dev/internal/testutil"
	"go.pinniped.dev/internal/testutil/tlsserver"
	"go.pinniped.dev/internal/upstreamgithub"
)

var (
	githubIDPGVR = schema.GroupVersionResource{
		Group:    idpv1alpha1.SchemeGroupVersion.Group,
		Version:  idpv1alpha1.SchemeGroupVersion.Version,
		Resource: "githubidentityproviders",
	}

	githubIDPKind = idpv1alpha1.SchemeGroupVersion.WithKind("GitHubIdentityProvider")
)

func TestController(t *testing.T) {
	require.Equal(t, 6, countExpectedConditions)

	goodServer, goodServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}), tlsserver.RecordTLSHello)
	goodServerDomain, _ := strings.CutPrefix(goodServer.URL, "https://")
	goodServerCAB64 := base64.StdEncoding.EncodeToString(goodServerCA)
	goodServerCertPool := x509.NewCertPool()
	goodServerCertPool.AppendCertsFromPEM(goodServerCA)

	goodServerIPv6, goodServerIPv6CA := tlsserver.TestServerIPv6(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}), tlsserver.RecordTLSHello)
	goodServerIPv6Domain, _ := strings.CutPrefix(goodServerIPv6.URL, "https://")
	goodServerIPv6CAB64 := base64.StdEncoding.EncodeToString(goodServerIPv6CA)
	goodServerIPv6CertPool := x509.NewCertPool()
	goodServerIPv6CertPool.AppendCertsFromPEM(goodServerCA)

	caForUnknownServer, err := certauthority.New("Some Unknown CA", time.Hour)
	require.NoError(t, err)
	unknownServerCABytes, _, err := caForUnknownServer.IssueServerCertPEM(
		[]string{"some-dns-name", "some-other-dns-name"},
		[]net.IP{net.ParseIP("10.2.3.4")},
		time.Hour,
	)
	require.NoError(t, err)

	wantObservedGeneration := int64(1234)
	namespace := "some-namespace"

	wantFrozenTime := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenClockForLastTransitionTime := clocktesting.NewFakeClock(wantFrozenTime)
	wantLastTransitionTime := metav1.Time{Time: wantFrozenTime}

	goodClientCredentialsSecret := &corev1.Secret{
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

	goodCABundleSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle-secret-name",
			Namespace: namespace,
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"ca.crt": goodServerCA,
		},
	}

	goodCABundleConfigMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ca-bundle-secret-name",
			Namespace: namespace,
		},
		Data: map[string]string{
			"ca.crt": string(goodServerCA),
		},
	}

	validMinimalIDP := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "minimal-idp-name",
			Namespace:  namespace,
			UID:        types.UID("minimal-uid"),
			Generation: wantObservedGeneration,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: idpv1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &idpv1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: goodClientCredentialsSecret.Name,
			},
			// These claims are optional when using the actual Kubernetes CRD.
			// However, they are required here because CRD defaulting/validation does not occur during testing.
			Claims: idpv1alpha1.GitHubClaims{
				Username: ptr.To(idpv1alpha1.GitHubUsernameLogin),
				Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
			},
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
		},
	}

	validFilledOutIDP := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "some-idp-name",
			Namespace:  namespace,
			UID:        types.UID("some-resource-uid"),
			Generation: wantObservedGeneration,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: idpv1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &idpv1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			Claims: idpv1alpha1.GitHubClaims{
				Username: ptr.To(idpv1alpha1.GitHubUsernameID),
				Groups:   ptr.To(idpv1alpha1.GitHubUseTeamNameForGroupName),
			},
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy:  ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyOnlyUsersFromAllowedOrganizations),
					Allowed: []string{"organization1", "org2"},
				},
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: goodClientCredentialsSecret.Name,
			},
		},
	}

	buildHostValidTrue := func(t *testing.T, host string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               HostValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             conditionsutil.ReasonSuccess,
			Message:            fmt.Sprintf("spec.githubAPI.host (%q) is valid", host),
		}
	}

	buildHostValidFalse := func(t *testing.T, host, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               HostValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             "InvalidHost",
			Message:            fmt.Sprintf(`spec.githubAPI.host (%q) is not valid: %s`, host, message),
		}
	}
	buildTLSConfigurationValidTrueWithMsg := func(t *testing.T, msg string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               TLSConfigurationValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             conditionsutil.ReasonSuccess,
			Message:            fmt.Sprintf("spec.githubAPI.tls is valid: %s", msg),
		}
	}

	buildTLSConfigurationValidTrue := func(t *testing.T) metav1.Condition {
		t.Helper()
		return buildTLSConfigurationValidTrueWithMsg(t, "loaded TLS configuration")
	}

	buildTLSConfigurationValidFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               TLSConfigurationValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             "InvalidTLSConfig",
			Message:            message,
		}
	}

	buildOrganizationsPolicyValidTrue := func(t *testing.T, policy idpv1alpha1.GitHubAllowedAuthOrganizationsPolicy) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               OrganizationsPolicyValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             conditionsutil.ReasonSuccess,
			Message:            fmt.Sprintf("spec.allowAuthentication.organizations.policy (%q) is valid", policy),
		}
	}

	buildOrganizationsPolicyValidFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               OrganizationsPolicyValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             "Invalid",
			Message:            message,
		}
	}

	buildClientCredentialsSecretValidTrue := func(t *testing.T, secretName string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               ClientCredentialsSecretValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             conditionsutil.ReasonSuccess,
			Message:            fmt.Sprintf("clientID and clientSecret have been read from spec.client.SecretName (%q)", secretName),
		}
	}

	buildClientCredentialsSecretValidFalse := func(t *testing.T, prefix, secretName, namespace, reason string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               ClientCredentialsSecretValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             reason,
			Message: fmt.Sprintf(
				`%s: secret from spec.client.SecretName (%q) must be found in namespace %q with type "secrets.pinniped.dev/github-client" and keys "clientID" and "clientSecret"`,
				prefix,
				secretName,
				namespace,
			),
		}
	}

	buildClaimsValidatedTrue := func(t *testing.T) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               ClaimsValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             conditionsutil.ReasonSuccess,
			Message:            "spec.claims are valid",
		}
	}

	buildClaimsValidatedFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               ClaimsValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             "Invalid",
			Message:            message,
		}
	}

	buildGitHubConnectionValidTrue := func(t *testing.T, host string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               GitHubConnectionValid,
			Status:             metav1.ConditionTrue,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             conditionsutil.ReasonSuccess,
			Message:            fmt.Sprintf("spec.githubAPI.host (%q) is reachable and TLS verification succeeds", host),
		}
	}

	buildGitHubConnectionValidFalse := func(t *testing.T, message string) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               GitHubConnectionValid,
			Status:             metav1.ConditionFalse,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             "UnableToDialServer",
			Message:            message,
		}
	}

	buildGitHubConnectionValidUnknown := func(t *testing.T) metav1.Condition {
		t.Helper()

		return metav1.Condition{
			Type:               GitHubConnectionValid,
			Status:             metav1.ConditionUnknown,
			ObservedGeneration: wantObservedGeneration,
			LastTransitionTime: wantLastTransitionTime,
			Reason:             "UnableToValidate",
			Message:            "unable to validate; see other conditions for details",
		}
	}

	buildLogForUpdatingClaimsValidTrue := func(name string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"ClaimsValid","status":"True","reason":"Success","message":"spec.claims are valid"}`, name)
	}

	buildLogForUpdatingClaimsValidFalse := func(name, message string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"ClaimsValid","status":"False","reason":"Invalid","message":"%s"}`, name, message)
	}

	buildLogForUpdatingClientCredentialsSecretValid := func(name, status, reason, message string) string {
		return fmt.Sprintf(`{"level":"info","timestamp":"2099-08-08T13:57:36.123456Z","logger":"github-upstream-observer","caller":"conditionsutil/conditions_util.go:<line>$conditionsutil.MergeConditions","message":"updated condition","namespace":"some-namespace","name":"%s","type":"ClientCredentialsSecretValid","status":"%s","reason":"%s","message":"%s"}`, name, status, reason, message)
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
		name                      string
		githubIdentityProviders   []runtime.Object
		secretsAndConfigMaps      []runtime.Object
		mockDialer                func(t *testing.T) func(network, addr string, config *tls.Config) (*tls.Conn, error)
		preexistingValidatedCache []GitHubValidatedAPICacheKey
		wantErr                   string
		wantLogs                  []string
		wantResultingCache        []*upstreamgithub.ProviderConfig
		wantResultingUpstreams    []idpv1alpha1.GitHubIdentityProvider
		wantValidatedCache        []GitHubValidatedAPICacheKey
	}{
		{
			name:                   "no GitHubIdentityProviders",
			wantResultingCache:     []*upstreamgithub.ProviderConfig{},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{},
			wantLogs:               []string{},
		},
		{
			name:                 "happy path with all fields",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				validFilledOutIDP,
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "some-idp-name",
					ResourceUID:        "some-resource-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet("organization1", "org2"),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerDomain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec:       validFilledOutIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:                 "happy path with minimal fields",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				validMinimalIDP,
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "minimal-idp-name",
					ResourceUID:        "minimal-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "login",
					GroupNameAttribute: "slug",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet(),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerDomain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validMinimalIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Ready"),
			},
		},
		{
			name:                 "happy path using github.com",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					githubIDP := validMinimalIDP.DeepCopy()
					githubIDP.Spec.GitHubAPI.Host = ptr.To("github.com")
					// don't change the CA because we are not really going to dial github.com in this test
					return githubIDP
				}(),
			},
			mockDialer: func(t *testing.T) func(network, addr string, config *tls.Config) (*tls.Conn, error) {
				t.Helper()

				return func(network, addr string, config *tls.Config) (*tls.Conn, error) {
					require.Equal(t, "github.com:443", addr)
					// don't actually dial github.com to avoid making external network calls in unit test
					configClone := config.Clone()
					configClone.RootCAs = goodServerCertPool
					return tls.Dial(network, goodServerDomain, configClone)
				}
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "minimal-idp-name",
					ResourceUID:        "minimal-uid",
					APIBaseURL:         "https://api.github.com",
					UsernameAttribute:  "login",
					GroupNameAttribute: "slug",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       "https://github.com:443/login/oauth/authorize",
							DeviceAuthURL: "", // not used
							TokenURL:      "https://github.com:443/login/oauth/access_token",
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet(),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      "github.com:443",
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						githubIDP := validMinimalIDP.DeepCopy()
						githubIDP.Spec.GitHubAPI.Host = ptr.To("github.com")
						// don't change the CA because we are not really going to dial github.com in this test
						return githubIDP.Spec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, "github.com:443"),
							buildHostValidTrue(t, "github.com"),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, "github.com"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, "github.com:443"),
				buildLogForUpdatingPhase("minimal-idp-name", "Ready"),
			},
		},
		{
			name:                 "happy path with IPv6",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					ipv6IDP := validMinimalIDP.DeepCopy()
					ipv6IDP.Spec.GitHubAPI.Host = ptr.To(goodServerIPv6Domain)
					ipv6IDP.Spec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: goodServerIPv6CAB64,
					}
					return ipv6IDP
				}(),
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "minimal-idp-name",
					ResourceUID:        "minimal-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", goodServerIPv6Domain),
					UsernameAttribute:  "login",
					GroupNameAttribute: "slug",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", goodServerIPv6Domain),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", goodServerIPv6Domain),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet(),
					HttpClient:           phttp.Default(goodServerIPv6CertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerIPv6Domain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerIPv6CA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validMinimalIDP.Spec.DeepCopy()
						otherSpec.GitHubAPI.Host = ptr.To(goodServerIPv6Domain)
						otherSpec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
							CertificateAuthorityData: goodServerIPv6CAB64,
						}
						return *otherSpec
					}(),

					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, goodServerIPv6Domain),
							buildHostValidTrue(t, goodServerIPv6Domain),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, goodServerIPv6Domain),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, goodServerIPv6Domain),
				buildLogForUpdatingPhase("minimal-idp-name", "Ready"),
			},
		},
		{
			name: "multiple idps - two good, one invalid",
			secretsAndConfigMaps: []runtime.Object{
				goodClientCredentialsSecret,
				func() runtime.Object {
					otherSecret := goodClientCredentialsSecret.DeepCopy()
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

					// No other test happens to verify that this particular value passes validation
					otherIDP.Spec.Claims.Username = ptr.To(idpv1alpha1.GitHubUsernameLoginAndID)
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
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet("organization1", "org2"),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
				{
					Name:               "other-idp-name",
					ResourceUID:        "some-resource-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "login:id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "other-client-id",
						ClientSecret: "other-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet("organization1", "org2"),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerDomain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: func() metav1.ObjectMeta {
						otherMeta := validFilledOutIDP.ObjectMeta.DeepCopy()
						otherMeta.Name = "invalid-idp-name"
						return *otherMeta
					}(),
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validFilledOutIDP.Spec.DeepCopy()
						otherSpec.Client.SecretName = "no-secret-with-this-name"
						return *otherSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidFalse(
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
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validFilledOutIDP.Spec.DeepCopy()
						otherSpec.Client.SecretName = "other-secret-name"
						otherSpec.Claims.Username = ptr.To(idpv1alpha1.GitHubUsernameLoginAndID)
						return *otherSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, "other-secret-name"),
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
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("invalid-idp-name", "False", "SecretNotFound", `secret \"no-secret-with-this-name\" not found: secret from spec.client.SecretName (\"no-secret-with-this-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingClaimsValidTrue("invalid-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("invalid-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("invalid-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("invalid-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("invalid-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("invalid-idp-name", "Error"),

				buildLogForUpdatingClientCredentialsSecretValid("other-idp-name", "True", "Success", `clientID and clientSecret have been read from spec.client.SecretName (\"other-secret-name\")`),
				buildLogForUpdatingClaimsValidTrue("other-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("other-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("other-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("other-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("other-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("other-idp-name", "Ready"),

				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name: "happy path for external TLS configuration - one secret and one configmap",
			secretsAndConfigMaps: []runtime.Object{
				goodClientCredentialsSecret,
				goodCABundleSecret,
				goodCABundleConfigMap,
			},
			// Note that the order here does not match the order below.
			// GitHubIDPs are processed in lexical order.
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					otherIDP := validFilledOutIDP.DeepCopy()
					otherIDP.Name = "idp-with-tls-in-secret"
					otherIDP.Spec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
						CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
							Kind: "Secret",
							Name: goodCABundleSecret.Name,
							Key:  "ca.crt",
						},
					}
					return otherIDP
				}(),
				func() runtime.Object {
					otherIDP := validFilledOutIDP.DeepCopy()
					otherIDP.Name = "idp-with-tls-in-config-map"
					otherIDP.Spec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
						CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
							Kind: "ConfigMap",
							Name: goodCABundleConfigMap.Name,
							Key:  "ca.crt",
						},
					}
					return otherIDP
				}(),
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "idp-with-tls-in-secret",
					ResourceUID:        "some-resource-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet("organization1", "org2"),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
				{
					Name:               "idp-with-tls-in-config-map",
					ResourceUID:        "some-resource-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet("organization1", "org2"),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerDomain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: func() metav1.ObjectMeta {
						otherMeta := validFilledOutIDP.ObjectMeta.DeepCopy()
						otherMeta.Name = "idp-with-tls-in-config-map"
						return *otherMeta
					}(),
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validFilledOutIDP.Spec.DeepCopy()
						otherSpec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
							CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
								Kind: "ConfigMap",
								Name: goodCABundleSecret.Name,
								Key:  "ca.crt",
							},
						}
						return *otherSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, "some-secret-name"),
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
						otherMeta.Name = "idp-with-tls-in-secret"
						return *otherMeta
					}(),
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						otherSpec := validFilledOutIDP.Spec.DeepCopy()
						otherSpec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
							CertificateAuthorityDataSource: &idpv1alpha1.CABundleSource{
								Kind: "Secret",
								Name: goodCABundleSecret.Name,
								Key:  "ca.crt",
							},
						}
						return *otherSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, "some-secret-name"),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("idp-with-tls-in-config-map", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("idp-with-tls-in-config-map"),
				buildLogForUpdatingOrganizationPolicyValid("idp-with-tls-in-config-map", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("idp-with-tls-in-config-map", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("idp-with-tls-in-config-map", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("idp-with-tls-in-config-map", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("idp-with-tls-in-config-map", "Ready"),

				buildLogForUpdatingClientCredentialsSecretValid("idp-with-tls-in-secret", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("idp-with-tls-in-secret"),
				buildLogForUpdatingOrganizationPolicyValid("idp-with-tls-in-secret", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("idp-with-tls-in-secret", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("idp-with-tls-in-secret", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("idp-with-tls-in-secret", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("idp-with-tls-in-secret", "Ready"),
			},
		},
		{
			name:                    "happy path with previously validated address/CA Bundle does not validate again",
			secretsAndConfigMaps:    []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{validFilledOutIDP},
			mockDialer: func(t *testing.T) func(network, addr string, config *tls.Config) (*tls.Conn, error) {
				t.Helper()

				return func(network, addr string, config *tls.Config) (*tls.Conn, error) {
					t.Errorf("this test should not perform dial")
					t.FailNow()
					return nil, nil
				}
			},
			preexistingValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerDomain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingCache: []*upstreamgithub.ProviderConfig{
				{
					Name:               "some-idp-name",
					ResourceUID:        "some-resource-uid",
					APIBaseURL:         fmt.Sprintf("https://%s/api/v3", *validFilledOutIDP.Spec.GitHubAPI.Host),
					UsernameAttribute:  "id",
					GroupNameAttribute: "name",
					OAuth2Config: &oauth2.Config{
						ClientID:     "some-client-id",
						ClientSecret: "some-client-secret",
						Endpoint: oauth2.Endpoint{
							AuthURL:       fmt.Sprintf("https://%s/login/oauth/authorize", *validFilledOutIDP.Spec.GitHubAPI.Host),
							DeviceAuthURL: "", // not used
							TokenURL:      fmt.Sprintf("https://%s/login/oauth/access_token", *validFilledOutIDP.Spec.GitHubAPI.Host),
							AuthStyle:     oauth2.AuthStyleInParams,
						},
						RedirectURL: "", // not used
						Scopes:      []string{"read:user", "read:org"},
					},
					AllowedOrganizations: setutil.NewCaseInsensitiveSet("organization1", "org2"),
					HttpClient:           phttp.Default(goodServerCertPool),
				},
			},
			wantValidatedCache: []GitHubValidatedAPICacheKey{
				{
					address:      goodServerDomain,
					caBundleHash: tlsconfigutil.NewCABundleHash(goodServerCA),
				},
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec:       validFilledOutIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Ready"),
			},
		},
		{
			name:                 "Host error - missing spec.githubAPI.host",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = nil
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "", "must not be empty"),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: must not be empty`, ""),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("some-idp-name"),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Host error - protocol/schema is specified",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("https://example.com")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("https://example.com")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "https://example.com", `invalid port "//example.com"`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: invalid port \"//example.com\"`, "https://example.com"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "Host error - path is specified",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("example.com/foo")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("example.com/foo")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "example.com/foo", `host "example.com/foo" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: host \"example.com/foo\" is not a valid hostname or IP address`, "example.com/foo"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "Host error - userinfo is specified",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("u:p@example.com")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("u:p@example.com")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "u:p@example.com", `invalid port "p@example.com"`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: invalid port \"p@example.com\"`, "u:p@example.com"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "Host error - query is specified",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("example.com?a=b")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("example.com?a=b")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "example.com?a=b", `host "example.com?a=b" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: host \"example.com?a=b\" is not a valid hostname or IP address`, "example.com?a=b"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "Host error - fragment is specified",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("example.com#a")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("example.com#a")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "example.com#a", `host "example.com#a" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"%s\") is not valid: host \"example.com#a\" is not a valid hostname or IP address`, "example.com#a"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "TLS error - invalid bundle",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("foo")),
					}
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString([]byte("foo")),
						}
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidFalse(t, `spec.githubAPI.tls.certificateAuthorityData is invalid: no base64-encoded PEM certificates found in 4 bytes of data (PEM certificates must begin with "-----BEGIN CERTIFICATE-----")`),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "False", "InvalidTLSConfig", `spec.githubAPI.tls.certificateAuthorityData is invalid: no base64-encoded PEM certificates found in 4 bytes of data (PEM certificates must begin with \"-----BEGIN CERTIFICATE-----\")`),
				buildLogForUpdatingGitHubConnectionValidUnknown("some-idp-name"),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Connection error - no such host",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("nowhere.bad-tld")
					return badIDP
				}(),
			},
			wantErr: "dial tcp: lookup nowhere.bad-tld: no such host",
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("nowhere.bad-tld")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidFalse(t, fmt.Sprintf(`cannot dial server spec.githubAPI.host (%q): dial tcp: lookup nowhere.bad-tld: no such host`, "nowhere.bad-tld:443")),
							buildHostValidTrue(t, "nowhere.bad-tld"),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, "nowhere.bad-tld"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "False", "UnableToDialServer", `cannot dial server spec.githubAPI.host (\"%s\"): dial tcp: lookup nowhere.bad-tld: no such host`, "nowhere.bad-tld:443"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "Connection error - ipv6 without brackets",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validMinimalIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.Host = ptr.To("0:0:0:0:0:0:0:1:9876")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validMinimalIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.Host = ptr.To("0:0:0:0:0:0:0:1:9876")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validMinimalIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidUnknown(t),
							buildHostValidFalse(t, "0:0:0:0:0:0:0:1:9876", `host "0:0:0:0:0:0:0:1:9876" is not a valid hostname or IP address`),
							buildOrganizationsPolicyValidTrue(t, *validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validMinimalIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "False", "InvalidHost", `spec.githubAPI.host (\"0:0:0:0:0:0:0:1:9876\") is not valid: host \"%s\" is not a valid hostname or IP address`, "0:0:0:0:0:0:0:1:9876"),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValidUnknown("minimal-idp-name"),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name:                 "Connection error - host not trusted by system certs",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.TLS = nil
					return badIDP
				}(),
			},
			wantErr: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.TLS = nil
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidFalse(t, fmt.Sprintf(`cannot dial server spec.githubAPI.host (%q): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host)),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrueWithMsg(t, "no TLS configuration provided"),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: no TLS configuration provided"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "False", "UnableToDialServer", `cannot dial server spec.githubAPI.host (\"%s\"): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Connection error - host not trusted by provided CA bundle",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
						CertificateAuthorityData: base64.StdEncoding.EncodeToString(unknownServerCABytes),
					}
					return badIDP
				}(),
			},
			wantErr: "tls: failed to verify certificate: x509: certificate signed by unknown authority",
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.GitHubAPI.TLS = &idpv1alpha1.TLSSpec{
							CertificateAuthorityData: base64.StdEncoding.EncodeToString(unknownServerCABytes),
						}
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidFalse(t, fmt.Sprintf(`cannot dial server spec.githubAPI.host (%q): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host)),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "False", "UnableToDialServer", `cannot dial server spec.githubAPI.host (\"%s\"): tls: failed to verify certificate: x509: certificate signed by unknown authority`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Organization Policy error - missing spec.allowAuthentication.organizations.policy",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Policy = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Policy = nil
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Organization Policy error - invalid spec.allowAuthentication.organizations.policy",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Policy = ptr.To[idpv1alpha1.GitHubAllowedAuthOrganizationsPolicy]("a")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Policy = ptr.To[idpv1alpha1.GitHubAllowedAuthOrganizationsPolicy]("a")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Organization Policy error - spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Policy = ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Policy = ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers)
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'OnlyUsersFromAllowedOrganizations' when spec.allowAuthentication.organizations.allowed has organizations listed"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Organization Policy error - spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.AllowAuthentication.Organizations.Allowed = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.AllowAuthentication.Organizations.Allowed = nil
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidFalse(t, "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty"),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidTrue("some-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "False", "Invalid", "spec.allowAuthentication.organizations.policy must be 'AllGitHubUsers' when spec.allowAuthentication.organizations.allowed is empty"),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Invalid Claims - missing spec.claims.username",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Username = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Username = nil
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedFalse(t, "spec.claims.username is required"),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidFalse("some-idp-name", "spec.claims.username is required"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Invalid Claims - invalid spec.claims.username",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Username = ptr.To[idpv1alpha1.GitHubUsernameAttribute]("a")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Username = ptr.To[idpv1alpha1.GitHubUsernameAttribute]("a")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedFalse(t, `spec.claims.username ("a") is not valid`),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidFalse("some-idp-name", `spec.claims.username (\"a\") is not valid`),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Invalid Claims - missing spec.claims.groups",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Groups = nil
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Groups = nil
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedFalse(t, "spec.claims.groups is required"),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidFalse("some-idp-name", "spec.claims.groups is required"),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name:                 "Invalid Claims - invalid spec.claims.groups",
			secretsAndConfigMaps: []runtime.Object{goodClientCredentialsSecret},
			githubIdentityProviders: []runtime.Object{
				func() runtime.Object {
					badIDP := validFilledOutIDP.DeepCopy()
					badIDP.Spec.Claims.Groups = ptr.To[idpv1alpha1.GitHubGroupNameAttribute]("b")
					return badIDP
				}(),
			},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validFilledOutIDP.ObjectMeta,
					Spec: func() idpv1alpha1.GitHubIdentityProviderSpec {
						badSpec := validFilledOutIDP.Spec.DeepCopy()
						badSpec.Claims.Groups = ptr.To[idpv1alpha1.GitHubGroupNameAttribute]("b")
						return *badSpec
					}(),
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedFalse(t, `spec.claims.groups ("b") is not valid`),
							buildClientCredentialsSecretValidTrue(t, validFilledOutIDP.Spec.Client.SecretName),
							buildGitHubConnectionValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildHostValidTrue(t, *validFilledOutIDP.Spec.GitHubAPI.Host),
							buildOrganizationsPolicyValidTrue(t, *validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy),
							buildTLSConfigurationValidTrue(t),
						},
					},
				},
			},
			wantLogs: []string{
				buildLogForUpdatingClientCredentialsSecretValid("some-idp-name", "True", "Success", fmt.Sprintf(`clientID and clientSecret have been read from spec.client.SecretName (\"%s\")`, validFilledOutIDP.Spec.Client.SecretName)),
				buildLogForUpdatingClaimsValidFalse("some-idp-name", `spec.claims.groups (\"b\") is not valid`),
				buildLogForUpdatingOrganizationPolicyValid("some-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validFilledOutIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("some-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("some-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("some-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - in different namespace",
			secretsAndConfigMaps: []runtime.Object{
				func() runtime.Object {
					badSecret := goodClientCredentialsSecret.DeepCopy()
					badSecret.Namespace = "other-namespace"
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidFalse(
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
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "False", "SecretNotFound", `secret \"some-secret-name\" not found: secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - wrong type",
			secretsAndConfigMaps: []runtime.Object{
				func() runtime.Object {
					badSecret := goodClientCredentialsSecret.DeepCopy()
					badSecret.Type = "other-type"
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidFalse(
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
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "False", "SecretNotFound", `wrong secret type \"other-type\": secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - missing clientId",
			secretsAndConfigMaps: []runtime.Object{
				func() runtime.Object {
					badSecret := goodClientCredentialsSecret.DeepCopy()
					delete(badSecret.Data, "clientID")
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidFalse(
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
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "False", "SecretNotFound", `missing key \"clientID\": secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - missing clientSecret",
			secretsAndConfigMaps: []runtime.Object{
				func() runtime.Object {
					badSecret := goodClientCredentialsSecret.DeepCopy()
					delete(badSecret.Data, "clientSecret")
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidFalse(
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
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "False", "SecretNotFound", `missing key \"clientSecret\": secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validMinimalIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
		{
			name: "Client Secret error - additional data",
			secretsAndConfigMaps: []runtime.Object{
				func() runtime.Object {
					badSecret := goodClientCredentialsSecret.DeepCopy()
					badSecret.Data["foo"] = []byte("bar")
					return badSecret
				}(),
			},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantResultingUpstreams: []idpv1alpha1.GitHubIdentityProvider{
				{
					ObjectMeta: validMinimalIDP.ObjectMeta,
					Spec:       validMinimalIDP.Spec,
					Status: idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseError,
						Conditions: []metav1.Condition{
							buildClaimsValidatedTrue(t),
							buildClientCredentialsSecretValidFalse(
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
				buildLogForUpdatingClientCredentialsSecretValid("minimal-idp-name", "False", "SecretNotFound", `extra keys found: secret from spec.client.SecretName (\"some-secret-name\") must be found in namespace \"some-namespace\" with type \"secrets.pinniped.dev/github-client\" and keys \"clientID\" and \"clientSecret\"`),
				buildLogForUpdatingClaimsValidTrue("minimal-idp-name"),
				buildLogForUpdatingOrganizationPolicyValid("minimal-idp-name", "True", "Success", fmt.Sprintf(`spec.allowAuthentication.organizations.policy (\"%s\") is valid`, string(*validMinimalIDP.Spec.AllowAuthentication.Organizations.Policy))),
				buildLogForUpdatingHostValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is valid`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingTLSConfigurationValid("minimal-idp-name", "True", "Success", "spec.githubAPI.tls is valid: loaded TLS configuration"),
				buildLogForUpdatingGitHubConnectionValid("minimal-idp-name", "True", "Success", `spec.githubAPI.host (\"%s\") is reachable and TLS verification succeeds`, *validFilledOutIDP.Spec.GitHubAPI.Host),
				buildLogForUpdatingPhase("minimal-idp-name", "Error"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeSupervisorClient := supervisorfake.NewSimpleClientset(tt.githubIdentityProviders...)
			supervisorInformers := supervisorinformers.NewSharedInformerFactory(fakeSupervisorClient, 0)

			fakeKubeClient := kubernetesfake.NewSimpleClientset(tt.secretsAndConfigMaps...)
			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(fakeKubeClient, 0)

			idpCache := dynamicupstreamprovider.NewDynamicUpstreamIDPProvider()
			idpCache.SetGitHubIdentityProviders([]upstreamprovider.UpstreamGithubIdentityProviderI{
				upstreamgithub.New(
					upstreamgithub.ProviderConfig{Name: "initial-entry-to-remove"},
				),
			})

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			gitHubIdentityProviderInformer := supervisorInformers.IDP().V1alpha1().GitHubIdentityProviders()

			dialer := tls.Dial
			if tt.mockDialer != nil {
				dialer = tt.mockDialer(t)
			}

			validatedCache := cache.NewExpiring()
			for _, item := range tt.preexistingValidatedCache {
				validatedCache.Set(item, nil, 1*time.Hour)
			}

			controller := New(
				namespace,
				idpCache,
				fakeSupervisorClient,
				gitHubIdentityProviderInformer,
				kubeInformers.Core().V1().Secrets(),
				kubeInformers.Core().V1().ConfigMaps(),
				logger,
				controllerlib.WithInformer,
				frozenClockForLastTransitionTime,
				dialer,
				validatedCache,
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			supervisorInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); len(tt.wantErr) > 0 {
				require.ErrorContains(t, err, controllerlib.ErrSyntheticRequeue.Error())
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}

			// Verify what's in the IDP cache
			actualIDPList := idpCache.GetGitHubIdentityProviders()
			require.Equal(t, len(tt.wantResultingCache), len(actualIDPList))
			for i := range len(tt.wantResultingCache) {
				// Do not expect any particular order in the cache
				var actualProvider *upstreamgithub.Provider
				for _, possibleIDP := range actualIDPList {
					if possibleIDP.GetResourceName() == tt.wantResultingCache[i].Name {
						var ok bool
						actualProvider, ok = possibleIDP.(*upstreamgithub.Provider)
						require.True(t, ok)
						break
					}
				}

				require.Equal(t, tt.wantResultingCache[i].Name, actualProvider.GetResourceName())
				require.Equal(t, tt.wantResultingCache[i].ResourceUID, actualProvider.GetResourceUID())
				require.Equal(t, tt.wantResultingCache[i].OAuth2Config.ClientID, actualProvider.GetClientID())
				require.Equal(t, tt.wantResultingCache[i].GroupNameAttribute, actualProvider.GetGroupNameAttribute())
				require.Equal(t, tt.wantResultingCache[i].UsernameAttribute, actualProvider.GetUsernameAttribute())
				require.Equal(t, tt.wantResultingCache[i].AllowedOrganizations, actualProvider.GetAllowedOrganizations())

				compareTLSClientConfigWithinHttpClients(t, tt.wantResultingCache[i].HttpClient, actualProvider.GetConfig().HttpClient)
				require.Equal(t, tt.wantResultingCache[i].OAuth2Config, actualProvider.GetConfig().OAuth2Config)
				require.Contains(t, tt.wantResultingCache[i].APIBaseURL, actualProvider.GetConfig().APIBaseURL)
			}

			// Verify what's in the validated cache
			var uniqueAddresses []string
			for _, cachedIDP := range tt.wantResultingCache {
				if !slices.Contains(uniqueAddresses, cachedIDP.APIBaseURL) {
					uniqueAddresses = append(uniqueAddresses, cachedIDP.APIBaseURL)
				}
			}
			require.Equal(t, len(uniqueAddresses), len(tt.wantValidatedCache), "every unique IDP address should have an entry in the validated cache")
			for _, item := range tt.wantValidatedCache {
				_, ok := validatedCache.Get(item)
				require.True(t, ok, "item with address %q must be found in the validated cache", item.address)
			}

			// Verify the status conditions as reported in Kubernetes
			allGitHubIDPs, err := fakeSupervisorClient.IDPV1alpha1().GitHubIdentityProviders(namespace).List(ctx, metav1.ListOptions{})
			require.NoError(t, err)

			require.Equal(t, len(tt.wantResultingUpstreams), len(allGitHubIDPs.Items))
			for i := range len(tt.wantResultingUpstreams) {
				require.Len(t, tt.wantResultingUpstreams[i].Status.Conditions, countExpectedConditions)

				// Do not expect any particular order in the K8s objects
				var actualIDP *idpv1alpha1.GitHubIdentityProvider
				for _, possibleMatch := range allGitHubIDPs.Items {
					if possibleMatch.GetName() == tt.wantResultingUpstreams[i].Name {
						actualIDP = ptr.To(possibleMatch)
						break
					}
				}

				require.NotNil(t, actualIDP, "must find IDP with name %s", tt.wantResultingUpstreams[i].Name)
				require.Len(t, actualIDP.Status.Conditions, countExpectedConditions)
				require.Equal(t, tt.wantResultingUpstreams[i], *actualIDP)
			}

			expectedLogs := ""
			if len(tt.wantLogs) > 0 {
				expectedLogs = strings.Join(tt.wantLogs, "\n") + "\n"
			}
			require.Equal(t, expectedLogs, log.String())

			// This needs to happen after the expected condition LastTransitionTime has been updated.
			wantActions := make([]coretesting.Action, 3+len(tt.wantResultingUpstreams))
			wantActions[0] = coretesting.NewListAction(githubIDPGVR, githubIDPKind, "", metav1.ListOptions{})
			wantActions[1] = coretesting.NewWatchAction(githubIDPGVR, "", metav1.ListOptions{})
			for i, want := range tt.wantResultingUpstreams {
				wantActions[2+i] = coretesting.NewUpdateSubresourceAction(githubIDPGVR, "status", want.Namespace, ptr.To(want))
			}
			// This List action is coming from the test code when it pulls the GitHubIdentityProviders from K8s
			wantActions[len(wantActions)-1] = coretesting.NewListAction(githubIDPGVR, githubIDPKind, namespace, metav1.ListOptions{})
			require.Equal(t, wantActions, fakeSupervisorClient.Actions())
		})
	}
}

func TestController_OnlyWantActions(t *testing.T) {
	require.Equal(t, 6, countExpectedConditions)

	goodServer, goodServerCA := tlsserver.TestServerIPv4(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}), tlsserver.RecordTLSHello)
	goodServerDomain, _ := strings.CutPrefix(goodServer.URL, "https://")
	goodServerCAB64 := base64.StdEncoding.EncodeToString(goodServerCA)

	oneHourAgo := metav1.Time{Time: time.Now().Add(-1 * time.Hour)}
	namespace := "existing-conditions-namespace"

	wantFrozenTime := time.Date(1122, time.September, 33, 4, 55, 56, 778899, time.Local)
	frozenClockForLastTransitionTime := clocktesting.NewFakeClock(wantFrozenTime)
	wantLastTransitionTime := metav1.Time{Time: wantFrozenTime}

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

	validMinimalIDP := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "minimal-idp-name",
			Namespace:  namespace,
			UID:        types.UID("minimal-uid"),
			Generation: 1234,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: idpv1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &idpv1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			// These claims are optional when using the actual Kubernetes CRD.
			// However, they are required here because CRD defaulting/validation does not occur during testing.
			Claims: idpv1alpha1.GitHubClaims{
				Username: ptr.To(idpv1alpha1.GitHubUsernameLogin),
				Groups:   ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: goodSecret.Name,
			},
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
		},
	}

	alreadyInvalidExistingIDP := &idpv1alpha1.GitHubIdentityProvider{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "already-existing-invalid-idp-name",
			Namespace:  namespace,
			UID:        types.UID("some-resource-uid"),
			Generation: 333,
		},
		Spec: idpv1alpha1.GitHubIdentityProviderSpec{
			GitHubAPI: idpv1alpha1.GitHubAPIConfig{
				Host: ptr.To(goodServerDomain),
				TLS: &idpv1alpha1.TLSSpec{
					CertificateAuthorityData: goodServerCAB64,
				},
			},
			AllowAuthentication: idpv1alpha1.GitHubAllowAuthenticationSpec{
				Organizations: idpv1alpha1.GitHubOrganizationsSpec{
					Policy: ptr.To(idpv1alpha1.GitHubAllowedAuthOrganizationsPolicyAllGitHubUsers),
				},
			},
			Claims: idpv1alpha1.GitHubClaims{
				Groups: ptr.To(idpv1alpha1.GitHubUseTeamSlugForGroupName),
			},
			Client: idpv1alpha1.GitHubClientSpec{
				SecretName: "unknown-secret",
			},
		},
		Status: idpv1alpha1.GitHubIdentityProviderStatus{
			Phase: idpv1alpha1.GitHubPhaseError,
			Conditions: []metav1.Condition{
				{
					Type:               ClaimsValid,
					Status:             metav1.ConditionFalse,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             "Invalid",
					Message:            "spec.claims.username is required",
				},
				{
					Type:               ClientCredentialsSecretValid,
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
					Reason:             conditionsutil.ReasonSuccess,
					Message:            fmt.Sprintf("spec.githubAPI.host (%q) is reachable and TLS verification succeeds", goodServerDomain),
				},
				{
					Type:               HostValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             conditionsutil.ReasonSuccess,
					Message:            fmt.Sprintf("spec.githubAPI.host (%q) is valid", goodServerDomain),
				},
				{
					Type:               OrganizationsPolicyValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             conditionsutil.ReasonSuccess,
					Message:            `spec.allowAuthentication.organizations.policy ("AllGitHubUsers") is valid`,
				},
				{
					Type:               TLSConfigurationValid,
					Status:             metav1.ConditionTrue,
					ObservedGeneration: 333,
					LastTransitionTime: oneHourAgo,
					Reason:             conditionsutil.ReasonSuccess,
					Message:            "spec.githubAPI.tls is valid: loaded TLS configuration",
				},
			},
		},
	}

	tests := []struct {
		name                    string
		secrets                 []runtime.Object
		githubIdentityProviders []runtime.Object
		addSupervisorReactors   func(*supervisorfake.Clientset)
		wantErr                 string
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
					otherIDP.Status.Phase = idpv1alpha1.GitHubPhaseReady
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
					idp.Status.Conditions[0].LastTransitionTime = wantLastTransitionTime
					wantAction := coretesting.NewUpdateSubresourceAction(githubIDPGVR, "status", namespace, idp)
					return wantAction
				}(),
			},
		},
		{
			name:                    "K8s client error - cannot update githubidentityproviders",
			secrets:                 []runtime.Object{goodSecret},
			githubIdentityProviders: []runtime.Object{validMinimalIDP},
			wantErr:                 "error from reactor - unable to update",
			addSupervisorReactors: func(fake *supervisorfake.Clientset) {
				fake.PrependReactor("update", "githubidentityproviders", func(_ coretesting.Action) (bool, runtime.Object, error) {
					return true, nil, fmt.Errorf("error from reactor - unable to update")
				})
			},
			wantActions: []coretesting.Action{
				coretesting.NewUpdateSubresourceAction(githubIDPGVR, "status", namespace, func() runtime.Object {
					idpWithConditions := validMinimalIDP.DeepCopy()
					idpWithConditions.Status = idpv1alpha1.GitHubIdentityProviderStatus{
						Phase: idpv1alpha1.GitHubPhaseReady,
						Conditions: []metav1.Condition{
							{
								Type:               ClaimsValid,
								Status:             metav1.ConditionTrue,
								ObservedGeneration: 1234,
								LastTransitionTime: wantLastTransitionTime,
								Reason:             conditionsutil.ReasonSuccess,
								Message:            "spec.claims are valid",
							},
							{
								Type:               ClientCredentialsSecretValid,
								Status:             metav1.ConditionTrue,
								ObservedGeneration: 1234,
								LastTransitionTime: wantLastTransitionTime,
								Reason:             conditionsutil.ReasonSuccess,
								Message:            `clientID and clientSecret have been read from spec.client.SecretName ("some-secret-name")`,
							},
							{
								Type:               GitHubConnectionValid,
								Status:             metav1.ConditionTrue,
								ObservedGeneration: 1234,
								LastTransitionTime: wantLastTransitionTime,
								Reason:             conditionsutil.ReasonSuccess,
								Message:            fmt.Sprintf("spec.githubAPI.host (%q) is reachable and TLS verification succeeds", goodServerDomain),
							},
							{
								Type:               HostValid,
								Status:             metav1.ConditionTrue,
								ObservedGeneration: 1234,
								LastTransitionTime: wantLastTransitionTime,
								Reason:             conditionsutil.ReasonSuccess,
								Message:            fmt.Sprintf("spec.githubAPI.host (%q) is valid", goodServerDomain),
							},
							{
								Type:               OrganizationsPolicyValid,
								Status:             metav1.ConditionTrue,
								ObservedGeneration: 1234,
								LastTransitionTime: wantLastTransitionTime,
								Reason:             conditionsutil.ReasonSuccess,
								Message:            `spec.allowAuthentication.organizations.policy ("AllGitHubUsers") is valid`,
							},
							{
								Type:               TLSConfigurationValid,
								Status:             metav1.ConditionTrue,
								ObservedGeneration: 1234,
								LastTransitionTime: wantLastTransitionTime,
								Reason:             conditionsutil.ReasonSuccess,
								Message:            "spec.githubAPI.tls is valid: loaded TLS configuration",
							},
						},
					}
					return idpWithConditions
				}()),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fakeSupervisorClient := supervisorfake.NewSimpleClientset(tt.githubIdentityProviders...)
			supervisorInformers := supervisorinformers.NewSharedInformerFactory(supervisorfake.NewSimpleClientset(tt.githubIdentityProviders...), 0)

			if tt.addSupervisorReactors != nil {
				tt.addSupervisorReactors(fakeSupervisorClient)
			}

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(tt.secrets...), 0)

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			controller := New(
				namespace,
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				fakeSupervisorClient,
				supervisorInformers.IDP().V1alpha1().GitHubIdentityProviders(),
				kubeInformers.Core().V1().Secrets(),
				kubeInformers.Core().V1().ConfigMaps(),
				logger,
				controllerlib.WithInformer,
				frozenClockForLastTransitionTime,
				tls.Dial,
				cache.NewExpiring(),
			)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			supervisorInformers.Start(ctx.Done())
			kubeInformers.Start(ctx.Done())
			controllerlib.TestRunSynchronously(t, controller)

			syncCtx := controllerlib.Context{Context: ctx, Key: controllerlib.Key{}}

			if err := controllerlib.TestSync(t, controller, syncCtx); len(tt.wantErr) > 0 {
				require.ErrorContains(t, err, controllerlib.ErrSyntheticRequeue.Error())
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tt.wantActions, fakeSupervisorClient.Actions())
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
	goodSecret := &corev1.Secret{
		Type: "secrets.pinniped.dev/github-client",
		ObjectMeta: metav1.ObjectMeta{
			Name: "some-name",
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
			name:       "should return true for a secret of the type secrets.pinniped.dev/github-client",
			secret:     goodSecret,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return true for a secret of the type Opaque",
			secret: func() *corev1.Secret {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.Type = corev1.SecretTypeOpaque
				return otherSecret
			}(),
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return true for a secret of the type TLS",
			secret: func() *corev1.Secret {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.Type = corev1.SecretTypeTLS
				return otherSecret
			}(),
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
		{
			name: "should return false for a secret of the wrong type",
			secret: func() *corev1.Secret {
				otherSecret := goodSecret.DeepCopy()
				otherSecret.Type = "other-type"
				return otherSecret
			}(),
		},
		{
			name: "should return false for a resource of wrong data type",
			secret: &corev1.Namespace{
				ObjectMeta: metav1.ObjectMeta{Name: "some-name", Namespace: "some-namespace"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kubeInformers := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0)

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			observableInformers := testutil.NewObservableWithInformerOption()
			secretInformer := kubeInformers.Core().V1().Secrets()

			_ = New(
				"some-namespace",
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				supervisorfake.NewSimpleClientset(),
				supervisorinformers.NewSharedInformerFactory(supervisorfake.NewSimpleClientset(), 0).IDP().V1alpha1().GitHubIdentityProviders(),
				secretInformer,
				kubeInformers.Core().V1().ConfigMaps(),
				logger,
				observableInformers.WithInformer,
				clock.RealClock{},
				tls.Dial,
				cache.NewExpiring(),
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

func TestGitHubUpstreamWatcherControllerFilterConfigMaps(t *testing.T) {
	namespace := "some-namespace"
	goodCM := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
		},
	}

	tests := []struct {
		name       string
		cm         metav1.Object
		wantAdd    bool
		wantUpdate bool
		wantDelete bool
	}{
		{
			name:       "any ConfigMap",
			cm:         goodCM,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			observableInformers := testutil.NewObservableWithInformerOption()
			configMapInformer := k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0).Core().V1().ConfigMaps()

			_ = New(
				namespace,
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				supervisorfake.NewSimpleClientset(),
				supervisorinformers.NewSharedInformerFactory(supervisorfake.NewSimpleClientset(), 0).IDP().V1alpha1().GitHubIdentityProviders(),
				k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0).Core().V1().Secrets(),
				configMapInformer,
				logger,
				observableInformers.WithInformer,
				clock.RealClock{},
				tls.Dial,
				cache.NewExpiring(),
			)

			unrelated := &corev1.ConfigMap{}
			filter := observableInformers.GetFilterForInformer(configMapInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.cm))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.cm))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.cm, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.cm))
		})
	}
}

func TestGitHubUpstreamWatcherControllerFilterGitHubIDP(t *testing.T) {
	namespace := "some-namespace"
	goodIDP := &idpv1alpha1.GitHubIdentityProvider{
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
			name:       "any GitHubIdentityProvider",
			idp:        goodIDP,
			wantAdd:    true,
			wantUpdate: true,
			wantDelete: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var log bytes.Buffer
			logger := plog.TestLogger(t, &log)

			observableInformers := testutil.NewObservableWithInformerOption()
			gitHubIdentityProviderInformer := supervisorinformers.NewSharedInformerFactory(supervisorfake.NewSimpleClientset(), 0).IDP().V1alpha1().GitHubIdentityProviders()

			_ = New(
				namespace,
				dynamicupstreamprovider.NewDynamicUpstreamIDPProvider(),
				supervisorfake.NewSimpleClientset(),
				gitHubIdentityProviderInformer,
				k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0).Core().V1().Secrets(),
				k8sinformers.NewSharedInformerFactoryWithOptions(kubernetesfake.NewSimpleClientset(), 0).Core().V1().ConfigMaps(),
				logger,
				observableInformers.WithInformer,
				clock.RealClock{},
				tls.Dial,
				cache.NewExpiring(),
			)

			unrelated := &idpv1alpha1.GitHubIdentityProvider{}
			filter := observableInformers.GetFilterForInformer(gitHubIdentityProviderInformer)
			require.Equal(t, tt.wantAdd, filter.Add(tt.idp))
			require.Equal(t, tt.wantUpdate, filter.Update(unrelated, tt.idp))
			require.Equal(t, tt.wantUpdate, filter.Update(tt.idp, unrelated))
			require.Equal(t, tt.wantDelete, filter.Delete(tt.idp))
		})
	}
}
